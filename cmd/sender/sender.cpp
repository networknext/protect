/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
*/

#include "next.h"
#include "next_platform.h"
#include "next_packet_filter.h"
#include "next_server_xdp.h"
#include "next_hash.h"
#include <ifaddrs.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <poll.h>
#include <memory.h>
#include <stdio.h>
#include <atomic>
#include <signal.h>

// todo: we do need to run this on start: sudo xdp-loader unload -a

const char * source_address_string = "192.168.1.4:40000"; // "69.67.149.151:40000";

uint32_t destination_address_big_endian = 0xC0 | ( 0xA8 << 8 ) | ( 0x01 << 16 ) | ( 0x03 << 24 ); // 192.168.1.3

//space2: 0x40 | ( 0x22 << 8 ) | ( 0x58 << 16 ) | ( 0x75 << 24 );

static volatile int quit;

void interrupt_handler( int signal )
{
    (void) signal; quit = 1;
}

#define NEXT_XDP_NUM_FRAMES                  8192
#define NEXT_XDP_FRAME_SIZE                  2048
#define NEXT_XDP_SEND_QUEUE_SIZE             4096
#define NEXT_XDP_SEND_BATCH_SIZE              256

struct next_xdp_socket_t
{
    uint8_t padding_0[1024];

    int queue;

    uint8_t padding_1[1024];

    void * buffer;
    struct xsk_umem * umem;
    struct xsk_ring_prod send_queue;
    struct xsk_ring_cons complete_queue;
    struct xsk_ring_prod fill_queue;
    struct xsk_socket * xsk;

    uint8_t padding_2[1024];

    uint32_t num_free_send_frames;
    uint64_t send_frames[NEXT_XDP_NUM_FRAMES];
    uint8_t sender_ethernet_address[ETH_ALEN];
    uint8_t gateway_ethernet_address[ETH_ALEN];
    uint32_t sender_address_big_endian;
    uint16_t sender_port_big_endian;
    next_platform_thread_t * send_thread;

    uint8_t padding_3[1024];
};

static bool get_interface_mac_address( const char * interface_name, uint8_t * mac_address ) 
{
    char path[256];
    snprintf( path, sizeof(path), "/sys/class/net/%s/address", interface_name );
    FILE * file = fopen(path, "r");
    if ( !file )
    {
        return false;
    }

    // xx.xx.xx.xx.xx.xx

    char mac_address_string[18];

    if ( fgets( mac_address_string, sizeof(mac_address_string), file ) == NULL ) 
    {
        fclose( file );
        return false;
    }

    mac_address_string[2] = 0;
    mac_address_string[5] = 0;
    mac_address_string[8] = 0;
    mac_address_string[11] = 0;
    mac_address_string[14] = 0;
    mac_address_string[17] = 0;

    mac_address[0] = (uint8_t) strtol( mac_address_string + 0, NULL, 16 );
    mac_address[1] = (uint8_t) strtol( mac_address_string + 3, NULL, 16 );
    mac_address[2] = (uint8_t) strtol( mac_address_string + 6, NULL, 16 );
    mac_address[3] = (uint8_t) strtol( mac_address_string + 9, NULL, 16 );
    mac_address[4] = (uint8_t) strtol( mac_address_string + 12, NULL, 16 );
    mac_address[5] = (uint8_t) strtol( mac_address_string + 15, NULL, 16 );

    fclose( file );

    return true;
}

static bool get_gateway_mac_address( const char * interface_name, uint8_t * mac_address )
{
    memset( mac_address, 0, 6 );

    // first find the gateway IP address for the network interface via netstat

    const char * gateway_ip_string = NULL;

    FILE * file = popen( "netstat -rn", "r" );
    char netstat_buffer[1024];
    while ( fgets( netstat_buffer, sizeof(netstat_buffer), file ) != NULL )
    {
        if ( strlen( netstat_buffer ) > 0 && strstr( netstat_buffer, "UG" ) && strstr( netstat_buffer, interface_name ) )
        {
            char * token = strtok( netstat_buffer, " " );
            if ( token )
            {
                token = strtok( NULL, " " );
                if ( token )
                {
                    gateway_ip_string = token;
                    break;
                }
            }
        }
    }
    pclose( file );

    if ( !gateway_ip_string )
    {
        return false;
    }

    // parse the address and make sure it's a valid ipv4

    next_address_t address;
    if ( !next_address_parse( &address, gateway_ip_string ) || address.type != NEXT_ADDRESS_IPV4 )
    {
        return false;
    }

    // now find the ethernet address corresponding to the gateway IP address and interface name

    bool found_mac_address = false;

    char mac_address_string[18];

    file = popen( "ip neigh show", "r" );
    char ip_buffer[1024];
    while ( fgets( ip_buffer, sizeof(ip_buffer), file ) != NULL )
    {
        if ( strlen( ip_buffer ) > 0 && strstr( ip_buffer, gateway_ip_string ) && strstr( ip_buffer, interface_name ) )
        {
            char * p = strstr( ip_buffer, " lladdr " );
            if ( p )
            {
                p += 8;
                found_mac_address = true;
                strncpy( mac_address_string, p, 17 );
                mac_address_string[17] = 0;
                break;
            }
        }
    }
    pclose( file );

    if ( !found_mac_address )
    {
        return false;
    }

    mac_address_string[2] = 0;
    mac_address_string[5] = 0;
    mac_address_string[8] = 0;
    mac_address_string[11] = 0;
    mac_address_string[14] = 0;
    mac_address_string[17] = 0;

    mac_address[0] = (uint8_t) strtol( mac_address_string + 0, NULL, 16 );
    mac_address[1] = (uint8_t) strtol( mac_address_string + 3, NULL, 16 );
    mac_address[2] = (uint8_t) strtol( mac_address_string + 6, NULL, 16 );
    mac_address[3] = (uint8_t) strtol( mac_address_string + 9, NULL, 16 );
    mac_address[4] = (uint8_t) strtol( mac_address_string + 12, NULL, 16 );
    mac_address[5] = (uint8_t) strtol( mac_address_string + 15, NULL, 16 );

    return true;
}

static uint16_t ipv4_checksum( const void * data, size_t header_length )
{
    unsigned long sum = 0;
    const uint16_t * p = (const uint16_t*) data;
    while ( header_length > 1 )
    {
        sum += *p++;
        if ( sum & 0x80000000 )
        {
            sum = ( sum & 0xFFFF ) + ( sum >> 16 );
        }
        header_length -= 2;
    }
    while ( sum >> 16 )
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

int generate_packet_header( void * data, uint8_t * sender_ethernet_address, uint8_t * gateway_ethernet_address, uint32_t sender_address_big_endian, uint32_t client_address_big_endian, uint16_t server_port_big_endian, uint16_t client_port_big_endian, int payload_bytes )
{
    struct ethhdr * eth = (ethhdr*) data;
    struct iphdr  * ip  = (iphdr*) ( (uint8_t*)data + sizeof( struct ethhdr ) );
    struct udphdr * udp = (udphdr*) ( (uint8_t*)ip + sizeof( struct iphdr ) );

    // generate ethernet header

    memcpy( eth->h_source, sender_ethernet_address, ETH_ALEN );
    memcpy( eth->h_dest, gateway_ethernet_address, ETH_ALEN );
    eth->h_proto = __constant_htons( ETH_P_IP );

    // generate ip header

    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 0x0;
    ip->id       = 0;
    ip->frag_off = __constant_htons( 0x4000 );
    ip->ttl      = 64;
    ip->tot_len  = __constant_htons( sizeof(struct iphdr) + sizeof(struct udphdr) + payload_bytes );
    ip->protocol = IPPROTO_UDP;
    ip->saddr    = sender_address_big_endian;
    ip->daddr    = client_address_big_endian;
    ip->check    = ipv4_checksum( ip, sizeof( struct iphdr ) );

    // generate udp header

    udp->source  = server_port_big_endian;
    udp->dest    = client_port_big_endian;
    udp->len     = __constant_htons( sizeof(struct udphdr) + payload_bytes );
    udp->check   = 0;

    return sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + payload_bytes; 
}

#define INVALID_FRAME UINT64_MAX

static uint64_t alloc_send_frame( next_xdp_socket_t * socket )
{
    uint64_t frame = INVALID_FRAME;
    if ( socket->num_free_send_frames > 0 )
    {
        socket->num_free_send_frames--;
        frame = socket->send_frames[socket->num_free_send_frames];
        socket->send_frames[socket->num_free_send_frames] = INVALID_FRAME;
    }
    return frame;
}

static void free_send_frame( next_xdp_socket_t * socket, uint64_t frame )
{
    next_assert( socket->num_free_send_frames < NEXT_XDP_NUM_FRAMES );
    socket->send_frames[socket->num_free_send_frames] = frame;
    socket->num_free_send_frames++;
}

struct sender_t
{
    int num_queues;

    uint8_t sender_ethernet_address[ETH_ALEN];
    uint8_t gateway_ethernet_address[ETH_ALEN];

    uint32_t sender_address_big_endian;
    uint16_t sender_port_big_endian;

    int interface_index;
    struct xdp_program * program;
    bool attached_native;
    bool attached_skb;

    next_xdp_socket_t * socket;
};

static sender_t sender;

static void xdp_send_thread_function( void * data );

int main()
{
    // AF_XDP can only run as root

    if ( geteuid() != 0 ) 
    {
        next_error( "sender must run as root" );
        return 1;
    }

    signal( SIGINT, interrupt_handler ); signal( SIGTERM, interrupt_handler );

    if ( !next_init() )
    {
        next_error( "could not initialize network next" );
        return 1;        
    }

    // find the network interface that matches the source address

    next_info( "source address is %s", source_address_string );

    next_address_t source_address;
    if ( !next_address_parse( &source_address, source_address_string ) )
    {
        next_error( "could not parse source address" );
        return 1;
    }

    uint32_t source_address_ipv4 = next_address_ipv4( &source_address );

    char interface_name[1024];
    memset( interface_name, 0, sizeof(interface_name) );
    {
        bool found = false;

        struct ifaddrs * addrs;
        if ( getifaddrs( &addrs ) != 0 )
        {
            next_error( "getifaddrs failed" );
            return 1;
        }

        for ( struct ifaddrs * iap = addrs; iap != NULL; iap = iap->ifa_next ) 
        {
            if ( iap->ifa_addr && ( iap->ifa_flags & IFF_UP ) && iap->ifa_addr->sa_family == AF_INET )
            {
                struct sockaddr_in * sa = (struct sockaddr_in*) iap->ifa_addr;
                if ( sa->sin_addr.s_addr == source_address_ipv4 )
                {
                    strncpy( interface_name, iap->ifa_name, sizeof(interface_name) );
                    next_info( "found network interface: %s", interface_name );
                    sender.interface_index = if_nametoindex( iap->ifa_name );
                    if ( !sender.interface_index ) 
                    {
                        next_error( "if_nametoindex failed" );
                        return 1;
                    }
                    found = true;
                    break;
                }
            }
        }

        freeifaddrs( addrs );

        if ( !found )
        {
            next_error( "could not find any network interface matching address" );
            return 1;
        }
    }

    next_info( "network interface is %s", interface_name );

    // force the NIC to use the number of NIC queues we want

    sender.num_queues = 8;
    {
        next_info( "initializing %d queues", sender.num_queues );

        char command[2048];
        snprintf( command, sizeof(command), "ethtool -L %s combined %d", interface_name, sender.num_queues );
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
        pclose( file );
    }

    // look up the ethernet address of the network interface

    if ( !get_interface_mac_address( interface_name, sender.sender_ethernet_address ) )
    {
        next_error( "could not get mac address of network interface" );
        return 1;
    }

    next_info( "sender ethernet address is %02x.%02x.%02x.%02x.%02x.%02x", 
        sender.sender_ethernet_address[0], 
        sender.sender_ethernet_address[1], 
        sender.sender_ethernet_address[2], 
        sender.sender_ethernet_address[3], 
        sender.sender_ethernet_address[4], 
        sender.sender_ethernet_address[5] 
    );

    // look up the gateway ethernet address for the network interface

    /*
    if ( !get_gateway_mac_address( interface_name, sender.gateway_ethernet_address ) )
    {
        next_error( "could not get gateway mac address" );
        return 1;
    }
    */

    // hulk
    sender.gateway_ethernet_address[0] = 0xd0;
    sender.gateway_ethernet_address[1] = 0x81;
    sender.gateway_ethernet_address[2] = 0x7a;
    sender.gateway_ethernet_address[3] = 0xd8;
    sender.gateway_ethernet_address[4] = 0x3a;
    sender.gateway_ethernet_address[5] = 0xec;

    next_info( "gateway ethernet address is %02x.%02x.%02x.%02x.%02x.%02x", 
        sender.gateway_ethernet_address[0], 
        sender.gateway_ethernet_address[1], 
        sender.gateway_ethernet_address[2], 
        sender.gateway_ethernet_address[3], 
        sender.gateway_ethernet_address[4], 
        sender.gateway_ethernet_address[5] 
    );

    // write out source tar.gz for server_xdp program
    {
        FILE * file = fopen( "server_xdp_source.tar.gz", "wb" );
        if ( !file )
        {
            next_error( "could not open server_xdp_source.tar.gz for writing" );
            return 1;
        }

        fwrite( next_server_xdp_tar_gz, sizeof(next_server_xdp_tar_gz), 1, file );

        fclose( file );
    }

    // unzip source and build server_xdp.o
    {
        const char * command = "rm -f Makefile && rm -f *.c && rm -f *.h && rm -f *.o && rm -f Makefile && tar -zxf server_xdp_source.tar.gz && make server_xdp.o";
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
        pclose( file );
    }

    // clean up after ourselves
    {
        const char * command = "rm -f Makefile && rm -f *.c && rm -f *.h && rm -f *.tar.gz";
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
        pclose( file );
    }

    // load the client_backend_xdp program and attach it to the network interface

    next_info( "loading server_xdp..." );

    sender.program = xdp_program__open_file( "server_xdp.o", "server_xdp", NULL );
    if ( libxdp_get_error( sender.program ) ) 
    {
        next_error( "could not load server_xdp program" );
        return 1;
    }

    next_info( "server_xdp loaded successfully." );

    next_info( "attaching server_xdp to network interface %s", interface_name );

    int ret = xdp_program__attach( sender.program, sender.interface_index, XDP_MODE_NATIVE, 0 );
    if ( ret == 0 )
    {
        sender.attached_native = true;
    } 
    else
    {
        next_info( "falling back to skb mode..." );
        ret = xdp_program__attach( sender.program, sender.interface_index, XDP_MODE_SKB, 0 );
        if ( ret == 0 )
        {
            sender.attached_skb = true;
        }
        else
        {
            next_error( "failed to attach server_xdp program to interface %s", interface_name );
            return 1;
        }
    }

    // allow unlimited locking of memory, so all memory needed for packet buffers can be locked

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };

    if ( setrlimit( RLIMIT_MEMLOCK, &rlim ) ) 
    {
        next_error( "could not setrlimit" );
        return 1;
    }

    // save the public address and port in network order (big endian)

    sender.sender_address_big_endian = source_address_ipv4;
    sender.sender_port_big_endian = next_platform_htons( source_address.port );

    // initialize xdp sockets (one socket per-NIC queue)

    sender.socket = (next_xdp_socket_t*) next_malloc( NULL, sender.num_queues * sizeof(next_xdp_socket_t) );
    if ( sender.socket == NULL )
    {
        next_error( "could not allocate sockets" );
        return 1;
    }

    for ( int queue = 0; queue < sender.num_queues; queue++ )
    {
        next_xdp_socket_t * socket = &sender.socket[queue];

        socket->queue = queue;

        // allocate umem

        const int buffer_size = NEXT_XDP_NUM_FRAMES * NEXT_XDP_FRAME_SIZE;

        if ( posix_memalign( &socket->buffer, getpagesize(), buffer_size ) ) 
        {
            next_error( "could allocate buffer" );
            return 1;
        }

        struct xsk_umem_config config = {
            .fill_size = 4096,
            .comp_size = 4096,
            .frame_size = 2048,
            .frame_headroom = 0, // Optional headroom for metadata/headers
            .flags = 0,          // No specific flags needed for basic setup
        };

        int result = xsk_umem__create( &socket->umem, socket->buffer, buffer_size, &socket->fill_queue, &socket->complete_queue, &config );
        if ( result ) 
        {
            next_error( "could not create umem" );
            return 1;
        }

        // create xdp socket

        struct xsk_socket_config xsk_config;

        memset( &xsk_config, 0, sizeof(xsk_config) );

        xsk_config.rx_size = 0;
        xsk_config.tx_size = NEXT_XDP_SEND_QUEUE_SIZE;
        xsk_config.xdp_flags = XDP_ZEROCOPY;     
        xsk_config.bind_flags = XDP_USE_NEED_WAKEUP;
        xsk_config.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

        result = xsk_socket__create( &socket->xsk, interface_name, queue, socket->umem, NULL, &socket->send_queue, &xsk_config );
        if ( result )
        {
            next_error( "could not create xsk socket for queue %d", queue );
            return 1;
        }

        // copy across data needed by the socket to send packets

        memcpy( socket->sender_ethernet_address, sender.sender_ethernet_address, ETH_ALEN );
        memcpy( socket->gateway_ethernet_address, sender.gateway_ethernet_address, ETH_ALEN );
        socket->sender_address_big_endian = sender.sender_address_big_endian;
        socket->sender_port_big_endian = sender.sender_port_big_endian;
    }

    // setup send threads

    for ( int queue = 0; queue < sender.num_queues; queue++ )
    {
        next_xdp_socket_t * socket = &sender.socket[queue];

        // initialize send frame allocator

        for ( int i = 0; i < NEXT_XDP_NUM_FRAMES; i++ )
        {
            socket->send_frames[i] = i * NEXT_XDP_FRAME_SIZE;
        }

        socket->num_free_send_frames = NEXT_XDP_NUM_FRAMES;

        // start send thread for queue

        next_info( "starting send thread for socket queue %d", socket->queue );

        socket->send_thread = next_platform_thread_create( NULL, xdp_send_thread_function, socket );
        if ( !socket->send_thread )
        {
            next_error( "server could not create send thread %d", queue );
            return 1;
        }
    }

    // ----------------------------------------------------------------------------------

    while ( !quit )
    {
        // ...

        next_platform_sleep( 1.0 / 10.0 );
    }

    next_term();

    return 0;
}

static void pin_thread_to_cpu( int cpu ) 
{
    int num_cpus = sysconf( _SC_NPROCESSORS_ONLN );
    next_assert( cpu >= 0 );
    next_assert( cpu < num_cpus );

    cpu_set_t cpuset;
    CPU_ZERO( &cpuset );
    CPU_SET( cpu, &cpuset );

    pthread_t current_thread = pthread_self();    

    pthread_setaffinity_np( current_thread, sizeof(cpu_set_t), &cpuset );
}

static void xdp_send_thread_function( void * data )
{
    next_xdp_socket_t * socket = (next_xdp_socket_t*) data;

    pin_thread_to_cpu( socket->queue );

    uint64_t sequence = 0;

    while ( !quit )
    {
        if ( xsk_ring_prod__needs_wakeup( &socket->send_queue ) )
        {
            sendto( xsk_socket__fd( socket->xsk ), NULL, 0, MSG_DONTWAIT, NULL, 0 );
        }

        // process completed send frames

        uint32_t complete_index;

        unsigned int num_completed = xsk_ring_cons__peek( &socket->complete_queue, XSK_RING_CONS__DEFAULT_NUM_DESCS, &complete_index );

        if ( num_completed != 0 )
        {
            for ( int i = 0; i < num_completed; i++ )
            {
                uint64_t frame = *xsk_ring_cons__comp_addr( &socket->complete_queue, complete_index + i );
                free_send_frame( socket, frame );
            }

            xsk_ring_cons__release( &socket->complete_queue, num_completed );
        }

        // reserve entries in the send queue. we *must* send all entries we reserve

        uint32_t send_queue_index;
        
        int num_packets = xsk_ring_prod__reserve( &socket->send_queue, NEXT_XDP_SEND_BATCH_SIZE, &send_queue_index );

        if ( num_packets == 0 )
            continue;

        // fill descriptors in the send queue

        for ( int i = 0; i < num_packets; i++ )
        {
            struct xdp_desc * desc = xsk_ring_prod__tx_desc( &socket->send_queue, send_queue_index + i );

            int frame = alloc_send_frame( socket );
            next_assert( frame != INVALID_FRAME );
            if ( frame == INVALID_FRAME )
            {
                next_error( "fatal error. this cannot happen unless you have too few frames. please adjust NEXT_XDP_NUM_FRAMES to the next highest power of two!" );
                exit(1);
            }

            uint8_t * packet_data = (uint8_t*)socket->buffer + frame;

            const int payload_bytes = 1200;

            sequence++;

            uint32_t to_address_big_endian = destination_address_big_endian;
            uint16_t to_port_big_endian = next_platform_htons( ( sequence % 1000 ) + 30000 );

            int packet_bytes = generate_packet_header( packet_data, socket->sender_ethernet_address, socket->gateway_ethernet_address, socket->sender_address_big_endian, to_address_big_endian, socket->sender_port_big_endian, to_port_big_endian, payload_bytes );

            desc->addr = frame;
            desc->len = packet_bytes;
        }

        // submit send queue to driver

        // next_info( "send batch of %d packets on queue %d", num_packets, socket->queue );

        xsk_ring_prod__submit( &socket->send_queue, num_packets );
    }
}
