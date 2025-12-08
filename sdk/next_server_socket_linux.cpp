/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#include "next.h"

#if NEXT_XDP

#include "next_server_socket.h"
#include "next_constants.h"
#include "next_platform.h"
#include "next_packet_filter.h"
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

#include "next_server_xdp.h"

#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <atomic>

struct next_server_socket_send_buffer_t
{
    uint8_t padding_0[1024];

    std::atomic<int> num_packets;
    int packet_start_index;
    next_address_t to[NEXT_XDP_SEND_QUEUE_SIZE];
    uint8_t packet_type[NEXT_XDP_SEND_QUEUE_SIZE];
    size_t packet_bytes[NEXT_XDP_SEND_QUEUE_SIZE];
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES*NEXT_XDP_SEND_QUEUE_SIZE];

    uint8_t padding_1[1024];
};

struct next_server_socket_receive_buffer_t
{
    uint8_t padding_0[1024];

    int num_packets;
    uint8_t eth[NEXT_XDP_RECV_QUEUE_SIZE][ETH_ALEN];
    next_address_t from[NEXT_XDP_RECV_QUEUE_SIZE];
    size_t packet_bytes[NEXT_XDP_RECV_QUEUE_SIZE];
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES*NEXT_XDP_RECV_QUEUE_SIZE];

    uint8_t padding_1[1024];
};

struct next_server_xdp_socket_t
{
    uint8_t padding_0[1024];

    int queue;
    int num_queues;

    uint8_t padding_1[1024];

    void * buffer;
    struct xsk_umem * umem;
    struct xsk_ring_cons receive_queue;
    struct xsk_ring_prod send_queue;
    struct xsk_ring_cons complete_queue;
    struct xsk_ring_prod fill_queue;
    struct xsk_socket * xsk;

    uint8_t padding_2[1024];

    std::atomic<bool> receive_quit;
    uint32_t num_free_receive_frames;
    uint64_t receive_frames[NEXT_XDP_NUM_FRAMES/2];
    next_platform_thread_t * receive_thread;
    std::atomic<uint64_t> receive_counter_main_thread;
    std::atomic<uint64_t> receive_counter_receive_thread;
    struct next_server_socket_receive_buffer_t receive_buffer[2];

    uint8_t padding_3[1024];

    std::atomic<bool> send_quit;
    uint32_t num_free_send_frames;
    uint64_t send_frames[NEXT_XDP_NUM_FRAMES/2];
    uint8_t server_ethernet_address[ETH_ALEN];
    uint8_t gateway_ethernet_address[ETH_ALEN];
    uint32_t server_address_big_endian;
    uint16_t server_port_big_endian;
    next_platform_thread_t * send_thread;
    std::atomic<uint64_t> send_counter_main_thread;
    std::atomic<uint64_t> send_counter_send_thread;
    struct next_server_socket_send_buffer_t send_buffer[2];

    uint8_t padding_4[1024];
};

struct next_server_socket_t
{
    void * context;
    int state;
    next_address_t public_address;
    uint64_t server_id;
    uint64_t match_id;

    uint8_t server_ethernet_address[ETH_ALEN];
    uint8_t gateway_ethernet_address[ETH_ALEN];

    uint32_t server_address_big_endian;
    uint16_t server_port_big_endian;

    int interface_index;
    struct xdp_program * program;
    bool attached_native;
    bool attached_skb;
    int config_map_fd;
    int state_map_fd;
    int socket_map_fd;

    std::atomic<uint64_t> packet_id;

    int num_queues;
    next_server_xdp_socket_t * socket;

    next_server_socket_process_packets_t process_packets;
};

void next_server_socket_destroy( next_server_socket_t * server );

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

    char mac_address_string[18];
    memset( mac_address_string, 0, sizeof(mac_address_string) );

    const char * gateway_ethernet_address_env = getenv( "NEXT_GATEWAY_ETHERNET_ADDRESS" );
    if ( gateway_ethernet_address_env )
    {
        // let the user force the gateway ethernet address to use (useful for testing)

        strncpy( mac_address_string, gateway_ethernet_address_env, 17 );
        mac_address_string[17] = 0;
    }
    else
    {
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

#define INVALID_FRAME UINT64_MAX

static uint64_t alloc_send_frame( next_server_xdp_socket_t * socket )
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

static void free_send_frame( next_server_xdp_socket_t * socket, uint64_t frame )
{
    next_assert( socket->num_free_send_frames < NEXT_XDP_NUM_FRAMES );
    socket->send_frames[socket->num_free_send_frames] = frame;
    socket->num_free_send_frames++;
}

static uint64_t alloc_receive_frame( next_server_xdp_socket_t * socket )
{
    uint64_t frame = INVALID_FRAME;
    if ( socket->num_free_receive_frames > 0 )
    {
        socket->num_free_receive_frames--;
        frame = socket->receive_frames[socket->num_free_receive_frames];
        socket->receive_frames[socket->num_free_receive_frames] = INVALID_FRAME;
    }
    return frame;
}

static void free_receive_frame( next_server_xdp_socket_t * socket, uint64_t frame )
{
    next_assert( socket->num_free_receive_frames < NEXT_XDP_NUM_FRAMES );
    socket->receive_frames[socket->num_free_receive_frames] = frame;
    socket->num_free_receive_frames++;
}

void xdp_send_thread_function( void * data );

void xdp_receive_thread_function( void * data );

next_server_socket_t * next_server_socket_create( void * context, const char * public_address_string, int num_queues )
{
    next_assert( num_queues >= 1 );
    next_assert( public_address_string );
    
    const char * num_queues_env = getenv( "NEXT_SERVER_NUM_QUEUES" );
    if ( num_queues_env )
    {
        num_queues = atoi( num_queues_env );
    }

    const char * public_address_env = getenv( "NEXT_SERVER_PUBLIC_ADDRESS" );
    if ( public_address_env )
    {
        public_address_string = public_address_env;
    }

    next_info( "server public address is %s", public_address_string );

    next_address_t public_address;
    if ( !next_address_parse( &public_address, public_address_string ) )
    {
        next_error( "server could not parse public address" );
        return NULL;
    }

    if ( public_address.type != NEXT_ADDRESS_IPV4 )
    {
        next_error( "we only support ipv4 servers at the moment" );
        return NULL;
    }

    next_server_socket_t * server_socket = (next_server_socket_t*) next_malloc( context, sizeof(next_server_socket_t) );
    if ( !server_socket )
        return NULL;

    memset( server_socket, 0, sizeof( next_server_socket_t) );
    
    server_socket->context = context;

    // AF_XDP can only run as root

    if ( geteuid() != 0 ) 
    {
        next_error( "server must run as root" );
        next_server_socket_destroy( server_socket );
        return NULL;
    }

    // find the network interface that matches the public address

    uint32_t public_address_ipv4 = next_address_ipv4( &public_address );

    char interface_name[1024];
    memset( interface_name, 0, sizeof(interface_name) );
    {
        bool found = false;

        struct ifaddrs * addrs;
        if ( getifaddrs( &addrs ) != 0 )
        {
            next_error( "server getifaddrs failed" );
            next_server_socket_destroy( server_socket );
            return NULL;
        }

        for ( struct ifaddrs * iap = addrs; iap != NULL; iap = iap->ifa_next ) 
        {
            if ( iap->ifa_addr && ( iap->ifa_flags & IFF_UP ) && iap->ifa_addr->sa_family == AF_INET )
            {
                struct sockaddr_in * sa = (struct sockaddr_in*) iap->ifa_addr;
                if ( sa->sin_addr.s_addr == public_address_ipv4 )
                {
                    strncpy( interface_name, iap->ifa_name, sizeof(interface_name) );
                    next_info( "server found network interface: %s", interface_name );
                    server_socket->interface_index = if_nametoindex( iap->ifa_name );
                    if ( !server_socket->interface_index ) 
                    {
                        next_error( "server if_nametoindex failed" );
                        next_server_socket_destroy( server_socket );
                        return NULL;
                    }
                    found = true;
                    break;
                }
            }
        }

        freeifaddrs( addrs );

        if ( !found )
        {
            next_error( "server could not find any network interface matching public address" );
            next_server_socket_destroy( server_socket );
            return NULL;
        }
    }

    next_info( "server network interface is %s", interface_name );

    // make sure no xdp programs are loaded on the NIC
    {
        char command[2048];
        snprintf( command, sizeof(command), "xdp-loader unload -a %s", interface_name );
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
        pclose( file );
    }

    // disable hyperthreading
    {
        char command[2048];
        snprintf( command, sizeof(command), "echo off > /sys/devices/system/cpu/smt/control" );
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
        pclose( file );
    }

    // setup for busy polling
    {
        char command[4096];
        snprintf( command, sizeof(command), "echo 2 > /sys/class/net/%s/napi_defer_hard_irqs && echo 200000 > /sys/class/net/%s/gro_flush_timeout", interface_name, interface_name );
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
        pclose( file );
    }

    // force the NIC to use the number of NIC queues we want
    {
        next_info( "initializing %d queues", num_queues );

        server_socket->num_queues = num_queues;

        char command[2048];
        snprintf( command, sizeof(command), "ethtool -L %s combined %d", interface_name, num_queues );
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
        pclose( file );
    }

    // look up the ethernet address of the network interface

    if ( !get_interface_mac_address( interface_name, server_socket->server_ethernet_address ) )
    {
        next_error( "server could not get mac address of network interface" );
        next_server_socket_destroy( server_socket );
        return NULL;
    }

    next_info( "server ethernet address is %02x.%02x.%02x.%02x.%02x.%02x", 
        server_socket->server_ethernet_address[0], 
        server_socket->server_ethernet_address[1], 
        server_socket->server_ethernet_address[2], 
        server_socket->server_ethernet_address[3], 
        server_socket->server_ethernet_address[4], 
        server_socket->server_ethernet_address[5] 
    );

    // look up the gateway ethernet address for the network interface

    if ( !get_gateway_mac_address( interface_name, server_socket->gateway_ethernet_address ) )
    {
        next_error( "server could not get gateway mac address" );
        next_server_socket_destroy( server_socket );
        return NULL;
    }

    next_info( "gateway ethernet address is %02x.%02x.%02x.%02x.%02x.%02x", 
        server_socket->gateway_ethernet_address[0], 
        server_socket->gateway_ethernet_address[1], 
        server_socket->gateway_ethernet_address[2], 
        server_socket->gateway_ethernet_address[3], 
        server_socket->gateway_ethernet_address[4], 
        server_socket->gateway_ethernet_address[5] 
    );

    // delete all bpf maps we use so stale data doesn't stick around
    {
        {
            const char * command = "rm -f /sys/fs/bpf/server_xdp_config_map";
            FILE * file = popen( command, "r" );
            char buffer[1024];
            while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
            pclose( file );
        }

        {
            const char * command = "rm -f /sys/fs/bpf/server_xdp_state_map";
            FILE * file = popen( command, "r" );
            char buffer[1024];
            while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
            pclose( file );
        }

        {
            const char * command = "rm -f /sys/fs/bpf/server_xdp_socket_map";
            FILE * file = popen( command, "r" );
            char buffer[1024];
            while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
            pclose( file );
        }
    }

    // write out source tar.gz for server_xdp program
    {
        FILE * file = fopen( "server_xdp_source.tar.gz", "wb" );
        if ( !file )
        {
            next_error( "could not open server_xdp_source.tar.gz for writing" );
            next_server_socket_destroy( server_socket );
            return NULL;
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

    server_socket->program = xdp_program__open_file( "server_xdp.o", "server_xdp", NULL );
    if ( libxdp_get_error( server_socket->program ) ) 
    {
        next_error( "could not load server_xdp program" );
        next_server_socket_destroy( server_socket );
        return NULL;
    }

    next_info( "server_xdp loaded successfully." );

    next_info( "attaching server_xdp to network interface %s", interface_name );

    int ret = xdp_program__attach( server_socket->program, server_socket->interface_index, XDP_MODE_NATIVE, 0 );
    if ( ret == 0 )
    {
        server_socket->attached_native = true;
    } 
    else
    {
        next_info( "falling back to skb mode..." );
        ret = xdp_program__attach( server_socket->program, server_socket->interface_index, XDP_MODE_SKB, 0 );
        if ( ret == 0 )
        {
            server_socket->attached_skb = true;
        }
        else
        {
            next_error( "failed to attach server_xdp program to interface %s", interface_name );
            next_server_socket_destroy( server_socket );
            return NULL;
        }
    }

    // allow unlimited locking of memory, so all memory needed for packet buffers can be locked

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };

    if ( setrlimit( RLIMIT_MEMLOCK, &rlim ) ) 
    {
        next_error( "server could not setrlimit" );
        next_server_socket_destroy( server_socket );
        return NULL;
    }

    // get file descriptors for maps so we can communicate with the server_xdp program running in kernel space

    server_socket->config_map_fd = bpf_obj_get( "/sys/fs/bpf/server_xdp_config_map" );
    if ( server_socket->config_map_fd <= 0 )
    {
        next_error( "server could not get config map: %s", strerror(errno) );
        next_server_socket_destroy( server_socket );
        return NULL;
    }

    server_socket->state_map_fd = bpf_obj_get( "/sys/fs/bpf/server_xdp_state_map" );
    if ( server_socket->state_map_fd <= 0 )
    {
        next_error( "server could not get state map: %s", strerror(errno) );
        next_server_socket_destroy( server_socket );
        return NULL;
    }

    server_socket->socket_map_fd = bpf_obj_get( "/sys/fs/bpf/server_xdp_socket_map" );
    if ( server_socket->socket_map_fd <= 0 )
    {
        next_error( "server could not get socket map: %s", strerror(errno) );
        next_server_socket_destroy( server_socket );
        return NULL;
    }

    // save the server public address and port in network order (big endian)

    server_socket->server_address_big_endian = public_address_ipv4;
    server_socket->server_port_big_endian = next_platform_htons( public_address.port );

    // initialize server xdp sockets (one socket per-NIC queue)

    server_socket->socket = (next_server_xdp_socket_t*) next_malloc( server_socket->context, num_queues * sizeof(next_server_xdp_socket_t) );
    if ( server_socket->socket == NULL )
    {
        next_error( "server could not allocate sockets" );
        next_server_socket_destroy( server_socket );
        return NULL;
    }

    for ( int queue = 0; queue < num_queues; queue++ )
    {
        next_server_xdp_socket_t * socket = &server_socket->socket[queue];

        socket->queue = queue;
        socket->num_queues = num_queues;

        // allocate umem

        const int buffer_size = NEXT_XDP_NUM_FRAMES * NEXT_XDP_FRAME_SIZE;

        if ( posix_memalign( &socket->buffer, getpagesize(), buffer_size ) ) 
        {
            next_error( "server could allocate buffer" );
            next_server_socket_destroy( server_socket );
            return NULL;
        }

        int result = xsk_umem__create( &socket->umem, socket->buffer, buffer_size, &socket->fill_queue, &socket->complete_queue, NULL );
        if ( result ) 
        {
            next_error( "server could not create umem" );
            next_server_socket_destroy( server_socket );
            return NULL;
        }

        // create xdp socket

        struct xsk_socket_config xsk_config;

        memset( &xsk_config, 0, sizeof(xsk_config) );

        xsk_config.rx_size = NEXT_XDP_RECV_QUEUE_SIZE;
        xsk_config.tx_size = NEXT_XDP_SEND_QUEUE_SIZE;
        xsk_config.xdp_flags = XDP_ZEROCOPY;     
        xsk_config.bind_flags = XDP_USE_NEED_WAKEUP;
        xsk_config.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

        result = xsk_socket__create( &socket->xsk, interface_name, queue, socket->umem, &socket->receive_queue, &socket->send_queue, &xsk_config );
        if ( result )
        {
            next_error( "server could not create xsk socket for queue %d", queue );
            next_server_socket_destroy( server_socket );
            return NULL;
        }

        // configure the xdp socket to receive packets from the xdp program

        __u32 key = queue;
        __u32 value = xsk_socket__fd( socket->xsk );

        if ( bpf_map_update_elem( server_socket->socket_map_fd, &key, &value, BPF_ANY ) < 0 ) 
        {
            next_error( "server failed to add xdp socket for queue %d to map", queue );
            next_server_socket_destroy( server_socket );
            return NULL;
        }

        // copy across data needed by the socket to send packets

        memcpy( socket->server_ethernet_address, server_socket->server_ethernet_address, ETH_ALEN );
        memcpy( socket->gateway_ethernet_address, server_socket->gateway_ethernet_address, ETH_ALEN );
        socket->server_address_big_endian = server_socket->server_address_big_endian;
        socket->server_port_big_endian = server_socket->server_port_big_endian;
    }

    // setup send threads

    for ( int queue = 0; queue < num_queues; queue++ )
    {
        next_server_xdp_socket_t * socket = &server_socket->socket[queue];

        // initialize send frame allocator

        next_assert( NEXT_XDP_SEND_QUEUE_SIZE <= NEXT_XDP_NUM_FRAMES / 4 );
        next_assert( NEXT_XDP_RECV_QUEUE_SIZE <= NEXT_XDP_NUM_FRAMES / 4 );

        for ( int j = 0; j < NEXT_XDP_NUM_FRAMES / 2; j++ )
        {
            socket->send_frames[j] = j * NEXT_XDP_FRAME_SIZE;
        }

        socket->num_free_send_frames = NEXT_XDP_NUM_FRAMES / 2;

        // start send thread for queue

        next_info( "starting send thread for socket queue %d", socket->queue );

        socket->send_thread = next_platform_thread_create( NULL, xdp_send_thread_function, socket );
        if ( !socket->send_thread )
        {
            next_error( "server could not create send thread %d", queue );
            next_server_socket_destroy( server_socket );
            return NULL;
        }
    }

    // setup receive threads

    for ( int queue = 0; queue < num_queues; queue++ )
    {
        next_server_xdp_socket_t * socket = &server_socket->socket[queue];

        // initialize receive frame allocator

        for ( int j = 0; j < NEXT_XDP_NUM_FRAMES / 2; j++ )
        {
            socket->receive_frames[j] = ( NEXT_XDP_NUM_FRAMES / 2 + j ) * NEXT_XDP_FRAME_SIZE;
        }

        socket->num_free_receive_frames = NEXT_XDP_NUM_FRAMES / 2;

        // populate fill ring for packets to be received in
        {
            next_assert( NEXT_XDP_FILL_QUEUE_SIZE <= NEXT_XDP_RECV_QUEUE_SIZE );

            uint32_t index;
            int result = xsk_ring_prod__reserve( &socket->fill_queue, NEXT_XDP_FILL_QUEUE_SIZE, &index );
            if ( result != NEXT_XDP_FILL_QUEUE_SIZE )
            {
                next_error( "server failed to populate fill queue: %d", result );
                next_server_socket_destroy( server_socket );
                return NULL;
            }

            uint64_t frames[NEXT_XDP_FILL_QUEUE_SIZE];
            for ( int i = 0; i < NEXT_XDP_FILL_QUEUE_SIZE; i++ ) 
            {
                frames[i] = alloc_receive_frame( socket );
                if ( frames[i] == INVALID_FRAME )
                {
                    next_error( "server could not allocate receive frame for fill queue" );
                    next_server_socket_destroy( server_socket );
                    return NULL;
                }
            }

            for ( int i = 0; i < NEXT_XDP_FILL_QUEUE_SIZE; i++ ) 
            {
                uint64_t * frame = (uint64_t*) xsk_ring_prod__fill_addr( &socket->fill_queue, index + i );
                next_assert( frame );
                *frame = frames[i];
            }

            xsk_ring_prod__submit( &socket->fill_queue, NEXT_XDP_FILL_QUEUE_SIZE );
        }

        // start receive thread for queue

        next_info( "starting receive thread for socket queue %d", socket->queue );

        socket->receive_thread = next_platform_thread_create( NULL, xdp_receive_thread_function, socket );
        if ( !socket->receive_thread )
        {
            next_error( "server could not create receive thread" );
            next_server_socket_destroy( server_socket );
            return NULL;
        }
    }

    // the server has started successfully

    char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_info( "server started on %s [xdp]", next_address_to_string( &public_address, address_string ) );

    server_socket->public_address = public_address;
    server_socket->state = NEXT_SERVER_SOCKET_RUNNING;
    server_socket->server_id = next_hash_string( public_address_string );
    server_socket->match_id = next_random_uint64();

    next_info( "server id is %016" PRIx64, server_socket->server_id );
    next_info( "match id is %016" PRIx64, server_socket->match_id );

    return server_socket;
}

void next_server_socket_destroy( next_server_socket_t * server_socket )
{
    next_assert( server_socket );
    next_assert( server_socket->state == NEXT_SERVER_SOCKET_STOPPED );        // IMPORTANT: Please stop the server and wait until state is NEXT_SERVER_STOPPED before destroying it

    if ( server_socket->program != NULL )
    {
        if ( server_socket->attached_native )
        {
            xdp_program__detach( server_socket->program, server_socket->interface_index, XDP_MODE_NATIVE, 0 );
        }
        if ( server_socket->attached_skb )
        {
            xdp_program__detach( server_socket->program, server_socket->interface_index, XDP_MODE_SKB, 0 );
        }
        xdp_program__close( server_socket->program );
    }

    for ( int i = 0; i < server_socket->num_queues; i++ )
    {
        next_server_xdp_socket_t * socket = &server_socket->socket[i];

        // stop send thread

        if ( socket->send_thread )
        {
            socket->send_quit = true;
            next_platform_thread_join( socket->send_thread );
            next_platform_thread_destroy( socket->send_thread );
        }

        // stop receive thread

        if ( socket->receive_thread )
        {
            socket->receive_quit = true;
            next_platform_thread_join( socket->receive_thread );
            next_platform_thread_destroy( socket->receive_thread );
        }

        // destroy xdp socket

        if ( socket->xsk )
        {
            xsk_socket__delete( socket->xsk );
        }

        if ( socket->umem )
        {
            xsk_umem__delete( socket->umem );
        }

        free( socket->buffer );
    }

    next_free( server_socket->context, server_socket->socket );

    next_clear_and_free( server_socket->context, server_socket, sizeof(next_server_socket_t) );
}

void next_server_socket_update( next_server_socket_t * server_socket )
{
    next_assert( server_socket );

    if ( server_socket->state == NEXT_SERVER_SOCKET_STOPPING )
    {
        server_socket->state = NEXT_SERVER_SOCKET_STOPPED;
    }
}

void next_server_socket_stop( next_server_socket_t * server_socket )
{
    next_assert( server_socket );
    server_socket->state = NEXT_SERVER_SOCKET_STOPPING;
}

int next_server_socket_state( next_server_socket_t * server_socket )
{
    next_assert( server_socket );
    return server_socket->state;
}

uint64_t next_server_socket_id( next_server_socket_t * server_socket )
{
    next_assert( server_socket );
    return server_socket->server_id;
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

int generate_packet_header( void * data, uint8_t * server_ethernet_address, uint8_t * gateway_ethernet_address, uint32_t server_address_big_endian, uint32_t client_address_big_endian, uint16_t server_port_big_endian, uint16_t client_port_big_endian, int payload_bytes )
{
    struct ethhdr * eth = (ethhdr*) data;
    struct iphdr  * ip  = (iphdr*) ( (uint8_t*)data + sizeof( struct ethhdr ) );
    struct udphdr * udp = (udphdr*) ( (uint8_t*)ip + sizeof( struct iphdr ) );

    // generate ethernet header

    memcpy( eth->h_source, server_ethernet_address, ETH_ALEN );
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
    ip->saddr    = server_address_big_endian;
    ip->daddr    = client_address_big_endian;
    ip->check    = ipv4_checksum( ip, sizeof( struct iphdr ) );

    // generate udp header

    udp->source  = server_port_big_endian;
    udp->dest    = client_port_big_endian;
    udp->len     = __constant_htons( sizeof(struct udphdr) + payload_bytes );
    udp->check   = 0;

    return sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + payload_bytes; 
}

uint8_t * next_server_socket_start_packet_internal( struct next_server_socket_t * server_socket, int queue, const next_address_t * to, uint8_t packet_type )
{
    next_server_xdp_socket_t * socket = &server_socket->socket[queue];

    const int off_index = ( socket->send_counter_main_thread + 1 ) % 2;

    next_server_socket_send_buffer_t * send_buffer = &socket->send_buffer[off_index];

    int packet_index = send_buffer->num_packets.fetch_add(1);

    if ( packet_index >= NEXT_XDP_SEND_QUEUE_SIZE )
    {
        return NULL;
    }

    uint8_t * packet_data = send_buffer->packet_data + packet_index * NEXT_MAX_PACKET_BYTES;

    packet_data += NEXT_HEADER_BYTES;

    send_buffer->to[packet_index] = *to;
    send_buffer->packet_type[packet_index] = packet_type;
    send_buffer->packet_bytes[packet_index] = 0;

    return packet_data;
}

uint8_t * next_server_socket_start_packet( struct next_server_socket_t * server_socket, const next_address_t * to, uint64_t * packet_id )
{
    next_assert( server_socket );
    next_assert( to );
    next_assert( packet_id );

    *packet_id = server_socket->packet_id.fetch_add(1);

    const int queue = *packet_id % server_socket->num_queues;

    // direct packet

    uint8_t * packet_data = next_server_socket_start_packet_internal( server_socket, queue, to, NEXT_PACKET_DIRECT );
    if ( !packet_data )
    {
        return NULL;
    }

    return packet_data;
}

void next_server_socket_finish_packet( struct next_server_socket_t * server_socket, uint64_t packet_id, uint8_t * packet_data, int packet_bytes )
{
    next_assert( server_socket );
    next_assert( packet_bytes >= 0 );
    next_assert( packet_bytes <= NEXT_MTU );

    const int queue = packet_id % server_socket->num_queues;

    next_server_xdp_socket_t * socket = &server_socket->socket[queue];

    const int off_index = ( socket->send_counter_main_thread + 1 ) % 2;

    next_server_socket_send_buffer_t * send_buffer = &socket->send_buffer[off_index];

    size_t offset = ( packet_data - send_buffer->packet_data );

    offset -= offset % NEXT_MAX_PACKET_BYTES;

    next_assert( offset < NEXT_MAX_PACKET_BYTES*NEXT_XDP_SEND_QUEUE_SIZE );

    const int packet_index = (int) ( offset / NEXT_MAX_PACKET_BYTES );

    next_assert( packet_index >= 0 );  
    next_assert( packet_index < NEXT_XDP_SEND_QUEUE_SIZE );  

    next_assert( packet_data );
    next_assert( packet_bytes > 0 );
    next_assert( packet_bytes <= NEXT_MTU );

    send_buffer->packet_bytes[packet_index] = packet_bytes + NEXT_HEADER_BYTES;

    // write the packet header

    packet_data -= NEXT_HEADER_BYTES;

    packet_data[0] = send_buffer->packet_type[packet_index];

    uint8_t to_address_data[32];
    next_address_data( &send_buffer->to[packet_index], to_address_data );

    uint8_t from_address_data[32];
    next_address_data( &server_socket->public_address, from_address_data );

    uint8_t * a = packet_data + 1;
    uint8_t * b = packet_data + 3;

    uint8_t magic[8];
    memset( magic, 0, sizeof(magic) );

    next_generate_pittle( a, from_address_data, to_address_data, packet_bytes );
    next_generate_chonkle( b, magic, from_address_data, to_address_data, packet_bytes );
}

void next_server_socket_abort_packet( struct next_server_socket_t * server_socket, uint64_t packet_id, uint8_t * packet_data )
{
    next_assert( server_socket );

    const int queue = packet_id % server_socket->num_queues;

    next_server_xdp_socket_t * socket = &server_socket->socket[queue];

    const int off_index = ( socket->send_counter_main_thread + 1 ) % 2;

    next_server_socket_send_buffer_t * send_buffer = &socket->send_buffer[off_index];

    size_t offset = ( packet_data - send_buffer->packet_data );

    offset -= offset % NEXT_MAX_PACKET_BYTES;

    next_assert( offset < NEXT_MAX_PACKET_BYTES*NEXT_XDP_SEND_QUEUE_SIZE );

    const int packet_index = (int) ( offset / NEXT_MAX_PACKET_BYTES );

    next_assert( packet_index >= 0 );  
    next_assert( packet_index < NEXT_XDP_SEND_QUEUE_SIZE );  

    send_buffer->packet_bytes[packet_index] = 0;
}

void next_server_socket_send_packets( struct next_server_socket_t * server_socket )
{
    next_assert( server_socket );

    for ( int queue = 0; queue < server_socket->num_queues; queue++ )
    {
        // double buffer send buffer

        next_server_xdp_socket_t * socket = &server_socket->socket[queue];

        socket->send_counter_main_thread++;

        while ( socket->send_counter_send_thread != socket->send_counter_main_thread ) {}

        const int off_index = ( socket->send_counter_main_thread + 1 ) % 2;

        socket->send_buffer[off_index].num_packets = 0;
        socket->send_buffer[off_index].packet_start_index = 0;
    }
}

void next_server_socket_process_packet_internal( next_server_socket_t * server_socket, uint8_t * eth, next_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    const uint8_t packet_type = packet_data[0];

    // ...

    (void) packet_type;
}

void next_server_socket_process_direct_packet( next_server_socket_t * server_socket, uint8_t * eth, next_address_t * from, uint8_t * packet_data, int packet_bytes )
{   
    if ( packet_bytes < NEXT_HEADER_BYTES )
        return;

    if ( server_socket->process_packets.num_packets >= NEXT_XDP_RECV_QUEUE_SIZE )
        return;

    const int index = server_socket->process_packets.num_packets++;

    packet_data += NEXT_HEADER_BYTES;
    packet_bytes -= NEXT_HEADER_BYTES;

    next_assert( packet_bytes >= 0 );

    server_socket->process_packets.from[index] = *from;
    server_socket->process_packets.packet_data[index] = packet_data;
    server_socket->process_packets.packet_bytes[index] = packet_bytes;
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

void xdp_send_thread_function( void * data )
{
    next_server_xdp_socket_t * socket = (next_server_xdp_socket_t*) data;

    next_assert( socket );

    pin_thread_to_cpu( socket->queue );

    while ( !socket->send_quit )
    {
        socket->send_counter_send_thread = (uint64_t) socket->send_counter_main_thread;

        const int on_index = socket->send_counter_main_thread % 2;

        next_server_socket_send_buffer_t * send_buffer = &socket->send_buffer[on_index];

        // busy poll the xdp driver

        if ( xsk_ring_prod__needs_wakeup( &socket->send_queue ) )
        {
            sendto( xsk_socket__fd( socket->xsk ), NULL, 0, MSG_DONTWAIT, NULL, 0 );
        }

        // mark any completed send packet frames as free to be reused

        while ( true )
        {
            uint32_t complete_index;

            unsigned int num_completed = xsk_ring_cons__peek( &socket->complete_queue, XSK_RING_CONS__DEFAULT_NUM_DESCS, &complete_index );

            if ( num_completed == 0 )
                break;

            for ( int i = 0; i < num_completed; i++ )
            {
                uint64_t frame = *xsk_ring_cons__comp_addr( &socket->complete_queue, complete_index + i );
                free_send_frame( socket, frame );
            }

            // todo
            // printf( "completed %d packets on queue %d\n", num_completed, socket->queue );

            xsk_ring_cons__release( &socket->complete_queue, num_completed );
        }

        // count how many packets we have to send in the send buffer

        if ( send_buffer->num_packets > NEXT_XDP_SEND_QUEUE_SIZE )
        {
            send_buffer->num_packets = NEXT_XDP_SEND_QUEUE_SIZE;
        }

        const int start_index = send_buffer->packet_start_index;

        next_assert( start_index >= 0 );
        next_assert( start_index < NEXT_XDP_SEND_QUEUE_SIZE );

        const int num_packets = (int) send_buffer->num_packets;

        next_assert( num_packets >= 0 );
        next_assert( num_packets <= NEXT_XDP_SEND_QUEUE_SIZE );

        int num_packets_to_send = 0;
        int send_packet_index[NEXT_XDP_SEND_BATCH_SIZE];

        for ( int i = start_index; i < num_packets; i++ )
        {
            if ( num_packets_to_send >= NEXT_XDP_SEND_BATCH_SIZE )
                break;

            if ( send_buffer->packet_bytes[i] > 0 )
            {
                send_packet_index[num_packets_to_send] = i;
                num_packets_to_send++;
            }
        }

        if ( num_packets_to_send > 0 )
        {
            // reserve entries in the send queue. we *must* send all entries we reserve

            uint32_t send_queue_index;
            int batch_packets = xsk_ring_prod__reserve( &socket->send_queue, num_packets_to_send, &send_queue_index );

            // it's possible to reserve fewer entries in the send queue than requested. when this happens wind back the packet start index for sending packets

            if ( batch_packets < num_packets_to_send )
            {
                send_buffer->packet_start_index = send_packet_index[batch_packets];
            }

            if ( batch_packets > 0 )
            {
                // setup descriptors for packets in batch to be sent

                for ( int j = 0; j < batch_packets; j++ )
                {
                    const int packet_index = send_packet_index[j];

                    struct xdp_desc * desc = xsk_ring_prod__tx_desc( &socket->send_queue, send_queue_index + j );

                    int frame = alloc_send_frame( socket );
                    next_assert( frame != INVALID_FRAME );
                    if ( frame == INVALID_FRAME )
                    {
                        next_error( "ran out of frames" );
                        exit(1);
                    }

                    uint8_t * packet_data = (uint8_t*)socket->buffer + frame;

                    const int payload_bytes = send_buffer->packet_bytes[packet_index];

                    memcpy( packet_data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr), send_buffer->packet_data + packet_index * NEXT_MAX_PACKET_BYTES, payload_bytes );

                    uint32_t to_address_big_endian = next_address_ipv4( &send_buffer->to[packet_index] );
                    uint16_t to_port_big_endian = next_platform_htons( send_buffer->to[packet_index].port );

                    int packet_bytes = generate_packet_header( packet_data, socket->server_ethernet_address, socket->gateway_ethernet_address, socket->server_address_big_endian, to_address_big_endian, socket->server_port_big_endian, to_port_big_endian, payload_bytes );

                    // todo
                    // printf( "---> generate %d byte packet\n", packet_bytes );

                    desc->addr = frame;
                    desc->len = packet_bytes;
                }

                // todo
                // printf( "sent %d packets on queue %d\n", batch_packets, socket->queue );

                // submit send queue to driver

                xsk_ring_prod__submit( &socket->send_queue, batch_packets );

                // advance our send index past sent packets

                send_buffer->packet_start_index = send_packet_index[batch_packets-1] + 1;
            }
        }            
    }
}

void xdp_receive_thread_function( void * data )
{
    next_server_xdp_socket_t * socket = (next_server_xdp_socket_t*) data;

    next_assert( socket );

    pin_thread_to_cpu( socket->num_queues + socket->queue );

    struct pollfd fds[1];
    fds[0].fd = xsk_socket__fd( socket->xsk );
    fds[0].events = POLLIN;

    while ( !socket->receive_quit )
    {
        // keep network driver active

        poll( fds, 1, 0 );

        // receive packets

        socket->receive_counter_receive_thread = (uint64_t) socket->receive_counter_main_thread;

        const int on_index = socket->receive_counter_receive_thread % 2;

        next_server_socket_receive_buffer_t * receive_buffer = &socket->receive_buffer[on_index];

        uint32_t receive_index;
        
        uint32_t num_packets = xsk_ring_cons__peek( &socket->receive_queue, NEXT_XDP_RECV_QUEUE_SIZE, &receive_index );

        if ( num_packets > 0 )
        {
            // receive packets

            uint64_t frame[NEXT_XDP_RECV_QUEUE_SIZE];

            for ( uint32_t i = 0; i < num_packets; i++ ) 
            {
                const struct xdp_desc * desc = xsk_ring_cons__rx_desc( &socket->receive_queue, receive_index + i );

                frame[i] = desc->addr;

                uint8_t * packet_data = (uint8_t*)socket->buffer + desc->addr;

                const int header_bytes = sizeof(ethhdr) + sizeof(iphdr) + sizeof(udphdr);

                int packet_bytes = desc->len - header_bytes;

                if ( packet_bytes >= 18 && receive_buffer->num_packets < NEXT_XDP_RECV_QUEUE_SIZE )
                {
                    const int index = receive_buffer->num_packets++;

                    struct ethhdr * eth = (ethhdr*) packet_data;
                    struct iphdr  * ip  = (iphdr*) ( (uint8_t*)packet_data + sizeof( struct ethhdr ) );
                    struct udphdr * udp = (udphdr*) ( (uint8_t*)ip + sizeof( struct iphdr ) );

                    next_address_load_ipv4( &receive_buffer->from[index], (uint32_t) ip->saddr, udp->source );
                    receive_buffer->packet_bytes[index] = packet_bytes;
                    memcpy( receive_buffer->eth[index], eth->h_source, ETH_ALEN );
                    memcpy( receive_buffer->packet_data + index * NEXT_MAX_PACKET_BYTES, packet_data + header_bytes, packet_bytes );
                }
            }

            xsk_ring_cons__release( &socket->receive_queue, num_packets );

            // busy poll the receive queue

            if ( xsk_ring_prod__needs_wakeup( &socket->fill_queue ) )
            {
                sendto( xsk_socket__fd( socket->xsk ), NULL, 0, MSG_DONTWAIT, NULL, 0 );
            }

            // return processed packets to fill queue

            uint32_t fill_index;
            int num_reserved = xsk_ring_prod__reserve( &socket->fill_queue, num_packets, &fill_index );
            for ( int i = 0; i < num_reserved; i++ )
            {
                *xsk_ring_prod__fill_addr( &socket->fill_queue, fill_index + i ) = frame[i];
            }

            if ( num_reserved != num_packets )
            {
                next_error( "could not reserve packets in fill queue (%d)", num_reserved );
                exit(1);
            }
            
            xsk_ring_prod__submit( &socket->fill_queue, num_reserved );
        }
    }
}

void next_server_socket_receive_packets( next_server_socket_t * server_socket )
{
    next_assert( server_socket );

    server_socket->process_packets.num_packets = 0;

    for ( int queue = 0; queue < server_socket->num_queues; queue++ )
    {
        // double buffer the receive buffer

        next_server_xdp_socket_t * socket = &server_socket->socket[queue];

        const int prev_off_index = ( socket->receive_counter_main_thread + 1 ) % 2;

        socket->receive_buffer[prev_off_index].num_packets = 0;

        socket->receive_counter_main_thread++;

        while ( socket->receive_counter_receive_thread != socket->receive_counter_main_thread ) {}

        const int off_index = ( socket->receive_counter_main_thread + 1 ) % 2;

        // now we can access the off receive buffer without contention with the receive thread

        next_server_socket_receive_buffer_t * receive_buffer = &socket->receive_buffer[off_index];

        for ( int i = 0; i < receive_buffer->num_packets; i++ )
        {
            uint8_t * eth = receive_buffer->eth[i];
            next_address_t from = receive_buffer->from[i];
            uint8_t * packet_data = receive_buffer->packet_data + i * NEXT_MAX_PACKET_BYTES;
            const int packet_bytes = receive_buffer->packet_bytes[i];

            if ( packet_bytes < 18 )
                continue;

            const uint8_t packet_type = packet_data[0];

            if ( packet_type == NEXT_PACKET_DIRECT )
            { 
                next_server_socket_process_direct_packet( server_socket, eth, &from, packet_data, packet_bytes );
            }
            else
            {
                next_server_socket_process_packet_internal( server_socket, eth, &from, packet_data, packet_bytes );
            }
        }

        receive_buffer->num_packets = 0;
    }
}

struct next_server_socket_process_packets_t * next_server_socket_process_packets( struct next_server_socket_t * server_socket )
{
    next_assert( server_socket );
    return &server_socket->process_packets;
}

int next_server_socket_num_queues( struct next_server_socket_t * server_socket )
{
    next_assert( server_socket );
    return server_socket->num_queues;
}

#else // #if NEXT_XDP

int next_server_socket_linux_cpp_dummy = 0;

#endif // #if NEXT_XDP
