/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#include "next_server.h"
#include "next_config.h"
#include "next_constants.h"
#include "next_platform.h"
#include "next_packet_filter.h"
#include "next_hash.h"

#ifdef __linux__

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
#include <errno.h>
#include <atomic>

#include "next_server_xdp.h"

#endif // #ifdef __linux

#include <memory.h>
#include <stdio.h>

#ifdef __linux__

#define NUM_SERVER_XDP_SOCKETS 2

struct next_server_xdp_receive_buffer_t
{
    int num_packets;
    next_address_t from[NEXT_XDP_RECV_QUEUE_SIZE];
    size_t packet_bytes[NEXT_XDP_RECV_QUEUE_SIZE];
    uint8_t packet_data[NEXT_MAX_PACKET_BYTES*NEXT_XDP_RECV_QUEUE_SIZE];
};

struct next_server_xdp_socket_t
{
    uint32_t num_free_frames;
    uint64_t frames[NEXT_XDP_NUM_FRAMES];

    void * buffer;
    struct xsk_umem * umem;
    struct xsk_ring_cons receive_queue;
    struct xsk_ring_prod send_queue;
    struct xsk_ring_cons complete_queue;
    struct xsk_ring_prod fill_queue;
    struct xsk_socket * xsk;

    next_platform_mutex_t receive_mutex;
    int receive_buffer_index;
    struct next_server_xdp_receive_buffer_t receive_buffer[2];
};

#else // #ifdef __linux__

struct next_server_send_buffer_t
{
    next_platform_mutex_t mutex;
    size_t current_packet;
    next_address_t to[NEXT_SERVER_MAX_SEND_PACKETS];
    size_t packet_bytes[NEXT_SERVER_MAX_SEND_PACKETS];
    uint8_t packet_type[NEXT_SERVER_MAX_SEND_PACKETS];
    uint8_t data[NEXT_MAX_PACKET_BYTES*NEXT_SERVER_MAX_SEND_PACKETS];
};

struct next_server_receive_buffer_t
{
    int current_packet;
    int client_index[NEXT_SERVER_MAX_RECEIVE_PACKETS];
    uint64_t sequence[NEXT_SERVER_MAX_RECEIVE_PACKETS];
    uint8_t * packet_data[NEXT_SERVER_MAX_RECEIVE_PACKETS];
    size_t packet_bytes[NEXT_SERVER_MAX_RECEIVE_PACKETS];
    uint8_t data[NEXT_MAX_PACKET_BYTES*NEXT_SERVER_MAX_RECEIVE_PACKETS];
};

#endif // #ifdef __linux__

struct next_server_t
{
    void * context;
    int state;
    next_address_t bind_address;
    next_address_t public_address;
    uint64_t server_id;
    uint64_t match_id;
    void (*packet_received_callback)( next_server_t * server, void * context, int client_index, const uint8_t * packet_data, int packet_bytes );

    bool client_connected[NEXT_MAX_CLIENTS];
    bool client_direct[NEXT_MAX_CLIENTS];
    next_address_t client_address[NEXT_MAX_CLIENTS];
    double client_last_packet_receive_time[NEXT_MAX_CLIENTS];

    next_platform_mutex_t client_payload_mutex;
    uint64_t client_payload_sequence[NEXT_MAX_CLIENTS];

    next_server_process_packets_t process_packets;

#ifdef __linux__

    uint8_t server_ethernet_address[ETH_ALEN];
    uint8_t gateway_ethernet_address[ETH_ALEN];

    uint32_t server_address_big_endian;
    uint16_t server_port_big_endian;

    uint32_t client_address_big_endian[NEXT_MAX_CLIENTS];
    uint16_t client_port_big_endian[NEXT_MAX_CLIENTS];

    int interface_index;
    struct xdp_program * program;
    bool attached_native;
    bool attached_skb;
    int config_map_fd;
    int state_map_fd;
    int socket_map_fd;

    next_server_xdp_socket_t socket[NUM_SERVER_XDP_SOCKETS];

#else // #ifdef __linux__

    next_platform_socket_t * socket;
    next_server_send_buffer_t send_buffer;
    next_server_receive_buffer_t receive_buffer;

#endif // #ifdef __linux__
};

void next_server_destroy( next_server_t * server );

#ifdef __linux__

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
        if ( strlen( ip_buffer ) > 0 && strstr( ip_buffer, gateway_ip_string ) && strstr( ip_buffer, interface_name ) && strstr( ip_buffer, "REACHABLE" ) )
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

#define INVALID_FRAME UINT64_MAX

uint64_t next_server_xdp_socket_alloc_frame( next_server_xdp_socket_t * socket )
{
    uint64_t frame = INVALID_FRAME;
    if ( socket->num_free_frames > 0 )
    {
        socket->num_free_frames--;
        frame = socket->frames[socket->num_free_frames];
        socket->frames[socket->num_free_frames] = INVALID_FRAME;
    }
    return frame;
}

void next_server_xdp_socket_free_frame( next_server_xdp_socket_t * socket, uint64_t frame )
{
    next_assert( socket->num_free_frames < NEXT_XDP_NUM_FRAMES );
    socket->frames[socket->num_free_frames] = frame;
    socket->num_free_frames++;
}

#endif // #ifdef __linux__

next_server_t * next_server_create( void * context, const char * bind_address_string, const char * public_address_string )
{
    next_assert( bind_address_string );
    next_assert( public_address_string );

    next_info( "server public address is %s", public_address_string );

    next_address_t bind_address;
    if ( !next_address_parse( &bind_address, bind_address_string ) )
    {
        next_error( "server could not parse bind address" );
        return NULL;
    }

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

    next_server_t * server = (next_server_t*) next_malloc( context, sizeof(next_server_t) );
    if ( !server )
        return NULL;

    memset( server, 0, sizeof( next_server_t) );
    
    server->context = context;

#ifdef __linux__

    // AF_XDP can only run as root

    if ( geteuid() != 0 ) 
    {
        next_error( "server must run as root" );
        next_server_destroy( server );
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
            next_server_destroy( server );
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
                    server->interface_index = if_nametoindex( iap->ifa_name );
                    if ( !server->interface_index ) 
                    {
                        next_error( "server if_nametoindex failed" );
                        next_server_destroy( server );
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
            next_server_destroy( server );
            return NULL;
        }
    }

    next_info( "server network interface is %s", interface_name );

    // look up the ethernet address of the network interface

    if ( !get_interface_mac_address( interface_name, server->server_ethernet_address ) )
    {
        next_error( "server could not get mac address of network interface" );
        next_server_destroy( server );
        return NULL;
    }

    next_info( "server ethernet address is %02x.%02x.%02x.%02x.%02x.%02x", 
        server->server_ethernet_address[0], 
        server->server_ethernet_address[1], 
        server->server_ethernet_address[2], 
        server->server_ethernet_address[3], 
        server->server_ethernet_address[4], 
        server->server_ethernet_address[5] 
    );

    // look up the gateway ethernet address for the network interface

    // batman mac address on LAN
    uint8_t batman_mac[] = { 0xd0, 0x81, 0x7a, 0xd8, 0x3a, 0xec };
    memcpy( server->gateway_ethernet_address, batman_mac, 6 );

    /*
    if ( !get_gateway_mac_address( interface_name, server->gateway_ethernet_address ) )
    {
        next_error( "server could not get gateway mac address" );
        next_server_destroy( server );
        return NULL;
    }
    */

    next_info( "gateway ethernet address is %02x.%02x.%02x.%02x.%02x.%02x", 
        server->gateway_ethernet_address[0], 
        server->gateway_ethernet_address[1], 
        server->gateway_ethernet_address[2], 
        server->gateway_ethernet_address[3], 
        server->gateway_ethernet_address[4], 
        server->gateway_ethernet_address[5] 
    );


    // be extra safe and let's make sure no xdp programs are running on this interface before we start
    {
        char command[2048];
        snprintf( command, sizeof(command), "xdp-loader unload %s --all", interface_name );
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
        pclose( file );
    }

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
            next_server_destroy( server );
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

    server->program = xdp_program__open_file( "server_xdp.o", "server_xdp", NULL );
    if ( libxdp_get_error( server->program ) ) 
    {
        next_error( "could not load server_xdp program" );
        next_server_destroy( server );
        return NULL;
    }

    next_info( "server_xdp loaded successfully." );

    next_info( "attaching server_xdp to network interface %s", interface_name );

    int ret = xdp_program__attach( server->program, server->interface_index, XDP_MODE_NATIVE, 0 );
    if ( ret == 0 )
    {
        server->attached_native = true;
    } 
    else
    {
        next_info( "falling back to skb mode..." );
        ret = xdp_program__attach( server->program, server->interface_index, XDP_MODE_SKB, 0 );
        if ( ret == 0 )
        {
            server->attached_skb = true;
        }
        else
        {
            next_error( "failed to attach server_xdp program to interface %s", interface_name );
            next_server_destroy( server );
            return NULL;
        }
    }

    // allow unlimited locking of memory, so all memory needed for packet buffers can be locked

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };

    if ( setrlimit( RLIMIT_MEMLOCK, &rlim ) ) 
    {
        next_error( "server could not setrlimit" );
        next_server_destroy( server );
        return NULL;
    }

    // get file descriptors for maps so we can communicate with the server_xdp program running in kernel space

    server->config_map_fd = bpf_obj_get( "/sys/fs/bpf/server_xdp_config_map" );
    if ( server->config_map_fd <= 0 )
    {
        next_error( "server could not get config map: %s", strerror(errno) );
        next_server_destroy( server );
        return NULL;
    }

    server->state_map_fd = bpf_obj_get( "/sys/fs/bpf/server_xdp_state_map" );
    if ( server->state_map_fd <= 0 )
    {
        next_error( "server could not get state map: %s", strerror(errno) );
        next_server_destroy( server );
        return NULL;
    }

    server->socket_map_fd = bpf_obj_get( "/sys/fs/bpf/server_xdp_socket_map" );
    if ( server->socket_map_fd <= 0 )
    {
        next_error( "server could not get socket map: %s", strerror(errno) );
        next_server_destroy( server );
        return NULL;
    }

    // initialize server xdp sockets (one socket per-NIC queue)

    for ( int queue = 0; queue < NUM_SERVER_XDP_SOCKETS; queue++ )
    {
        next_server_xdp_socket_t * socket = &server->socket[queue];

        // allocate umem

        const int buffer_size = NEXT_XDP_NUM_FRAMES * NEXT_XDP_FRAME_SIZE;

        if ( posix_memalign( &socket->buffer, getpagesize(), buffer_size ) ) 
        {
            next_error( "server could allocate buffer" );
            next_server_destroy( server );
            return NULL;
        }

        int result = xsk_umem__create( &socket->umem, socket->buffer, buffer_size, &socket->fill_queue, &socket->complete_queue, NULL );
        if ( result ) 
        {
            next_error( "server could not create umem" );
            next_server_destroy( server );
            return NULL;
        }

        // create xdp socket and assign to network interface queue 0

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
            next_server_destroy( server );
            return NULL;
        }

        // configure the xdp socket to receive packets from the xdp program

        __u32 key = queue;
        __u32 value = xsk_socket__fd( socket->xsk );

        if ( bpf_map_update_elem( server->socket_map_fd, &key, &value, BPF_ANY ) < 0 ) 
        {
            next_error( "server failed to add xdp socket for queue %d to map", queue );
            next_server_destroy( server );
            return NULL;
        }

        // initialize frame allocator

        for ( int j = 0; j < NEXT_XDP_NUM_FRAMES; j++ )
        {
            socket->frames[j] = j * NEXT_XDP_FRAME_SIZE;
        }

        socket->num_free_frames = NEXT_XDP_NUM_FRAMES;

        // populate fill ring for packets to be received in
        {
            uint32_t index;
            int result = xsk_ring_prod__reserve( &socket->fill_queue, NEXT_XDP_FILL_QUEUE_SIZE, &index );
            if ( result != NEXT_XDP_FILL_QUEUE_SIZE )
            {
                next_error( "server failed to populate fill queue: %d", result );
                next_server_destroy( server );
                return NULL;
            }

            uint64_t frames[NEXT_XDP_FILL_QUEUE_SIZE];
            for ( int i = 0; i < NEXT_XDP_FILL_QUEUE_SIZE; i++ ) 
            {
                frames[i] = next_server_xdp_socket_alloc_frame( socket );
                if ( frames[i] == INVALID_FRAME )
                {
                    next_error( "server could not allocate frame for fill queue" );
                    next_server_destroy( server );
                    return NULL;
                }
            }

            for ( int i = 0; i < NEXT_XDP_FILL_QUEUE_SIZE; i++ ) 
            {
                uint64_t * frame = (uint64_t*) xsk_ring_prod__fill_addr( &socket->fill_queue, index + i );
                next_assert( frame );
                *frame = frames[i];
            }

            if ( !next_platform_mutex_create( &socket->receive_mutex ) )
            {
                next_error( "server failed to create receive mutex" );
                next_server_destroy( server );
                return NULL;
            }

            xsk_ring_prod__submit( &socket->fill_queue, NEXT_XDP_FILL_QUEUE_SIZE );
        }
    }

    // save the server public address and port in network order (big endian)

    server->server_address_big_endian = public_address_ipv4;
    server->server_port_big_endian = next_platform_htons( public_address.port );

    // todo: mock a client connected in slot 0
    server->client_connected[0] = true;
    server->client_direct[0] = true;
    next_address_parse( &server->client_address[0], "192.168.1.3:30000" );
    server->client_address_big_endian[0] = next_address_ipv4( &server->client_address[0] );
    server->client_port_big_endian[0] = next_platform_htons( 30000 );

    // the server has started successfully

    char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_info( "server started on %s [xdp]", next_address_to_string( &public_address, address_string ) );

#else // #ifdef __linux __

    server->socket = next_platform_socket_create( server->context, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0.0f, NEXT_SOCKET_SEND_BUFFER_SIZE, NEXT_SOCKET_RECEIVE_BUFFER_SIZE );
    if ( server->socket == NULL )
    {
        next_error( "server could not create socket" );
        next_server_destroy( server );
        return NULL;
    }

    char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_info( "server started on %s", next_address_to_string( &bind_address, address_string ) );

#endif // #ifdef __linux__

    server->bind_address = bind_address;
    server->public_address = public_address;
    server->state = NEXT_SERVER_RUNNING;
    server->server_id = next_hash_string( public_address_string );
    server->match_id = next_random_uint64();

    next_info( "server id is %016" PRIx64, server->server_id );
    next_info( "match id is %016" PRIx64, server->match_id );

    if ( !next_platform_mutex_create( &server->client_payload_mutex ) )
    {
        next_error( "server failed to create client payload mutex" );
        next_server_destroy( server );
        return NULL;
    }

#ifndef __linux__

    if ( !next_platform_mutex_create( &server->send_buffer.mutex ) )
    {
        next_error( "server failed to create send buffer mutex" );
        next_server_destroy( server );
        return NULL;
    }

#endif // #ifndef __linux__

    return server;    
}

void next_server_destroy( next_server_t * server )
{
    next_assert( server );
    next_assert( server->state == NEXT_SERVER_STOPPED );        // IMPORTANT: Please stop the server and wait until state is NEXT_SERVER_STOPPED before destroying it

    next_platform_mutex_destroy( &server->client_payload_mutex );

#ifdef __linux__

    if ( server->program != NULL )
    {
        if ( server->attached_native )
        {
            xdp_program__detach( server->program, server->interface_index, XDP_MODE_NATIVE, 0 );
        }
        if ( server->attached_skb )
        {
            xdp_program__detach( server->program, server->interface_index, XDP_MODE_SKB, 0 );
        }
        xdp_program__close( server->program );
    }

    for ( int i = 0; i < NUM_SERVER_XDP_SOCKETS; i++ )
    {
        next_server_xdp_socket_t * socket = &server->socket[i];

        // todo: delete receive thread

        next_platform_mutex_destroy( &socket->receive_mutex );

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

#else // #ifdef __linux__

    if ( server->socket )
    {
        next_platform_socket_destroy( server->socket );
    }

    next_platform_mutex_destroy( &server->send_buffer.mutex );

#endif // #ifdef __linux__

    next_clear_and_free( server->context, server, sizeof(next_server_t) );
}

void next_server_client_timed_out( next_server_t * server, int client_index )
{
    next_assert( client_index >= 0 );
    next_assert( client_index < NEXT_MAX_CLIENTS );
    char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_info( "client %s timed out from slot %d", next_address_to_string( &server->client_address[client_index], buffer ), client_index );
    server->client_connected[client_index] = 0;
    memset( &server->client_address[client_index], 0, sizeof(next_address_t) );
#ifdef __linux__
    server->client_address_big_endian[client_index] = 0;
    server->client_port_big_endian[client_index] = 0;
#endif // #ifdef __linux__
}

void next_server_client_disconnected( next_server_t * server, int client_index )
{
    next_assert( client_index >= 0 );
    next_assert( client_index < NEXT_MAX_CLIENTS );
    char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_info( "client %s disconnected from slot %d", next_address_to_string( &server->client_address[client_index], buffer ), client_index );
    server->client_connected[client_index] = 0;
    memset( &server->client_address[client_index], 0, sizeof(next_address_t) );
#ifdef __linux__
    server->client_address_big_endian[client_index] = 0;
    server->client_port_big_endian[client_index] = 0;
#endif // #ifdef __linux__
}

void next_server_update_timeout( next_server_t * server )
{
    double current_time = next_platform_time();

    for ( int i = 0; i < NEXT_MAX_CLIENTS; i++ )
    {
        if ( server->client_connected[i] )
        {
            if ( server->client_direct[i] )
            {
                if ( server->client_last_packet_receive_time[i] + NEXT_DIRECT_TIMEOUT < current_time )
                {
                    next_server_client_timed_out( server, i );
                }
            }
            else
            {
                // todo: next timeout                
            }
        }
    }
}

void next_server_update( next_server_t * server )
{
    next_assert( server );

    // todo: mock stopping -> stopped transition
    if ( server->state == NEXT_SERVER_STOPPING )
    {
        server->state = NEXT_SERVER_STOPPED;
    }

    next_server_update_timeout( server );
}

bool next_server_client_connected( next_server_t * server, int client_index )
{
    next_assert( server );
    next_assert( client_index >= 0 );
    next_assert( client_index <= NEXT_MAX_CLIENTS );
    return server->client_connected[client_index];
}

void next_server_disconnect_client( next_server_t * server, int client_index )
{
    next_assert( server );
    next_assert( client_index >= 0 );
    next_assert( client_index <= NEXT_MAX_CLIENTS );

    if ( !server->client_connected[client_index] )
        return;

    next_server_client_disconnected( server, client_index );
}

void next_server_stop( next_server_t * server )
{
    next_assert( server );
    server->state = NEXT_SERVER_STOPPING;
}

int next_server_state( next_server_t * server )
{
    next_assert( server );
    return server->state;
}

uint64_t next_server_id( next_server_t * server )
{
    next_assert( server );
    return server->server_id;
}

#ifdef __linux__

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

int generate_packet_header( void * data, uint8_t * server_ethernet_address, uint8_t * client_ethernet_address, uint32_t server_address_big_endian, uint32_t client_address_big_endian, uint16_t server_port_big_endian, uint16_t client_port_big_endian, int payload_bytes )
{
    struct ethhdr * eth = (ethhdr*) data;
    struct iphdr  * ip  = (iphdr*) ( (uint8_t*)data + sizeof( struct ethhdr ) );
    struct udphdr * udp = (udphdr*) ( (uint8_t*)ip + sizeof( struct iphdr ) );

    // generate ethernet header

    memcpy( eth->h_source, server_ethernet_address, ETH_ALEN );
    memcpy( eth->h_dest, client_ethernet_address, ETH_ALEN );
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

#endif // #ifdef __linux__

#ifndef __linux__

uint8_t * next_server_start_packet_internal( struct next_server_t * server, next_address_t * to, uint8_t packet_type )
{
    next_assert( server );
    next_assert( to );

    next_platform_mutex_acquire( &server->send_buffer.mutex );

    uint8_t * packet_data = NULL;
    int packet = server->send_buffer.current_packet ;
    if ( server->send_buffer.current_packet < NEXT_SERVER_MAX_SEND_PACKETS )
    {
        packet_data = server->send_buffer.data + packet * NEXT_MAX_PACKET_BYTES;
        server->send_buffer.current_packet++;
    }

    next_platform_mutex_release( &server->send_buffer.mutex );

    if ( !packet_data )
        return NULL;

    packet_data += NEXT_HEADER_BYTES;

    server->send_buffer.to[packet] = *to;
    server->send_buffer.packet_type[packet] = packet_type;
    server->send_buffer.packet_bytes[packet] = 0;

    return packet_data;
}

#endif // #ifndef __linux__

uint8_t * next_server_start_packet( struct next_server_t * server, int client_index, uint64_t * out_sequence )
{
    next_assert( server );
    next_assert( client_index >= 0 );
    next_assert( client_index < NEXT_MAX_CLIENTS );
    next_assert( out_sequence );

    if ( !server->client_connected[client_index] )
        return NULL;

#ifdef __linux__

    // todo: AF_XDP
    return NULL;

#else // #ifdef __linux__

    // todo: this can actually be atomic increment
    next_platform_mutex_acquire( &server->client_payload_mutex );
    uint64_t sequence = ++server->client_payload_sequence[client_index];
    next_platform_mutex_release( &server->client_payload_mutex );

    if ( server->client_direct[client_index] )
    {
        // direct packet

        uint8_t * packet_data = next_server_start_packet_internal( server, &server->client_address[client_index], NEXT_PACKET_DIRECT );
        if ( !packet_data )
            return NULL;

        uint64_t endian_sequence = sequence;
        next_endian_fix( &endian_sequence );
        memcpy( packet_data, (char*)&endian_sequence, 8 );

        packet_data += 8;

        *out_sequence = sequence;

        return packet_data;
    }
    else
    {
        // todo: next packet

        return NULL;
    }

#endif // #ifdef __linux__
}

void next_server_finish_packet( struct next_server_t * server, uint8_t * packet_data, int packet_bytes )
{
    next_assert( server );
    next_assert( packet_bytes >= 0 );
    next_assert( packet_bytes <= NEXT_MTU );

#ifdef __linux__

    // todo: AF_XDP

#else // #ifdef __linux__

    size_t offset = ( packet_data - server->send_buffer.data );

    offset -= offset % NEXT_MAX_PACKET_BYTES;

    next_assert( offset < NEXT_MAX_PACKET_BYTES*NEXT_SERVER_MAX_SEND_PACKETS );

    const int packet = (int) ( offset / NEXT_MAX_PACKET_BYTES );

    next_assert( packet >= 0 );  
    next_assert( packet < NEXT_SERVER_MAX_SEND_PACKETS );  

    next_assert( packet_data );
    next_assert( packet_bytes > 0 );
    next_assert( packet_bytes <= NEXT_MTU );

    server->send_buffer.packet_bytes[packet] = packet_bytes + NEXT_HEADER_BYTES + 8;

    // write the packet header

    packet_data -= NEXT_HEADER_BYTES + 8;

    packet_data[0] = server->send_buffer.packet_type[packet];

    uint8_t to_address_data[32];
    next_address_data( &server->send_buffer.to[packet], to_address_data );

    uint8_t from_address_data[32];
    next_address_data( &server->public_address, from_address_data );

    uint8_t * a = packet_data + 1;
    uint8_t * b = packet_data + 3;

    uint8_t magic[8];
    memset( magic, 0, sizeof(magic) );

    next_generate_pittle( a, from_address_data, to_address_data, packet_bytes );
    next_generate_chonkle( b, magic, from_address_data, to_address_data, packet_bytes );

#endif // #ifdef __linux__
}

void next_server_abort_packet( struct next_server_t * server, uint8_t * packet_data )
{
    next_assert( server );

#ifdef __linux__

    // todo: AF_XDP

#else // #ifdef __linux__

    size_t offset = ( packet_data - server->send_buffer.data );

    offset -= offset % NEXT_MAX_PACKET_BYTES;

    next_assert( offset < NEXT_MAX_PACKET_BYTES*NEXT_SERVER_MAX_SEND_PACKETS );

    const int packet = (int) ( offset / NEXT_MAX_PACKET_BYTES );

    next_assert( packet >= 0 );  
    next_assert( packet < NEXT_SERVER_MAX_SEND_PACKETS );  

    server->send_buffer.packet_bytes[packet] = 0;

#endif // #ifdef __linux__
}

void next_server_send_packets( struct next_server_t * server )
{
    next_assert( server );

#ifdef __linux__

// todo: to make this work we need to scatter packets when sent across n send buffers, one per-XDP socket
#if 0
    for ( int s = 0; s < NUM_SERVER_XDP_SOCKETS; s++ )
    {
        next_server_xdp_socket_t * socket = &server->socket[s];
    
        // mark any sent packet frames as free to be reused

        while ( true )
        {
            uint32_t complete_index;

            unsigned int num_completed = xsk_ring_cons__peek( &server->complete_queue, XSK_RING_CONS__DEFAULT_NUM_DESCS, &complete_index );

            if ( num_completed == 0 )
                break;

            for ( int i = 0; i < num_completed; i++ )
            {
                uint64_t frame = *xsk_ring_cons__comp_addr( &server->complete_queue, complete_index++ );
                next_server_free_frame( server, frame );
            }

            xsk_ring_cons__release( &server->complete_queue, num_completed );
        }

        // count how many valid packets we have to send in the send buffer (non-zero size)

        int num_packets_to_send = 0;

        const int num_packets = (int) server->send_buffer.current_packet;

        for ( int i = 0; i < num_packets; i++ )
        {
            const int packet_bytes = (int) server->send_buffer.packet_bytes[i];

            if ( packet_bytes > 0 )
            {
                num_packets_to_send++;
            }
        }

        // send packets in batches

        int index = 0;

        while ( true )
        {
            if ( num_packets_to_send == 0 )
                break;

            int batch_packets = ( num_packets_to_send < NEXT_XDP_SEND_BATCH_SIZE ) ? num_packets_to_send : NEXT_XDP_SEND_BATCH_SIZE;

            const int original_batch_packets = batch_packets;

            uint64_t frames[NEXT_XDP_SEND_BATCH_SIZE];
            for ( int i = 0; i < batch_packets; i++ )
            {
                // allocate frames up first, so we know 100% that we can send any frames that we reserve in the tx buffer

                frames[i] = next_server_alloc_frame( server );
                next_assert( frames[i] != INVALID_FRAME );
                if ( frames[i] == INVALID_FRAME )
                {
                    next_warn( "out of frames. can't send all packets..." );
                    for ( int j = 0; j < i; j++ )
                    {
                        next_server_free_frame( server, frames[j] );
                    }
                    if ( xsk_ring_prod__needs_wakeup( &server->send_queue ) )
                    {
                        sendto( xsk_socket__fd( server->xsk ), NULL, 0, MSG_DONTWAIT, NULL, 0 );
                    }
                    return;
                }

                // reserve entries in the send queue. we *must* send all entries we reserve

                uint32_t send_queue_index;
                batch_packets = xsk_ring_prod__reserve( &server->send_queue, batch_packets, &send_queue_index );
                if ( batch_packets == 0 ) 
                {
                    next_warn( "server send queue is full" );
                    return;
                }

                // it's possible to reserve fewer entries in the send queue than we requested. when this happens we have to free some frames

                for ( int j = batch_packets; j < original_batch_packets; j++ )
                {
                    next_server_free_frame( server, frames[j] );
                }

                // setup descriptors for packets to be sent

                for ( int i = 0; i < batch_packets; i++ )
                {
                    while ( server->send_buffer.packet_bytes[index] == 0 )
                    {
                        index++;
                    } 

                    struct xdp_desc * desc = xsk_ring_prod__tx_desc( &server->send_queue, send_queue_index + i );

                    uint8_t * packet_data = (uint8_t*)server->buffer + frames[i];

                    const int payload_bytes = server->send_buffer.packet_bytes[index];

                    memcpy( packet_data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr), server->send_buffer.data + index * NEXT_XDP_FRAME_SIZE, payload_bytes );

                    // todo: get these from the client arrays according to client_index or whatever
                    uint32_t client_address_big_endian = 0x0301a8c0;                            // batman IP on 10G LAN
                    uint32_t client_port_big_endian = next_platform_htons( 30000 );

                    int packet_bytes = generate_packet_header( packet_data, server->server_ethernet_address, server->gateway_ethernet_address, server->server_address_big_endian, client_address_big_endian, server->server_port_big_endian, client_port_big_endian, payload_bytes );

                    desc->addr = frames[i];
                    desc->len = packet_bytes;
                }

                // submit send queue to driver

                xsk_ring_prod__submit( &server->send_queue, batch_packets );
            }

            num_packets_to_send -= batch_packets;
        }

        // actually send the packets

        if ( xsk_ring_prod__needs_wakeup( &server->send_queue ) )
        {
            sendto( xsk_socket__fd( server->xsk ), NULL, 0, MSG_DONTWAIT, NULL, 0 );
        }

        // all packets have been sent

        next_assert( num_packets_to_send == 0 );

        server->send_buffer.current_packet = 0;
    }
#endif // #if 0

#else // #ifdef __linux__

    const int num_packets = (int) server->send_buffer.current_packet;

    for ( int i = 0; i < num_packets; i++ )
    {
        uint8_t * packet_data = server->send_buffer.data + i * NEXT_MAX_PACKET_BYTES;

        const int packet_bytes = (int) server->send_buffer.packet_bytes[i];

        if ( packet_bytes > 0 )
        {
            next_assert( packet_data );
            next_assert( packet_bytes <= NEXT_MAX_PACKET_BYTES );
            next_platform_socket_send_packet( server->socket, &server->send_buffer.to[i], packet_data, (int) server->send_buffer.packet_bytes[i] );
        }
    }

    server->send_buffer.current_packet = 0;

#endif // #ifdef __linux__
}

void next_server_process_packet_internal( next_server_t * server, next_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    const uint8_t packet_type = packet_data[0];

    if ( packet_type == NEXT_PACKET_DISCONNECT && packet_bytes == sizeof(next_disconnect_packet_t) )
    {
        int client_index = -1;
        for ( int i = 0; i < NEXT_MAX_CLIENTS; i++ )
        {
            if ( next_address_equal( from, &server->client_address[i] ) )
            {
                client_index = i;
                break;
            }
        }

        if ( client_index == -1 )
            return;

        next_server_disconnect_client( server, client_index );
    }
}

void next_server_process_direct_packet( next_server_t * server, next_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    if ( packet_bytes < NEXT_HEADER_BYTES + 8 )
        return;

    if ( server->process_packets.num_packets == NEXT_SERVER_MAX_RECEIVE_PACKETS )
        return;

    int client_index = -1;
    int first_free_slot = -1;
    for ( int i = 0; i < NEXT_MAX_CLIENTS; i++ )
    {
        if ( first_free_slot == -1 && !server->client_connected[i] )
        {
            first_free_slot = i;
        }
        if ( next_address_equal( from, &server->client_address[i] ) )
        {
            client_index = i;
            break;
        }
    }

    if ( client_index == -1 )
    {
        if ( first_free_slot != -1 )
        {
            client_index = first_free_slot;
            char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
            next_info( "client %s connected in slot %d", next_address_to_string( from, buffer ) );
            server->client_connected[client_index] = true;
            server->client_direct[client_index] = true;
            server->client_address[client_index] = *from;
            // todo: stash big endian address and port for XDP
        }
        else
        {
            // all client slots are full
            return;
        }
    }

    server->client_last_packet_receive_time[client_index] = next_platform_time();

    const int index = server->process_packets.num_packets++;

    uint64_t sequence;
    memcpy( (char*) &sequence, packet_data + NEXT_HEADER_BYTES, 8 );
    next_endian_fix( &sequence );

    packet_data += NEXT_HEADER_BYTES + 8;
    packet_bytes -= NEXT_HEADER_BYTES + 8;

    next_assert( packet_bytes >= 0 );

    server->process_packets.client_index[index] = client_index;
    server->process_packets.sequence[index] = sequence;
    server->process_packets.packet_data[index] = packet_data;
    server->process_packets.packet_bytes[index] = packet_bytes;
}

void next_server_receive_packets( next_server_t * server )
{
    next_assert( server );

    // IMPORTANT: Each time you call next_server_receive_packets you throw away
    // any packets ready for processing that you have not processed yet!
    server->process_packets.num_packets = 0;

#ifdef __linux__

    for ( int queue = 0; queue < NUM_SERVER_XDP_SOCKETS; queue++ )
    {
        // double buffer socket receive buffer ...

        next_server_xdp_socket_t * socket = &server->socket[queue];

        next_platform_mutex_acquire( &socket->receive_mutex );
        const int current_index = socket->receive_buffer_index;
        socket->receive_buffer_index = current_index ? 0 : 1;
        next_platform_mutex_release( &socket->receive_mutex );

        // ... now we can access the off receive buffer without contention

        next_server_xdp_receive_buffer_t * receive_buffer = &socket->receive_buffer[current_index];

        for ( int i = 0; i < receive_buffer->num_packets; i++ )
        {
            next_address_t from = receive_buffer->from[i];
            uint8_t * packet_data = receive_buffer->packet_data + i * NEXT_MAX_PACKET_BYTES;
            const int packet_bytes = receive_buffer->packet_bytes[i];

            if ( packet_bytes < 18 )
                continue;

            const uint8_t packet_type = packet_data[0];

            if ( packet_type == NEXT_PACKET_DIRECT )
            {  
                next_server_process_direct_packet( server, &from, packet_data, packet_bytes );
            }
            else
            {
                next_server_process_packet_internal( server, &from, packet_data, packet_bytes );            
            }
        }
    }

    // todo: move this to a thread per-socket

    for ( int queue = 0; queue < NUM_SERVER_XDP_SOCKETS; queue++ )
    {
        next_server_xdp_socket_t * socket = &server->socket[queue];

        uint32_t receive_index;
        
        uint32_t num_packets = xsk_ring_cons__peek( &socket->receive_queue, NEXT_XDP_RECV_QUEUE_SIZE, &receive_index );

        if ( num_packets > 0 )
        {
            for ( uint32_t i = 0; i < num_packets; i++ ) 
            {
                const struct xdp_desc * desc = xsk_ring_cons__rx_desc( &socket->receive_queue, receive_index + i );

                uint8_t * packet_data = (uint8_t*)socket->buffer + desc->addr;

                int packet_bytes = desc->len - ( sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) );

                next_info( "received %d byte packet on queue %d", packet_bytes, queue );

                if ( packet_bytes > 18 && socket->receive_buffer.current_packet < NEXT_XDP_RECV_QUEUE_SIZE )
                {
                    const int index = socket->receive_buffer.current_packet++;
                    socket->receive_buffer.packet_data[index] = socket->receive_buffer.data + index * NEXT_MAX_PACKET_BYTES;
                    socket->receive_buffer.packet_bytes[index] = packet_bytes;
                    memcpy( socket->receive_buffer.packet_data[index], packet_data, packet_bytes );
                }

                // todo: batch prod__submit -> num_packets
                uint32_t fill_index;
                if ( xsk_ring_prod__reserve( &socket->fill_queue, 1, &fill_index ) == 1 ) 
                {
                    *xsk_ring_prod__fill_addr( &socket->fill_queue, fill_index ) = desc->addr;
                    xsk_ring_prod__submit( &socket->fill_queue, 1 );
                }
            }

            xsk_ring_cons__release( &socket->receive_queue, num_packets );
        }
    }

#else // #ifdef __linux__

    server->receive_buffer.current_packet = 0;

    while ( 1 )
    {
        if ( server->receive_buffer.current_packet >= NEXT_SERVER_MAX_RECEIVE_PACKETS )
            break;

        uint8_t * packet_data = server->receive_buffer.data + NEXT_MAX_PACKET_BYTES * server->receive_buffer.current_packet;

        struct next_address_t from;
        int packet_bytes = next_platform_socket_receive_packet( server->socket, &from, packet_data, NEXT_MAX_PACKET_BYTES );
        if ( packet_bytes == 0 )
            break;

        // basic packet filter

        if ( !next_basic_packet_filter( packet_data, packet_bytes ) )
        {
            next_debug( "basic packet filter dropped packet" );
            continue;
        }

#if NEXT_ADVANCED_PACKET_FILTER

        // todo: advanced packet filter

#endif // #if NEXT_ADVANCED_PACKET_FILTER

        const uint8_t packet_type = packet_data[0];

        if ( packet_type == NEXT_PACKET_DIRECT )
        {  
            next_server_process_direct_packet( server, &from, packet_data, packet_bytes );
        }
        else
        {
            next_server_process_packet_internal( server, &from, packet_data, packet_bytes );            
        }
    }

#endif // #ifdef __linux__
}

struct next_server_process_packets_t * next_server_process_packets( struct next_server_t * server )
{
    next_assert( server );
    return &server->process_packets;
}
