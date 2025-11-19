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

#include "next_server_xdp.h"

#endif // #ifdef __linux

#include <memory.h>
#include <stdio.h>

#ifndef __linux__

struct next_server_send_buffer_t
{
    next_platform_mutex_t mutex;
    size_t current_frame;
    next_address_t to[NEXT_NUM_SERVER_FRAMES];
    size_t packet_bytes[NEXT_NUM_SERVER_FRAMES];
    uint8_t packet_type[NEXT_NUM_SERVER_FRAMES];
    uint8_t data[NEXT_MAX_PACKET_BYTES*NEXT_NUM_SERVER_FRAMES];
};

struct next_server_receive_buffer_t
{
    int current_frame;
    bool processing_packets;
    int client_index[NEXT_NUM_SERVER_FRAMES];
    uint64_t sequence[NEXT_NUM_SERVER_FRAMES];
    uint8_t * packet_data[NEXT_NUM_SERVER_FRAMES];
    size_t packet_bytes[NEXT_NUM_SERVER_FRAMES];
    uint8_t data[NEXT_MAX_PACKET_BYTES*NEXT_NUM_SERVER_FRAMES];
};

#endif // #ifndef __linux__

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

    next_platform_mutex_t frame_mutex;
    uint32_t num_free_frames;
    uint64_t frames[NEXT_NUM_SERVER_FRAMES];

    void * buffer;
    struct xsk_umem * umem;
    struct xsk_ring_cons receive_queue;
    struct xsk_ring_prod send_queue;
    struct xsk_ring_cons complete_queue;
    struct xsk_ring_prod fill_queue;
    struct xsk_socket * xsk;

    bool sending_packets;
    uint32_t xdp_send_queue_index;

    int num_send_packets;
    uint64_t send_packet_offset[NEXT_XDP_MAX_SEND_PACKETS];
    int send_packet_bytes[NEXT_XDP_MAX_SEND_PACKETS];

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

    mac_address[5] = (uint8_t) strtol( mac_address_string + 0, NULL, 16 );
    mac_address[4] = (uint8_t) strtol( mac_address_string + 3, NULL, 16 );
    mac_address[3] = (uint8_t) strtol( mac_address_string + 6, NULL, 16 );
    mac_address[2] = (uint8_t) strtol( mac_address_string + 9, NULL, 16 );
    mac_address[1] = (uint8_t) strtol( mac_address_string + 12, NULL, 16 );
    mac_address[0] = (uint8_t) strtol( mac_address_string + 15, NULL, 16 );

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
        // todo
        printf( "could not find gateway ip string" );
        return false;
    }

    // parse the address and make sure it's a valid ipv4

    next_address_t address;
    if ( !next_address_parse( &address, gateway_ip_string ) || address.type != NEXT_ADDRESS_IPV4 )
    {
        // todo
        printf( "gateway address is not valid" );
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
        // todo
        printf( "did not find mac address" );
        return false;
    }

    mac_address_string[2] = 0;
    mac_address_string[5] = 0;
    mac_address_string[8] = 0;
    mac_address_string[11] = 0;
    mac_address_string[14] = 0;
    mac_address_string[17] = 0;

    mac_address[5] = (uint8_t) strtol( mac_address_string + 0, NULL, 16 );
    mac_address[4] = (uint8_t) strtol( mac_address_string + 3, NULL, 16 );
    mac_address[3] = (uint8_t) strtol( mac_address_string + 6, NULL, 16 );
    mac_address[2] = (uint8_t) strtol( mac_address_string + 9, NULL, 16 );
    mac_address[1] = (uint8_t) strtol( mac_address_string + 12, NULL, 16 );
    mac_address[0] = (uint8_t) strtol( mac_address_string + 15, NULL, 16 );

    return true;
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
        server->server_ethernet_address[5], 
        server->server_ethernet_address[4], 
        server->server_ethernet_address[3], 
        server->server_ethernet_address[2], 
        server->server_ethernet_address[1], 
        server->server_ethernet_address[0] 
    );

    // look up the gateway ethernet address for the network interface

    if ( !get_gateway_mac_address( interface_name, server->gateway_ethernet_address ) )
    {
        next_error( "server could not get gateway mac address" );
        next_server_destroy( server );
        return NULL;
    }

    next_info( "gateway ethernet address is %02x.%02x.%02x.%02x.%02x.%02x", 
        server->gateway_ethernet_address[5], 
        server->gateway_ethernet_address[4], 
        server->gateway_ethernet_address[3], 
        server->gateway_ethernet_address[2], 
        server->gateway_ethernet_address[1], 
        server->gateway_ethernet_address[0] 
    );

    // allow unlimited locking of memory, so all memory needed for packet buffers can be locked

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };

    if ( setrlimit( RLIMIT_MEMLOCK, &rlim ) ) 
    {
        next_error( "server could not setrlimit" );
        next_server_destroy( server );
        return NULL;
    }

    const int buffer_size = NEXT_NUM_SERVER_FRAMES * NEXT_SERVER_FRAME_SIZE;

    if ( posix_memalign( &server->buffer, getpagesize(), buffer_size ) ) 
    {
        next_error( "server could allocate buffer" );
        next_server_destroy( server );
        return NULL;
    }

    // allocate umem

    int result = xsk_umem__create( &server->umem, server->buffer, buffer_size, &server->fill_queue, &server->complete_queue, NULL );
    if ( result ) 
    {
        next_error( "server could not create umem" );
        next_server_destroy( server );
        return NULL;
    }

    // create xsk socket and assign to network interface queue

    struct xsk_socket_config xsk_config;

    memset( &xsk_config, 0, sizeof(xsk_config) );

    xsk_config.rx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_config.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_config.xdp_flags = XDP_ZEROCOPY;     
    xsk_config.bind_flags = XDP_USE_NEED_WAKEUP;
    xsk_config.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;

    int queue_id = 0;

    result = xsk_socket__create( &server->xsk, interface_name, queue_id, server->umem, &server->receive_queue, &server->send_queue, &xsk_config );
    if ( result )
    {
        next_error( "server could not create xsk socket" );
        next_server_destroy( server );
        return NULL;
    }

    // initialize frame allocator

    if ( !next_platform_mutex_create( &server->frame_mutex ) )
    {
        next_error( "server failed to create frame mutex" );
        next_server_destroy( server );
        return NULL;
    }

    for ( int j = 0; j < NEXT_NUM_SERVER_FRAMES; j++ )
    {
        server->frames[j] = j;
    }

    server->num_free_frames = NEXT_NUM_SERVER_FRAMES;

    // save the server public address and port in network order (big endian)

    server->server_address_big_endian = public_address_ipv4;

    server->server_port_big_endian = next_platform_htons( public_address.port );

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

    next_platform_mutex_destroy( &server->frame_mutex );

    if ( server->xsk )
    {
        xsk_socket__delete( server->xsk );
    }

    if ( server->umem )
    {
        xsk_umem__delete( server->umem );
    }

    free( server->buffer );

#else // #ifdef __linux__

    next_platform_mutex_destroy( &server->send_buffer.mutex );

    if ( server->socket )
    {
        next_platform_socket_destroy( server->socket );
    }

#endif // #ifdef __linux__

    next_clear_and_free( server->context, server, sizeof(next_server_t) );
}

#ifdef __linux__

#define INVALID_FRAME UINT64_MAX

uint64_t next_server_alloc_frame( next_server_t * server )
{
    next_platform_mutex_acquire( &server->frame_mutex );
    uint64_t frame = INVALID_FRAME;
    if ( server->num_free_frames > 0 )
    {
        server->num_free_frames--;
        frame = server->frames[server->num_free_frames];
        server->frames[server->num_free_frames] = INVALID_FRAME;
    }
    next_platform_mutex_release( &server->frame_mutex );
    return frame;
}

void next_server_free_frame( next_server_t * server, uint64_t frame )
{
    next_platform_mutex_acquire( &server->frame_mutex );
    next_assert( server->num_free_frames < NEXT_NUM_SERVER_FRAMES );
    server->frames[server->num_free_frames] = frame;
    server->num_free_frames++;
    next_platform_mutex_release( &server->frame_mutex );
}

#endif // #ifdef __linux__

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

void next_server_send_packets_begin( struct next_server_t * server )
{
    next_assert( server );

#ifdef __linux__

    next_assert( !server->sending_packets );     // IMPORTANT: You must call next_server_send_packets_end!

    // todo
    /*
    int result = xsk_ring_prod__reserve( &server->send_queue, NEXT_XDP_MAX_SEND_PACKETS, &server->xdp_send_queue_index );
    if ( result == 0 ) 
    {
        next_warn( "server send queue is full" );
        return;
    }
    */

    server->sending_packets = true;

#else // #ifdef __linux__

    // ...

#endif // #ifdef __linux__
}

uint8_t * next_server_start_packet_internal( struct next_server_t * server, next_address_t * to, uint8_t packet_type )
{
    next_assert( server );
    next_assert( to );
    next_assert( client_index >= 0 );

#ifdef __linux__

    if ( !server->sending_packets )
        return NULL;

    // todo
    return NULL;

    /*
    next_assert( server->num_send_packets < NEXT_XDP_MAX_SEND_PACKETS );
    if ( server->num_send_packets >= NEXT_XDP_MAX_SEND_PACKETS )
        return NULL;

    uint64_t frame = next_server_alloc_frame( server, send_index );

    next_assert( frame != INVALID_FRAME );      // this should never happen!
    if ( frame == INVALID_FRAME )
        return NULL;

    uint8_t * packet_data = (uint8_t*)server->buffer + ( NEXT_SERVER_FRAME_SIZE * frame );

    // todo: acquire send mutex here
    const int index = server->num_send_packets++;
    server->send_packet_frame[index] = frame;
    server->send_packet_bytes[index] = 0;
    // todo: release send mutex here

    return packet_data;
    */

#else // #ifdef __linux__

    next_platform_mutex_acquire( &server->send_buffer.mutex );

    uint8_t * packet_data = NULL;
    int frame = server->send_buffer.current_frame ;
    if ( server->send_buffer.current_frame < NEXT_NUM_SERVER_FRAMES )
    {
        packet_data = server->send_buffer.data + frame * NEXT_MAX_PACKET_BYTES;
        server->send_buffer.current_frame++;
    }

    next_platform_mutex_release( &server->send_buffer.mutex );

    if ( !packet_data )
        return NULL;

    packet_data += NEXT_HEADER_BYTES;

    next_assert( packet_info );

    server->send_buffer.to[frame] = *to;
    server->send_buffer.packet_type[frame] = packet_type;
    server->send_buffer.packet_bytes[frame] = 0;

    return packet_data;

#endif // #ifdef __linux__
}

uint8_t * next_server_start_packet( struct next_server_t * server, int client_index, uint64_t * out_sequence )
{
    next_assert( server );
    next_assert( client_index >= 0 );
    next_assert( client_index < NEXT_MAX_CLIENTS );
    next_assert( out_sequence );

    if ( !server->client_connected[client_index] )
        return NULL;

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
}

void next_server_finish_packet_internal( struct next_server_t * server, uint8_t * packet_data, int packet_bytes )
{
    next_assert( server );

#ifdef __linux__

    if ( !server->sending_packets )
        return;

    // todo: AF_XDP

#else // #ifdef __linux__

    size_t offset = ( packet_data - server->send_buffer.data );

    offset -= offset % NEXT_MAX_PACKET_BYTES;

    next_assert( offset < NEXT_MAX_PACKET_BYTES*NEXT_NUM_SERVER_FRAMES );

    const int frame = (int) ( offset / NEXT_MAX_PACKET_BYTES );

    next_assert( frame >= 0 );  
    next_assert( frame < NEXT_NUM_SERVER_FRAMES );  

    next_assert( packet_data );
    next_assert( packet_bytes > 0 );
    next_assert( packet_bytes <= NEXT_MTU );

    server->send_buffer.packet_bytes[frame] = packet_bytes + NEXT_HEADER_BYTES;

    // write the packet header

    packet_data -= 18;

    packet_data[0] = server->send_buffer.packet_type[frame];

    uint8_t to_address_data[32];
    next_address_data( &server->send_buffer.to[frame], to_address_data );

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

void next_server_finish_packet( struct next_server_t * server, uint8_t * packet_data, int packet_bytes )
{
    next_assert( server );
    next_assert( packet_bytes >= 0 );
    next_assert( packet_bytes <= NEXT_MTU );

    next_server_finish_packet_internal( server, packet_data - 8, packet_bytes + 8 );
}

void next_server_abort_packet( struct next_server_t * server, uint8_t * packet_data )
{
    next_assert( server );

#ifdef __linux__

    if ( !server->sending_packets )
        return;

    // todo: AF_XDP

#else // #ifdef __linux__

    size_t offset = ( packet_data - server->send_buffer.data );

    offset -= offset % NEXT_MAX_PACKET_BYTES;

    next_assert( offset < NEXT_MAX_PACKET_BYTES*NEXT_NUM_SERVER_FRAMES );

    const int frame = (int) ( offset / NEXT_MAX_PACKET_BYTES );

    next_assert( frame >= 0 );  
    next_assert( frame < NEXT_NUM_SERVER_FRAMES );  

    server->send_buffer.packet_bytes[frame] = 0;

#endif // #ifdef __linux__
}

void next_server_send_packets_end( struct next_server_t * server )
{
    next_assert( server );

#ifdef __linux__

    next_assert( server->sending_packets );

    // setup descriptors for packets that were sent

    /*
    for ( int i = 0; i < NEXT_XDP_MAX_SEND_PACKETS; i++ )
    {
        struct xdp_desc * desc = xsk_ring_prod__tx_desc( &server->send_queue, server->xdp_send_queue_index + i );

        uint64_t frame = next_server_alloc_frame( server );

        next_assert( frame != INVALID_FRAME );          // this should never happen
        if ( frame == INVALID_FRAME )
        {
            printf( "invalid frame\n" );
            exit(0);
        }

        uint8_t * packet_data = (uint8_t*)server->buffer + frame * NEXT_SERVER_FRAME_SIZE;

        // todo: actually set these to something valid
        uint32_t client_address_big_endian = 0;
        uint32_t client_port_big_endian = 0;

        int payload_bytes = 100;

        int packet_bytes = generate_packet_header( packet_data, server->server_ethernet_address, server->gateway_ethernet_address, server->server_address_big_endian, client_address_big_endian, server->server_port_big_endian, client_port_big_endian, payload_bytes );

        desc->addr = frame;
        desc->len = packet_bytes;
    }

    // submit send queue to driver

    xsk_ring_prod__submit( &server->send_queue, NEXT_XDP_MAX_SEND_PACKETS );

    // actually send the packets

    if ( xsk_ring_prod__needs_wakeup( &server->send_queue ) )
    {
        sendto( xsk_socket__fd( server->xsk ), NULL, 0, MSG_DONTWAIT, NULL, 0 );
    }

    // mark any sent packet frames as free to be reused

    uint32_t complete_index;

    unsigned int num_completed = xsk_ring_cons__peek( &server->complete_queue, XSK_RING_CONS__DEFAULT_NUM_DESCS, &complete_index );

    if ( num_completed > 0 ) 
    {
        printf( "%d completed\n", num_completed );
        fflush( stdout );

        for ( int i = 0; i < num_completed; i++ )
        {
            uint64_t frame = *xsk_ring_cons__comp_addr( &server->complete_queue, complete_index++ );

            printf( "frame %" PRId64 " completed\n", frame );

            next_server_free_frame( server, frame );
        }

        xsk_ring_cons__release( &server->complete_queue, num_completed );
    }
    */

    // reset ready for next packet send

    server->num_send_packets = 0;
    server->xdp_send_queue_index = 0;
    server->sending_packets = false;

#else // #ifdef __linux__

    const int num_packets = (int) server->send_buffer.current_frame;

    server->send_buffer.current_frame = 0;

    for ( int i = 0; i < num_packets; i++ )
    {
        uint8_t * packet_data = server->send_buffer.data + i*NEXT_MAX_PACKET_BYTES;

        const int packet_bytes = (int) server->send_buffer.packet_bytes[i];

        if ( packet_bytes > 0 )
        {
            next_assert( packet_data );
            next_assert( packet_bytes <= NET_MAX_PACKET_BYTES );
            next_platform_socket_send_packet( server->socket, &server->send_buffer.to[i], packet_data, (int) server->send_buffer.packet_bytes[i] );
        }
    }

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

void next_server_receive_packets( next_server_t * server )
{
    next_assert( server );

#ifdef __linux__

    // todo: AF_XDP

#else // #ifdef __linux__

    server->receive_buffer.current_frame = 0;

    while ( 1 )
    {
        if ( server->receive_buffer.current_frame >= NEXT_NUM_SERVER_FRAMES )
            break;

        uint8_t * packet_data = server->receive_buffer.data + NEXT_MAX_PACKET_BYTES * server->receive_buffer.current_frame;

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
            if ( packet_bytes < NEXT_HEADER_BYTES + 8 )
                continue;

            int client_index = -1;
            int first_free_slot = -1;
            for ( int i = 0; i < NEXT_MAX_CLIENTS; i++ )
            {
                if ( first_free_slot == -1 && !server->client_connected[i] )
                {
                    first_free_slot = i;
                }
                if ( next_address_equal( &from, &server->client_address[i] ) )
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
                    next_info( "client %s connected in slot %d", next_address_to_string( &from, buffer ) );
                    server->client_connected[client_index] = true;
                    server->client_direct[client_index] = true;
                    server->client_address[client_index] = from;
                }
                else
                {
                    // all client slots are full
                    continue;
                }
            }

            server->client_last_packet_receive_time[client_index] = next_platform_time();

            const int index = server->receive_buffer.current_frame;

            uint64_t sequence;
            memcpy( (char*) &sequence, packet_data + NEXT_HEADER_BYTES, 8 );
            next_endian_fix( &sequence );

            packet_data += NEXT_HEADER_BYTES + 8;
            packet_bytes -= NEXT_HEADER_BYTES + 8;

            next_assert( packet_bytes >= 0 );

            server->receive_buffer.client_index[index] = client_index;
            server->receive_buffer.sequence[index] = sequence;
            server->receive_buffer.packet_data[index] = packet_data;
            server->receive_buffer.packet_bytes[index] = packet_bytes;

            server->receive_buffer.current_frame++;
        }
        else
        {
            next_server_process_packet_internal( server, &from, packet_data, packet_bytes );            
        }
    }

#endif // #ifdef __linux__
}

struct next_server_process_packets_t * next_server_process_packets_begin( struct next_server_t * server )
{
    next_assert( server );

#ifdef __linux__

    // todo: AF_XDP
    memset( &server->process_packets, 0, sizeof(server->process_packets) );
    return &server->process_packets;

#else // #ifdef __linux__

    next_assert( !server->receive_buffer.processing_packets );          // IMPORTANT: You must always call next_server_process_packets_finish

    const int num_packets = server->receive_buffer.current_frame;

    if ( num_packets == 0 )
        return NULL;

    for ( int i = 0; i < num_packets; i++ )
    {
        server->process_packets.sequence[i] = server->receive_buffer.sequence[i];
        server->process_packets.client_index[i] = server->receive_buffer.client_index[i];
        server->process_packets.packet_bytes[i] = server->receive_buffer.packet_bytes[i];
        server->process_packets.packet_data[i] = server->receive_buffer.packet_data[i];
    }

    server->process_packets.num_packets = num_packets;

    server->receive_buffer.processing_packets = true;

    return &server->process_packets;

#endif // #ifdef __linux__
}

void next_server_packet_processed( struct next_server_t * server, uint8_t * packet_data )
{
    next_assert( server );
    next_assert( packet_data );

#ifdef __linux__

    // todo: AF_XDP

#else // #ifdef __linux__

    // ...

    (void) server;
    (void) packet_data;

#endif // #ifdef __linux__
}

void next_server_process_packets_end( struct next_server_t * server )
{
    next_assert( server );

#ifdef __linux__

    // todo: AF_XDP

#else // #ifdef __linux__

    next_assert( server->receive_buffer.processing_packets );
    server->receive_buffer.processing_packets = false;
    server->process_packets.num_packets = 0;

#endif // #ifdef __linux__
}


// todo: xdp send logic

#if 0

void socket_update( struct socket_t * socket, int queue_id )
{
    // don't do anything if we don't have enough free packets to send a batch

    if ( socket->num_frames < SEND_BATCH_SIZE )
        return;

    // queue packets to send

    int send_index;
    int result = xsk_ring_prod__reserve( &socket->send_queue, SEND_BATCH_SIZE, &send_index );
    if ( result == 0 ) 
    {
        return;
    }

    int num_packets = 0;
    uint64_t packet_address[SEND_BATCH_SIZE];
    int packet_length[SEND_BATCH_SIZE];

    while ( true )
    {
        uint64_t frame = socket_alloc_frame( socket );

        assert( frame != INVALID_FRAME );   // this should never happen

        uint8_t * packet = socket->buffer + frame;

        packet_address[num_packets] = frame;
        packet_length[num_packets] = client_generate_packet( packet, PAYLOAD_BYTES, socket->counter + num_packets );

        num_packets++;

        if ( num_packets == SEND_BATCH_SIZE )
            break;
    }

    for ( int i = 0; i < num_packets; i++ )
    {
        struct xdp_desc * desc = xsk_ring_prod__tx_desc( &socket->send_queue, send_index + i );
        desc->addr = packet_address[i];
        desc->len = packet_length[i];
    }

    xsk_ring_prod__submit( &socket->send_queue, num_packets );

    // send queued packets

    if ( xsk_ring_prod__needs_wakeup( &socket->send_queue ) )
        sendto( xsk_socket__fd( socket->xsk ), NULL, 0, MSG_DONTWAIT, NULL, 0 );

    // mark completed sent packet frames as free to be reused

    uint32_t complete_index;

    unsigned int completed = xsk_ring_cons__peek( &socket->complete_queue, XSK_RING_CONS__DEFAULT_NUM_DESCS, &complete_index );

    if ( completed > 0 ) 
    {
        for ( int i = 0; i < completed; i++ )
        {
            socket_free_frame( socket, *xsk_ring_cons__comp_addr( &socket->complete_queue, complete_index++ ) );
        }

        xsk_ring_cons__release( &socket->complete_queue, completed );

        __sync_fetch_and_add( &socket->sent_packets, completed );

        socket->counter += completed;
    }
}

#endif // #if 0
