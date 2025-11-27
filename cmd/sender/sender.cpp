/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
*/

#include "next.h"
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
#include <memory.h>
#include <stdio.h>
#include <atomic>
#include <signal.h>

static volatile int quit;

void interrupt_handler( int signal )
{
    (void) signal; quit = 1;
}

#define NEXT_XDP_NUM_FRAMES                  8192
#define NEXT_XDP_FRAME_SIZE                  2048
#define NEXT_XDP_SEND_QUEUE_SIZE             4096
#define NEXT_XDP_SEND_BATCH_SIZE               32

struct next_server_xdp_socket_t
{
    uint8_t padding_0[1024];

    int queue;

    uint8_t padding_1[1024];

    void * buffer;
    struct xsk_umem * umem;
    struct xsk_ring_prod send_queue;
    struct xsk_ring_cons complete_queue;
    struct xsk_socket * xsk;

    uint8_t padding_2[1024];

    uint32_t num_free_send_frames;
    uint64_t send_frames[NEXT_XDP_NUM_FRAMES];
    uint8_t sender_ethernet_address[ETH_ALEN];
    uint8_t gateway_ethernet_address[ETH_ALEN];
    uint32_t server_address_big_endian;
    uint16_t server_port_big_endian;
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
};

static sender_t sender;

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

    // find the network interface that matches the address

    const char * address_string = "69.67.149.151:40000";

    next_info( "address is %s", address_string );

    next_address_t address;
    if ( !next_address_parse( &address, address_string ) )
    {
        next_error( "could not parse address" );
        return 1;
    }

    uint32_t address_ipv4 = next_address_ipv4( &address );

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
                if ( sa->sin_addr.s_addr == address_ipv4 )
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

    if ( !get_gateway_mac_address( interface_name, sender.gateway_ethernet_address ) )
    {
        next_error( "could not get gateway mac address" );
        return 1;
    }

    // hulk
    /*
    sender.gateway_ethernet_address[0] = 0xd0;
    sender.gateway_ethernet_address[1] = 0x81;
    sender.gateway_ethernet_address[2] = 0x7a;
    sender.gateway_ethernet_address[3] = 0xd8;
    sender.gateway_ethernet_address[4] = 0x3a;
    sender.gateway_ethernet_address[5] = 0xec;
    */

    next_info( "gateway ethernet address is %02x.%02x.%02x.%02x.%02x.%02x", 
        sender.gateway_ethernet_address[0], 
        sender.gateway_ethernet_address[1], 
        sender.gateway_ethernet_address[2], 
        sender.gateway_ethernet_address[3], 
        sender.gateway_ethernet_address[4], 
        sender.gateway_ethernet_address[5] 
    );

    while ( !quit )
    {
        // ...

        next_platform_sleep( 1.0 / 100.0 );
    }

    next_term();

    return 0;
}
