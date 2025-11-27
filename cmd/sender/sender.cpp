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
    uint8_t server_ethernet_address[ETH_ALEN];
    uint8_t gateway_ethernet_address[ETH_ALEN];
    uint32_t server_address_big_endian;
    uint16_t server_port_big_endian;
    next_platform_thread_t * send_thread;

    uint8_t padding_3[1024];
};

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
    int interface_index;
    int num_queues;
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

    while ( !quit )
    {
        // ...

        next_platform_sleep( 1.0 / 100.0 );
    }

    next_term();

    return 0;
}
