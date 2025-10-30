/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0

    USAGE:

        clang -Ilibbpf/src -g -O2 -target bpf -c client_backend_xdp.c -o client_backend_xdp.o
        sudo ip link set dev enp4s0 xdp obj client_backend_xdp.o sec client_backend_xdp
        sudo cat /sys/kernel/debug/tracing/trace_pipe
        sudo ip link set dev enp4s0 xdp off
*/

#ifdef __linux__

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/string.h>
#include <bpf/bpf_helpers.h>

#define CLIENT_BACKEND_ADVANCED_PACKET_FILTER 0

#include "client_backend_shared.h"

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohl(x)        __builtin_bswap32(x)
#define bpf_htonl(x)        __builtin_bswap32(x)
#define bpf_ntohs(x)        __builtin_bswap16(x)
#define bpf_htons(x)        __builtin_bswap16(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohl(x)        (x)
#define bpf_htonl(x)        (x)
#define bpf_ntohs(x)        (x)
#define bpf_htons(x)        (x)
#else
# error "Endianness detection needs to be set up for your compiler?!"
#endif

/*
#define XCHACHA20POLY1305_NONCE_SIZE 24

#define CHACHA20POLY1305_KEY_SIZE 32

struct chacha20poly1305_crypto
{
    __u8 nonce[XCHACHA20POLY1305_NONCE_SIZE];
    __u8 key[CHACHA20POLY1305_KEY_SIZE];
};

int bpf_next_sha256( void * data, int data__sz, void * output, int output__sz ) __ksym;

int bpf_next_xchacha20poly1305_decrypt( void * data, int data__sz, struct chacha20poly1305_crypto * crypto ) __ksym;
*/

struct {
    __uint( type, BPF_MAP_TYPE_ARRAY );
    __type( key, __u32 );
    __type( value, struct client_backend_config );
    __uint( max_entries, 1 );
    __uint( pinning, LIBBPF_PIN_BY_NAME );
} client_backend_config_map SEC(".maps");

#define DEBUG 1

#if DEBUG
#define debug_printf bpf_printk
#else // #if DEBUG
#define debug_printf(...) do { } while (0)
#endif // #if DEBUG

static void reflect_packet( void * data, int payload_bytes )
{
    struct ethhdr * eth = data;
    struct iphdr  * ip  = data + sizeof( struct ethhdr );
    struct udphdr * udp = (void*) ip + sizeof( struct iphdr );

    __u16 a = udp->source;
    udp->source = udp->dest;
    udp->dest = a;
    udp->check = 0;
    udp->len = bpf_htons( sizeof(struct udphdr) + payload_bytes );

    __u32 b = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = b;
    ip->tot_len = bpf_htons( sizeof(struct iphdr) + sizeof(struct udphdr) + payload_bytes );
    ip->check = 0;

    char c[ETH_ALEN];
    memcpy( c, eth->h_source, ETH_ALEN );
    memcpy( eth->h_source, eth->h_dest, ETH_ALEN );
    memcpy( eth->h_dest, c, ETH_ALEN );

    __u16 * p = (__u16*) ip;
    __u32 checksum = p[0];
    checksum += p[1];
    checksum += p[2];
    checksum += p[3];
    checksum += p[4];
    checksum += p[5];
    checksum += p[6];
    checksum += p[7];
    checksum += p[8];
    checksum += p[9];
    checksum = ~ ( ( checksum & 0xFFFF ) + ( checksum >> 16 ) );
    ip->check = checksum;

    __u8 * packet_data = (void*) udp + sizeof( struct udphdr );

    __u32 from = ip->saddr;
    __u32 to   = ip->daddr;
}

SEC("client_backend_xdp") int client_backend_xdp_filter( struct xdp_md *ctx ) 
{ 
    void * data = (void*) (long) ctx->data; 

    void * data_end = (void*) (long) ctx->data_end; 

    struct ethhdr * eth = data;

    if ( (void*)eth + sizeof(struct ethhdr) <= data_end )
    {
        if ( eth->h_proto == __constant_htons(ETH_P_IP) ) // IPV4
        {
            struct iphdr * ip = data + sizeof(struct ethhdr);

            if ( (void*)ip + sizeof(struct iphdr) > data_end )
            {
                debug_printf( "smaller than ipv4 header" );
                return XDP_DROP;
            }

            if ( ip->ihl == 5 && ip->protocol == IPPROTO_UDP ) // UDP only
            {
                debug_printf( "udp packet" );

                struct udphdr * udp = (void*) ip + sizeof(struct iphdr);

                if ( (void*)udp + sizeof(struct udphdr) <= data_end )
                {
                    debug_printf( "get config" );

                    int key = 0;
                    struct client_backend_config * config = (struct client_backend_config*) bpf_map_lookup_elem( &client_backend_config_map, &key );
                    if ( config == NULL )
                    {
                        debug_printf( "config is null" );
                        return XDP_PASS;
                    }

                    debug_printf( "config public address = %x:%d", config->public_address, config->port );

                    // 8818ecb8:21974 ?!

                    if ( ip->daddr == 0x7cb7a8c0 && udp->dest == 16540 )
                    {
                        __u8 * packet_data = (unsigned char*) (void*)udp + sizeof(struct udphdr);

                        if ( (void*)packet_data + 100 != data_end )
                        {
                            debug_printf( "udp packet is not 100 bytes" );
                            return XDP_DROP;
                        }

                        debug_printf( "reflect packet" );

                        reflect_packet( data, 100 );

                        return XDP_TX;
                    }

                    /*
                    if ( udp->dest == config->port )//&& ip->daddr == config->public_address ) // &&  )
                    {
                        debug_printf( "valid port" );

                        if ( ip->daddr == config->public_address )
                        {
                            debug_printf( "valid address" );

                        }
                    }
                    */
                }
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

#endif // #ifdef __linux__
