/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0

    USAGE:

        clang -Ilibbpf/src -g -O2 -target bpf -c client_backend_xdp.c -o client_backend_xdp.o
        sudo ip link set dev enp4s0 xdp obj client_backend_xdp.o sec client_backend_xdp
        sudo cat /sys/kernel/debug/tracing/trace_pipe
        sudo ip link set dev enp4s0 xdp off
*/

#if defined(__linux__) && defined(__BPF__)

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

#define NEXT_CLIENT_BACKEND_PACKET_INIT_REQUEST              0
#define NEXT_CLIENT_BACKEND_PACKET_INIT_RESPONSE             1
#define NEXT_CLIENT_BACKEND_PACKET_PING                      2
#define NEXT_CLIENT_BACKEND_PACKET_PONG                      3
#define NEXT_CLIENT_BACKEND_PACKET_REFRESH_TOKEN             4

#define NEXT_SIGN_PUBLIC_KEY_BYTES                          32
#define NEXT_SIGN_PRIVATE_KEY_BYTES                         64

#define NEXT_SECRETBOX_KEY_BYTES                            32

#define NEXT_MAX_CONNECT_TOKEN_BYTES                       500
#define NEXT_MAX_CONNECT_TOKEN_BACKENDS                     32
#define NEXT_CONNECT_TOKEN_SIGNATURE_BYTES                  64

#define NEXT_CLIENT_BACKEND_TOKEN_CRYPTO_HEADER_BYTES       36

#define ADVANCED_PACKET_FILTER                               0

#include "client_backend_shared.h"

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohl(x)        __builtin_bswap32(x)
#define bpf_htonl(x)        __builtin_bswap32(x)
#define bpf_ntohs(x)        __builtin_bswap16(x)
#define bpf_htons(x)        __builtin_bswap16(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohl(x)        (x)
#define bpf_htonl(x)        (x)
#define bpf_ntohs(x)        (x)
#define bpf_htons(x)        (x)
#else
# error "Endianness detection needs to be set up for your compiler?!"
#endif

struct next_sign_create_args
{
    __u8 private_key[NEXT_SIGN_PRIVATE_KEY_BYTES];
};

struct next_sign_verify_args
{
    __u8 public_key[NEXT_SIGN_PUBLIC_KEY_BYTES];
};

extern int bpf_next_sha256( void * data, int data__sz, void * output, int output__sz ) __ksym;

extern int bpf_next_sign_create( void * data, int data__sz, void * signature, int signature__sz, struct next_sign_create_args * args ) __ksym;

extern int bpf_next_sign_verify( void * data, int data__sz, void * signature, int signature__sz, struct next_sign_verify_args * args ) __ksym;

extern int bpf_next_secretbox_encrypt( void * data, int data__sz, void * key, int key__sz ) __ksym;

extern int bpf_next_secretbox_decrypt( void * data, int data__sz, void * key, int key__sz ) __ksym;

#pragma pack(push,1)
struct next_connect_token_t
{
    uint64_t version;
    uint64_t expire_timestamp;
    uint64_t buyer_id;
    uint64_t server_id;
    uint64_t session_id;
    uint64_t user_hash;
    uint32_t client_public_address;
    uint32_t backend_addresses[NEXT_MAX_CONNECT_TOKEN_BACKENDS];             // big endian ipv4. 0 if not provided.
    uint16_t backend_ports[NEXT_MAX_CONNECT_TOKEN_BACKENDS];                 // big endian port. 0 if not provided.
    uint8_t pings_per_second;
    uint8_t max_connect_seconds;
    uint8_t signature[NEXT_CONNECT_TOKEN_SIGNATURE_BYTES];
};
#pragma pack(pop)

#pragma pack(push,1)
struct next_client_backend_token_t
{
    uint8_t crypto_header[NEXT_CLIENT_BACKEND_TOKEN_CRYPTO_HEADER_BYTES];
    uint64_t version;
    uint64_t expire_timestamp;
    uint64_t buyer_id;
    uint64_t server_id;
    uint64_t session_id;
    uint64_t user_hash;
};
#pragma pack(pop)

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

static void reflect_packet( void * data, int payload_bytes, __u8 * magic )
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

    unsigned short sum = 0;

    sum += ( from >> 24 );
    sum += ( from >> 16 ) & 0xFF;
    sum += ( from >> 8  ) & 0xFF;
    sum += ( from       ) & 0xFF;

    sum += ( to >> 24 );
    sum += ( to >> 16 ) & 0xFF;
    sum += ( to >> 8  ) & 0xFF;
    sum += ( to       ) & 0xFF;

    sum += ( payload_bytes >> 8 );
    sum += ( payload_bytes      ) & 0xFF;

    char * sum_data = (char*) &sum;

    __u8 sum_0 = ( sum      ) & 0xFF;
    __u8 sum_1 = ( sum >> 8 );

    __u8 pittle[2];
    pittle[0] = 1 | ( sum_0 ^ sum_1 ^ 193 );
    pittle[1] = 1 | ( ( 255 - pittle[0] ) ^ 113 );

    packet_data[1] = pittle[0];
    packet_data[2] = pittle[1];

    __u64 hash = 0xCBF29CE484222325;

    hash ^= magic[0];
    hash *= 0x00000100000001B3;

    hash ^= magic[1];
    hash *= 0x00000100000001B3;

    hash ^= magic[2];
    hash *= 0x00000100000001B3;

    hash ^= magic[3];
    hash *= 0x00000100000001B3;

    hash ^= magic[4];
    hash *= 0x00000100000001B3;

    hash ^= magic[5];
    hash *= 0x00000100000001B3;

    hash ^= magic[6];
    hash *= 0x00000100000001B3;

    hash ^= magic[7];
    hash *= 0x00000100000001B3;

    hash ^= ( from       ) & 0xFF;
    hash *= 0x00000100000001B3;

    hash ^= ( from >> 8  ) & 0xFF;
    hash *= 0x00000100000001B3;

    hash ^= ( from >> 16 ) & 0xFF;
    hash *= 0x00000100000001B3;

    hash ^= ( from >> 24 );
    hash *= 0x00000100000001B3;

    hash ^= ( to       ) & 0xFF;
    hash *= 0x00000100000001B3;

    hash ^= ( to >> 8  ) & 0xFF;
    hash *= 0x00000100000001B3;

    hash ^= ( to >> 16 ) & 0xFF;
    hash *= 0x00000100000001B3;

    hash ^= ( to >> 24 );
    hash *= 0x00000100000001B3;

    hash ^= ( payload_bytes      ) & 0xFF;
    hash *= 0x00000100000001B3;

    hash ^= ( payload_bytes >> 8 );
    hash *= 0x00000100000001B3;

    __u8 hash_0 = ( hash       ) & 0xFF;
    __u8 hash_1 = ( hash >> 8  ) & 0xFF;
    __u8 hash_2 = ( hash >> 16 ) & 0xFF;
    __u8 hash_3 = ( hash >> 24 ) & 0xFF;
    __u8 hash_4 = ( hash >> 32 ) & 0xFF;
    __u8 hash_5 = ( hash >> 40 ) & 0xFF;
    __u8 hash_6 = ( hash >> 48 ) & 0xFF;
    __u8 hash_7 = ( hash >> 56 );

    __u8 chonkle[15];

    chonkle[0] = ( ( hash_6 & 0xC0 ) >> 6 ) + 42;
    chonkle[1] = ( hash_3 & 0x1F ) + 200;
    chonkle[2] = ( ( hash_2 & 0xFC ) >> 2 ) + 5;
    chonkle[3] = hash_0;
    chonkle[4] = ( hash_2 & 0x03 ) + 78;
    chonkle[5] = ( hash_4 & 0x7F ) + 96;
    chonkle[6] = ( ( hash_1 & 0xFC ) >> 2 ) + 100;
    if ( ( hash_7 & 1 ) == 0 ) 
    {
        chonkle[7] = 79;
    } 
    else 
    {
        chonkle[7] = 7;
    }
    if ( ( hash_4 & 0x80 ) == 0 )
    {
        chonkle[8] = 37;
    } 
    else 
    {
        chonkle[8] = 83;
    }
    chonkle[9] = ( hash_5 & 0x07 ) + 124;
    chonkle[10] = ( ( hash_1 & 0xE0 ) >> 5 ) + 175;
    chonkle[11] = ( hash_6 & 0x3F ) + 33;
    __u8 value = ( hash_1 & 0x03 );
    if ( value == 0 )
    {
        chonkle[12] = 97;
    } 
    else if ( value == 1 )
    {
        chonkle[12] = 5;
    } 
    else if ( value == 2 )
    {
        chonkle[12] = 43;
    } 
    else 
    {
        chonkle[12] = 13;
    }
    chonkle[13] = ( ( hash_5 & 0xF8 ) >> 3 ) + 210;
    chonkle[14] = ( ( hash_7 & 0xFE ) >> 1 ) + 17;

    packet_data[3]  = chonkle[0];
    packet_data[4]  = chonkle[1];
    packet_data[5]  = chonkle[2];
    packet_data[6]  = chonkle[3];
    packet_data[7]  = chonkle[4];
    packet_data[8]  = chonkle[5];
    packet_data[9]  = chonkle[6];
    packet_data[10] = chonkle[7];
    packet_data[11] = chonkle[8];
    packet_data[12] = chonkle[9];
    packet_data[13] = chonkle[10];
    packet_data[14] = chonkle[11];
    packet_data[15] = chonkle[12];
    packet_data[16] = chonkle[13];
    packet_data[17] = chonkle[14];
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
                struct udphdr * udp = (void*) ip + sizeof(struct iphdr);

                if ( (void*)udp + sizeof(struct udphdr) <= data_end )
                {
                    int key = 0;
                    struct client_backend_config * config = (struct client_backend_config*) bpf_map_lookup_elem( &client_backend_config_map, &key );
                    if ( config == NULL )
                    {
                        debug_printf( "config is null" );
                        return XDP_PASS;
                    }

                    if ( ip->daddr == config->public_address && udp->dest == config->port )
                    {
                        __u8 * packet_data = (unsigned char*) (void*)udp + sizeof(struct udphdr);

                        __u8 magic[8] = {0,0,0,0,0,0,0,0};

                        // Drop packets that are too small to be valid

                        if ( (void*)packet_data + 18 > data_end )
                        {
                            debug_printf( "packet is too small" );
                            return XDP_DROP;
                        }

                        // Drop packets that are too large to be valid

                        int packet_bytes = data_end - (void*)udp - sizeof(struct udphdr);

                        if ( packet_bytes > 1400 )
                        {
                            debug_printf( "packet is too large" );
                            return XDP_DROP;
                        }

                        // Basic packet filter

                        if ( packet_data[2] != ( 1 | ( ( 255 - packet_data[1] ) ^ 113 ) )                                             ||
                             packet_data[3] < 0x2A || packet_data[3] > 0x2D                                                           ||
                             packet_data[4] < 0xC8 || packet_data[4] > 0xE7                                                           ||
                             packet_data[5] < 0x05 || packet_data[5] > 0x44                                                           ||
                             packet_data[7] < 0x4E || packet_data[7] > 0x51                                                           ||
                             packet_data[8] < 0x60 || packet_data[8] > 0xDF                                                           ||
                             packet_data[9] < 0x64 || packet_data[9] > 0xE3                                                           ||
                             packet_data[10] != 0x07 && packet_data[10] != 0x4F                                                       ||
                             packet_data[11] != 0x25 && packet_data[11] != 0x53                                                       ||
                             packet_data[12] < 0x7C || packet_data[12] > 0x83                                                         ||
                             packet_data[13] < 0xAF || packet_data[13] > 0xB6                                                         ||
                             packet_data[14] < 0x21 || packet_data[14] > 0x60                                                         ||
                             packet_data[15] != 0x61 && packet_data[15] != 0x05 && packet_data[15] != 0x2B && packet_data[15] != 0x0D ||
                             packet_data[16] < 0xD2 || packet_data[16] > 0xF1                                                         ||
                             packet_data[17] < 0x11 || packet_data[17] > 0x90 )
                        {
                            debug_printf( "basic packet filter dropped packet" );
                            return XDP_DROP;
                        }

#if ADVANCED_PACKET_FILTER

                        // Advanced packet filter

                        __u32 from = ip->saddr;
                        __u32 to   = config->public_address;

                        unsigned short sum = 0;

                        sum += ( from       ) & 0xFF;
                        sum += ( from >> 8  ) & 0xFF;
                        sum += ( from >> 16 ) & 0xFF;
                        sum += ( from >> 24 );

                        sum += ( to       ) & 0xFF;
                        sum += ( to >> 8  ) & 0xFF;
                        sum += ( to >> 16 ) & 0xFF;
                        sum += ( to >> 24 );

                        sum += ( packet_bytes >> 8 );
                        sum += ( packet_bytes      ) & 0xFF;

                        char * sum_data = (char*) &sum;

                        __u8 sum_0 = ( sum      ) & 0xFF;
                        __u8 sum_1 = ( sum >> 8 );

                        __u8 pittle[2];
                        pittle[0] = 1 | ( sum_0 ^ sum_1 ^ 193 );
                        pittle[1] = 1 | ( ( 255 - pittle[0] ) ^ 113 );

                        if ( pittle[0] != packet_data[1] || pittle[1] != packet_data[2] )
                        {
                            debug_printf( "advanced packet filter dropped packet (a)" );
                            return XDP_DROP;
                        }

                        int passed = 0;
                        {
                            __u64 hash = 0xCBF29CE484222325;

                            hash ^= magic[0];
                            hash *= 0x00000100000001B3;

                            hash ^= magic[1];
                            hash *= 0x00000100000001B3;

                            hash ^= magic[2];
                            hash *= 0x00000100000001B3;

                            hash ^= magic[3];
                            hash *= 0x00000100000001B3;

                            hash ^= magic[4];
                            hash *= 0x00000100000001B3;

                            hash ^= magic[5];
                            hash *= 0x00000100000001B3;

                            hash ^= magic[6];
                            hash *= 0x00000100000001B3;

                            hash ^= magic[7];
                            hash *= 0x00000100000001B3;

                            hash ^= ( from       ) & 0xFF;
                            hash *= 0x00000100000001B3;

                            hash ^= ( from >> 8  ) & 0xFF;
                            hash *= 0x00000100000001B3;

                            hash ^= ( from >> 16 ) & 0xFF;
                            hash *= 0x00000100000001B3;

                            hash ^= ( from >> 24 );
                            hash *= 0x00000100000001B3;

                            hash ^= ( to       ) & 0xFF;
                            hash *= 0x00000100000001B3;

                            hash ^= ( to >> 8  ) & 0xFF;
                            hash *= 0x00000100000001B3;

                            hash ^= ( to >> 16 ) & 0xFF;
                            hash *= 0x00000100000001B3;

                            hash ^= ( to >> 24 );
                            hash *= 0x00000100000001B3;

                            hash ^= ( packet_bytes      ) & 0xFF;
                            hash *= 0x00000100000001B3;

                            hash ^= ( packet_bytes >> 8 );
                            hash *= 0x00000100000001B3;

                            __u8 hash_0 = ( hash       ) & 0xFF;
                            __u8 hash_1 = ( hash >> 8  ) & 0xFF;
                            __u8 hash_2 = ( hash >> 16 ) & 0xFF;
                            __u8 hash_3 = ( hash >> 24 ) & 0xFF;
                            __u8 hash_4 = ( hash >> 32 ) & 0xFF;
                            __u8 hash_5 = ( hash >> 40 ) & 0xFF;
                            __u8 hash_6 = ( hash >> 48 ) & 0xFF;
                            __u8 hash_7 = ( hash >> 56 );

                            __u8 chonkle[15];

                            chonkle[0] = ( ( hash_6 & 0xC0 ) >> 6 ) + 42;
                            chonkle[1] = ( hash_3 & 0x1F ) + 200;
                            chonkle[2] = ( ( hash_2 & 0xFC ) >> 2 ) + 5;
                            chonkle[3] = hash_0;
                            chonkle[4] = ( hash_2 & 0x03 ) + 78;
                            chonkle[5] = ( hash_4 & 0x7F ) + 96;
                            chonkle[6] = ( ( hash_1 & 0xFC ) >> 2 ) + 100;
                            if ( ( hash_7 & 1 ) == 0 ) 
                            {
                                chonkle[7] = 79;
                            } 
                            else 
                            {
                                chonkle[7] = 7;
                            }
                            if ( ( hash_4 & 0x80 ) == 0 )
                            {
                                chonkle[8] = 37;
                            } 
                            else 
                            {
                                chonkle[8] = 83;
                            }
                            chonkle[9] = ( hash_5 & 0x07 ) + 124;
                            chonkle[10] = ( ( hash_1 & 0xE0 ) >> 5 ) + 175;
                            chonkle[11] = ( hash_6 & 0x3F ) + 33;
                            __u8 value = ( hash_1 & 0x03 );
                            if ( value == 0 )
                            {
                                chonkle[12] = 97;
                            } 
                            else if ( value == 1 )
                            {
                                chonkle[12] = 5;
                            } 
                            else if ( value == 2 )
                            {
                                chonkle[12] = 43;
                            } 
                            else 
                            {
                                chonkle[12] = 13;
                            }
                            chonkle[13] = ( ( hash_5 & 0xF8 ) >> 3 ) + 210;
                            chonkle[14] = ( ( hash_7 & 0xFE ) >> 1 ) + 17;

                            if ( chonkle[0] == packet_data[3]   &&
                                 chonkle[1] == packet_data[4]   &&
                                 chonkle[2] == packet_data[5]   &&
                                 chonkle[3] == packet_data[6]   &&
                                 chonkle[4] == packet_data[7]   &&
                                 chonkle[5] == packet_data[8]   &&
                                 chonkle[6] == packet_data[9]   &&
                                 chonkle[7] == packet_data[10]  &&
                                 chonkle[8] == packet_data[11]  &&
                                 chonkle[9] == packet_data[12]  &&
                                 chonkle[10] == packet_data[13] &&
                                 chonkle[11] == packet_data[14] &&
                                 chonkle[12] == packet_data[15] &&
                                 chonkle[13] == packet_data[16] &&
                                 chonkle[14] == packet_data[17] )
                            {
                                passed = 1;
                            }
                        }

                        if ( !passed )
                        {
                            debug_printf( "advanced packet filter dropped packet (b)" );
                            return XDP_DROP;
                        }

#endif // #if ADVANCED_PACKET_FILTER

                        switch ( packet_data[0] )
                        {
                            case NEXT_CLIENT_BACKEND_PACKET_INIT_REQUEST:
                            {
                                if ( (void*)packet_data + 336 > data_end )
                                {
                                    debug_printf( "client backend init request packet is too small" );
                                    return XDP_DROP;
                                }

                                struct next_sign_verify_args args = { { 0x9d, 0x59, 0x40, 0xa4, 0xe2, 0x4a, 0xa3, 0x0a, 0xf2, 0x30, 0xb6, 0x1b, 0x49, 0x7d, 0x60, 0xe8, 0x6d, 0xf9, 0x03, 0x28, 0x5c, 0x96, 0x83, 0x06, 0x89, 0xf5, 0xdd, 0x62, 0x8a, 0x25, 0x95, 0x16 } };
                                __u8 * connect_token = packet_data + 18;
                                __u8 * signature = packet_data + 18 + 310 - 64;
                                if ( bpf_next_sign_verify( connect_token, 310 - 64, signature, 64, &args ) != 0 )
                                {
                                    debug_printf( "connect token did not verify" );
                                    return XDP_DROP;
                                }

                                debug_printf( "reflect packet" );

                                reflect_packet( data, 336, magic );
                            }
                            break;

                            case NEXT_CLIENT_BACKEND_PACKET_PING:
                            {
                                // ...
                            }
                            break;
                            
                            case NEXT_CLIENT_BACKEND_PACKET_REFRESH_TOKEN:
                            {
                                // ...
                            }
                            break;

                            default:
                                return XDP_DROP;
                        }

                        return XDP_TX;
                    }
                }
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

#endif // #if defined(__linux__) && defined(__BPF__)
