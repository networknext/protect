/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#ifndef CLIENT_BACKEND_SHARED_H
#define CLIENT_BACKEND_SHARED_H

#include "client_backend_constants.h"

#ifdef __linux__
#include <linux/types.h>
#endif // #ifdef __linux__

#if 0

struct relay_config
{
    __u32 dedicated;
    __u32 relay_public_address;                                             // big endian
    __u32 relay_internal_address;                                           // big endian
    __u16 relay_port;                                                       // big endian
    __u8 relay_secret_key[RELAY_SECRET_KEY_BYTES];
    __u8 relay_backend_public_key[RELAY_BACKEND_PUBLIC_KEY_BYTES];
    __u8 gateway_ethernet_address[RELAY_ETHERNET_ADDRESS_BYTES];
    __u8 use_gateway_ethernet_address;
};

struct relay_state
{
    __u64 current_timestamp;
    __u8 current_magic[8];
    __u8 previous_magic[8];
    __u8 next_magic[8];
    __u8 ping_key[RELAY_PING_KEY_BYTES];
};

struct relay_stats
{
    __u64 counters[RELAY_NUM_COUNTERS];
};

struct session_data
{
    __u8 session_private_key[RELAY_SESSION_PRIVATE_KEY_BYTES];
    __u64 expire_timestamp;
    __u64 session_id;
    __u64 payload_client_to_server_sequence;
    __u64 payload_server_to_client_sequence;
    __u64 special_client_to_server_sequence;
    __u64 special_server_to_client_sequence;
    __u32 envelope_kbps_up;
    __u32 envelope_kbps_down;
    __u32 next_address;                                                     // big endian
    __u32 prev_address;                                                     // big endian
    __u16 next_port;                                                        // big endian
    __u16 prev_port;                                                        // big endian
    __u8 session_version;
    __u8 next_internal;
    __u8 prev_internal;
    __u8 first_hop;
};

#pragma pack(push, 1)
struct ping_token_data
{
    __u8 ping_key[RELAY_PING_KEY_BYTES];
    __u64 expire_timestamp;                         
    __u32 source_address;                                                   // big endian
    __u32 dest_address;                                                     // big endian
    __u16 source_port;                                                      // big endian
    __u16 dest_port;                                                        // big endian
};
#pragma pack(pop)

#pragma pack(push, 1)
struct header_data
{
    __u8 session_private_key[RELAY_SESSION_PRIVATE_KEY_BYTES];
    __u8 packet_type;
    __u64 packet_sequence;
    __u64 session_id;
    __u8 session_version;
};
#pragma pack(pop)

struct decrypt_route_token_data
{
    __u8 relay_secret_key[RELAY_SECRET_KEY_BYTES];
    __u8 relay_backend_public_key[RELAY_BACKEND_PUBLIC_KEY_BYTES];
};

struct decrypt_continue_token_data
{
    __u8 relay_secret_key[RELAY_SECRET_KEY_BYTES];
    __u8 relay_backend_public_key[RELAY_BACKEND_PUBLIC_KEY_BYTES];
};

struct whitelist_key {
    __u32 address;                                                          // big endian
    __u32 port;                                                             // big endian (IMPORTANT: Must be __u32 or alignment issues cause failed lookups in map!)
};

struct whitelist_value {
    __u64 expire_timestamp;
    __u8 source_address[6];
    __u8 dest_address[6];
};

#pragma pack(push, 1)
struct route_token
{
    __u8 session_private_key[RELAY_SESSION_PRIVATE_KEY_BYTES];
    __u64 expire_timestamp;
    __u64 session_id;
    __u32 envelope_kbps_up;
    __u32 envelope_kbps_down;
    __u32 next_address;                                                     // big endian
    __u32 prev_address;                                                     // big endian
    __u16 next_port;                                                        // big endian
    __u16 prev_port;                                                        // big endian
    __u8 session_version;
    __u8 next_internal;
    __u8 prev_internal;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct continue_token
{
    __u64 expire_timestamp;
    __u64 session_id;
    __u8 session_version;
};
#pragma pack(pop)

struct session_key
{
    __u64 session_id;
    __u64 session_version;                                                  // IMPORTANT: must be __u64 or weird stuff happens
};

#endif // #if 0

#endif // #ifndef CLIENT_BACKEND_SHARED_H
