/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#pragma once

#ifndef NEXT_CONNECT_TOKEN_H
#define NEXT_CONNECT_TOKEN_H

#include "next.h"

#define NEXT_MAX_CONNECT_TOKEN_BYTES 500

#define NEXT_MAX_CONNECT_TOKEN_BACKENDS 32

#define NEXT_CONNECT_TOKEN_SIGNATURE_BYTES 64

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
    uint8_t pongs_before_select;
    uint8_t max_connect_seconds;
    uint8_t backend_token_refresh_seconds;
    uint8_t signature[NEXT_CONNECT_TOKEN_SIGNATURE_BYTES];
};
#pragma pack(pop)

bool next_write_connect_token( next_connect_token_t * token, char * output, const uint8_t * private_key );

bool next_read_connect_token( next_connect_token_t * token, const char * input, const uint8_t * public_key );

void next_endian_fix( next_connect_token_t * token );

#endif // #ifndef NEXT_ROUTE_TOKEN_H
