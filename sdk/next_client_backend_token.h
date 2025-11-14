/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#pragma once

#ifndef NEXT_CLIENT_BACKEND_TOKEN_H
#define NEXT_CLIENT_BACKEND_TOKEN_H

#include "next.h"

#define NEXT_CLIENT_BACKEND_TOKEN_CRYPTO_HEADER_BYTES 36

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
    uint32_t client_address;                        // big endian ipv4
    uint16_t client_port;                           // big endian port #
};
#pragma pack(pop)

int next_write_client_backend_token( next_client_backend_token_t * token, uint8_t * output, const uint8_t * private_key );

bool next_read_client_backend_token( next_client_backend_token_t * token, const uint8_t * input, int input_bytes, const uint8_t * private_key );

#endif // #ifndef NEXT_ROUTE_TOKEN_H
