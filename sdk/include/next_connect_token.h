/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#ifndef NEXT_CONNECT_TOKEN_H
#define NEXT_CONNECT_TOKEN_H

#include "next.h"

#define NEXT_MAX_CONNECT_TOKEN_BYTES 256

struct next_connect_token_t
{
    uint32_t nonce;
    uint64_t expire_timestamp;
    uint64_t buyer_id;
    uint64_t server_id;
    uint64_t session_id;
    uint64_t user_hash;

};

bool write_connect_token( char * output, size_t output_size );

#endif // #ifndef NEXT_ROUTE_TOKEN_H
