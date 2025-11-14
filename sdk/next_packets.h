/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#pragma once

#include "next_connect_token.h"
#include "next_client_backend_token.h"

#ifndef NEXT_PACKETS_H
#define NEXT_PACKETS_H

#define NEXT_PACKET_CLIENT_BACKEND_INIT_REQUEST                 0
#define NEXT_PACKET_CLIENT_BACKEND_INIT_RESPONSE                1
#define NEXT_PACKET_CLIENT_BACKEND_PING                         2
#define NEXT_PACKET_CLIENT_BACKEND_PONG                         3
#define NEXT_PACKET_CLIENT_BACKEND_REFRESH_TOKEN_REQUEST        4
#define NEXT_PACKET_CLIENT_BACKEND_REFRESH_TOKEN_RESPONSE       5

#define NEXT_PACKET_DIRECT                                      6

#pragma pack(push,1)

struct next_client_backend_init_request_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint8_t sdk_version_major;
    uint8_t sdk_version_minor;
    uint8_t sdk_version_patch;
    struct next_connect_token_t connect_token;
    uint64_t request_id;
};

struct next_client_backend_init_response_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint64_t request_id;
    struct next_client_backend_token_t backend_token;
};

struct next_client_backend_ping_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint8_t sdk_version_major;
    uint8_t sdk_version_minor;
    uint8_t sdk_version_patch;
    uint64_t request_id;
    uint64_t ping_sequence;
    struct next_client_backend_token_t backend_token;
};

struct next_client_backend_pong_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint64_t request_id;
    uint64_t ping_sequence;
};

struct next_client_backend_refresh_token_request_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint8_t sdk_version_major;
    uint8_t sdk_version_minor;
    uint8_t sdk_version_patch;
    uint64_t request_id;
    struct next_client_backend_token_t backend_token;
};

struct next_client_backend_refresh_token_response_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint64_t request_id;
    struct next_client_backend_token_t backend_token;
};

struct next_direct_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint64_t sequence;
    uint8_t payload[NEXT_MTU];
};

#pragma pack(pop)

inline void next_endian_fix( next_client_backend_init_request_packet_t * packet )
{

}

inline void next_endian_fix( next_client_backend_init_response_packet_t * packet )
{

}

inline void next_endian_fix( next_client_backend_ping_packet_t * packet )
{

}

inline void next_endian_fix( next_client_backend_pong_packet_t * packet )
{

}

inline void next_endian_fix( next_client_backend_refresh_token_request_packet_t * packet )
{
}

inline void next_endian_fix( next_client_backend_refresh_token_response_packet_t * packet )
{

}

inline void next_endian_fix( next_direct_packet_t * packet )
{
    
}

#endif // #ifndef NEXT_PACKETS_H
