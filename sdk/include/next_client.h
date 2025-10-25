/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#ifndef NEXT_CLIENT_H
#define NEXT_CLIENT_H

#include "next_address.h"

struct next_client_t;

#define NEXT_CLIENT_DISCONNECTED      0
#define NEXT_CLIENT_CONNECTING        1
#define NEXT_CLIENT_CONNECTED         2

next_client_t * next_client_create( void * context, const char * connect_token, void (*packet_received_callback)( next_client_t * client, void * context, const uint8_t * packet_data, int packet_bytes ) );

void next_client_destroy( next_client_t * client );

void next_client_update( next_client_t * client );

void next_client_send_packet( next_client_t * client, const uint8_t * packet_data, int packet_bytes );

void next_client_disconnect( next_client_t * client );

int next_client_state( next_client_t * client );

uint64_t next_client_session_id( next_client_t * client );

uint64_t next_client_server_id( next_client_t * client );

#endif // #ifndef NEXT_CLIENT_H
