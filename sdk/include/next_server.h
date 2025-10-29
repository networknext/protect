/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#ifndef NEXT_SERVER_H
#define NEXT_SERVER_H

#include "next_address.h"

struct next_server_t;

#define NEXT_SERVER_STOPPED    0
#define NEXT_SERVER_RUNNING    1
#define NEXT_SERVER_STOPPING   2

next_server_t * next_server_create( void * context, const char * bind_address, const char * public_address, void (*packet_received_callback)( next_server_t * server, void * context, int client_index, const uint8_t * packet_data, int packet_bytes ) );

void next_server_destroy( next_server_t * server );

void next_server_update( next_server_t * server );

uint8_t * net_server_start_packet( struct net_server_t * server, int client_index );

void net_server_finish_packet( struct net_server_t * server, uint8_t * packet_data, int packet_bytes );

void net_server_abort_packet( struct net_server_t * server, uint8_t * packet_data );

void net_server_send_packets( struct net_server_t * server );

bool next_server_client_connected( next_server_t * server, int client_index );

void next_server_disconnect_client( next_server_t * server, int client_index );

void next_server_stop( next_server_t * server );

int next_server_state( next_server_t * server );

uint64_t next_server_id( next_server_t * server );

#endif // #ifndef NEXT_CLIENT_H
