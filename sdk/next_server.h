/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#pragma once

#ifndef NEXT_SERVER_H
#define NEXT_SERVER_H

#include "next_address.h"
#include "next_packets.h"

struct next_server_t;

#define NEXT_SERVER_STOPPED    0
#define NEXT_SERVER_RUNNING    1
#define NEXT_SERVER_STOPPING   2

next_server_t * next_server_create( void * context, const char * bind_address, const char * public_address );

void next_server_destroy( next_server_t * server );

void next_server_update( next_server_t * server );

bool next_server_client_connected( next_server_t * server, int client_index );

void next_server_disconnect_client( next_server_t * server, int client_index );

void next_server_stop( next_server_t * server );

int next_server_state( next_server_t * server );

uint64_t next_server_id( next_server_t * server );

// send packets (zero copy)

uint8_t * next_server_start_packet( struct next_server_t * server, int client_index, uint64_t * sequence );

void next_server_finish_packet( struct next_server_t * server, uint8_t * packet_data, int packet_bytes );

void next_server_abort_packet( struct next_server_t * server, uint8_t * packet_data );

void next_server_send_packets( struct next_server_t * server );

// receive packets (zero copy)

void next_server_receive_packets( struct next_server_t * server );

// ...

#endif // #ifndef NEXT_CLIENT_H
