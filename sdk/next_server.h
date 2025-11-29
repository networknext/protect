/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#pragma once

#ifndef NEXT_SERVER_H
#define NEXT_SERVER_H

#include "next_address.h"
#include "next_packets.h"
#include "next_constants.h"

struct next_server_t;

#define NEXT_SERVER_STOPPED    0
#define NEXT_SERVER_RUNNING    1
#define NEXT_SERVER_STOPPING   2

struct next_server_t * next_server_create( void * context, const char * bind_address, const char * public_address, int num_queues = 2 );

void next_server_destroy( struct next_server_t * server );

void next_server_update( struct next_server_t * server );

void next_server_stop( struct next_server_t * server );

int next_server_state( struct next_server_t * server );

uint64_t next_server_id( struct next_server_t * server );

int next_server_num_queues( struct next_server_t * server );

// send packets (zero copy)

uint8_t * next_server_start_packet( struct next_server_t * server, const next_address_t * to, uint64_t * packet_id );

void next_server_finish_packet( struct next_server_t * server, uint64_t packet_id, uint8_t * packet_data, int packet_bytes );

void next_server_abort_packet( struct next_server_t * server, uint64_t packet_id, uint8_t * packet_data );

void next_server_send_packets( struct next_server_t * server );

// receive packets (zero copy)

void next_server_receive_packets( struct next_server_t * server );

struct next_server_process_packets_t
{
    int num_packets;
    next_address_t from[NEXT_SERVER_MAX_PROCESS_PACKETS];
    int packet_bytes[NEXT_SERVER_MAX_PROCESS_PACKETS];
    uint8_t * packet_data[NEXT_SERVER_MAX_PROCESS_PACKETS];
};

struct next_server_process_packets_t * next_server_process_packets( struct next_server_t * server );

#endif // #ifndef NEXT_CLIENT_H
