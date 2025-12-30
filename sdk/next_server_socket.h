/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#pragma once

#ifndef NEXT_SERVER_SOCKET_H
#define NEXT_SERVER_SOCKET_H

#include "next_address.h"
#include "next_packets.h"
#include "next_constants.h"

struct next_server_socket_t;

#define NEXT_SERVER_SOCKET_STOPPED    0
#define NEXT_SERVER_SOCKET_RUNNING    1
#define NEXT_SERVER_SOCKET_STOPPING   2

struct next_server_socket_t * next_server_socket_create( void * context, const char * server_address, int num_xdp_queues = 7, int num_os_cpus = 1 );

void next_server_socket_destroy( struct next_server_socket_t * server_socket );

void next_server_socket_update( struct next_server_socket_t * server_socket );

void next_server_socket_stop( struct next_server_socket_t * server_socket );

int next_server_socket_state( struct next_server_socket_t * server_socket );

uint64_t next_server_socket_id( struct next_server_socket_t * server_socket );

int next_server_socket_num_queues( struct next_server_socket_t * server_socket );

// send packets (zero copy)

uint8_t * next_server_socket_start_packet( struct next_server_socket_t * server_socket, const next_address_t * to, uint64_t * packet_id );

void next_server_socket_finish_packet( struct next_server_socket_t * server_socket, uint64_t packet_id, uint8_t * packet_data, int packet_bytes );

void next_server_socket_abort_packet( struct next_server_socket_t * server_socket, uint64_t packet_id, uint8_t * packet_data );

void next_server_socket_send_packets( struct next_server_socket_t * server_socket );

// receive packets (zero copy)

void next_server_socket_receive_packets( struct next_server_socket_t * server_socket );

struct next_server_socket_process_packets_t
{
    int num_packets;
    next_address_t from[NEXT_SERVER_SOCKET_MAX_PROCESS_PACKETS];
    int packet_bytes[NEXT_SERVER_SOCKET_MAX_PROCESS_PACKETS];
    uint8_t * packet_data[NEXT_SERVER_SOCKET_MAX_PROCESS_PACKETS];
};

struct next_server_socket_process_packets_t * next_server_socket_process_packets( struct next_server_socket_t * server_socket );

#endif // #ifndef NEXT_SERVER_SOCKET_H
