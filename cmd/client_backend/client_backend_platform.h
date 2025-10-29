/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#ifndef CLIENT_BACKEND_PLATFORM_H
#define CLIENT_BACKEND_PLATFORM_H

#include "client_backend.h"
#include <pthread.h>

// -----------------------------------------------------------------------------------------------------------------------------------------------

#define CLIENT_BACKEND_PLATFORM_SOCKET_NON_BLOCKING       0
#define CLIENT_BACKEND_PLATFORM_SOCKET_BLOCKING           1

typedef int client_backend_platform_socket_handle_t;

struct client_backend_platform_socket_t
{
    int type;
    client_backend_platform_socket_handle_t handle;
};

struct client_backend_platform_thread_t
{
    pthread_t handle;
};

typedef void* (client_backend_platform_thread_func_t)(void*);

struct client_backed_platform_mutex_t
{
    pthread_mutex_t handle;
};

// -----------------------------------------------------------------------------------------------------------------------------------------------

int client_backend_platform_init();

double client_backend_platform_time();

void client_backend_platform_sleep( double time );

// -----------------------------------------------------------------------------------------------------------------------------------------------

void client_backend_platform_random_bytes( uint8_t * buffer, int bytes );

// -----------------------------------------------------------------------------------------------------------------------------------------------

int client_backend_platform_parse_address( char * address_string, uint32_t * address, uint16_t * port );

// -----------------------------------------------------------------------------------------------------------------------------------------------

struct client_backend_platform_socket_t * client_backend_platform_socket_create( uint32_t address, uint16_t port, int socket_type, float timeout_seconds, int send_buffer_size, int receive_buffer_size );

void client_backend_platform_socket_destroy( struct client_backend_platform_socket_t * socket );

void client_backend_platform_socket_send_packet( struct client_backend_platform_socket_t * socket, uint32_t to_address, uint16_t to_port, const void * packet_data, int packet_bytes );

int client_backend_platform_socket_receive_packet( struct client_backend_platform_socket_t * socket, uint32_t * from_address, uint16_t * from_port, void * packet_data, int max_packet_size );

// -----------------------------------------------------------------------------------------------------------------------------------------------

struct client_backend_platform_thread_t * client_backend_platform_thread_create( client_backend_platform_thread_func_t * thread_function, void * arg );

void client_backend_platform_thread_join( struct client_backend_platform_thread_t * thread );

void client_backend_platform_thread_destroy( struct client_backend_platform_thread_t * thread );

bool client_backend_platform_thread_set_high_priority( struct client_backend_platform_thread_t * thread );

// -----------------------------------------------------------------------------------------------------------------------------------------------

struct client_backend_platform_mutex_t * client_backend_platform_mutex_create();

void client_backend_platform_mutex_acquire( struct client_backend_platform_mutex_t * mutex );

void client_backend_platform_mutex_release( struct client_backend_platform_mutex_t * mutex );

void client_backend_platform_mutex_destroy( struct client_backend_platform_mutex_t * mutex );

// -----------------------------------------------------------------------------------------------------------------------------------------------

#endif // #ifndef CLIENT_BACKEND_PLATFORM_H
