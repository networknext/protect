/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#include "next_server.h"
#include "next_config.h"
#include "next_internal_config.h"
#include "next_constants.h"
#include "next_platform.h"
#include "next_hash.h"

#include <memory.h>

struct next_server_t
{
    void * context;
    int state;
    next_address_t bind_address;
    next_address_t public_address;
    uint64_t server_id;
    uint64_t match_id;
    next_platform_socket_t * socket;
    void (*packet_received_callback)( next_server_t * server, void * context, int client_index, const uint8_t * packet_data, int packet_bytes );
};

// todo
// extern next_internal_config_t next_global_config;

next_server_t * next_server_create( void * context, const char * bind_address_string, const char * public_address_string, void (*packet_received_callback)( next_server_t * client, void * context, int client_index, const uint8_t * packet_data, int packet_bytes ) )
{
    next_assert( packet_received_callback );
    next_assert( bind_address_string );
    next_assert( public_address_string );

    next_address_t bind_address;
    if ( next_address_parse( &bind_address, bind_address_string ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not parse bind address" );
        return NULL;
    }

    next_address_t public_address;
    if ( next_address_parse( &public_address, public_address_string ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not parse public address" );
        return NULL;
    }

    next_server_t * server = (next_server_t*) next_malloc( context, sizeof(next_server_t) );
    if ( !server )
        return NULL;

    memset( server, 0, sizeof( next_server_t) );
    
    server->context = context;
    server->packet_received_callback = packet_received_callback;

    server->socket = next_platform_socket_create( server->context, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0.0f, NEXT_DEFAULT_SOCKET_SEND_BUFFER_SIZE, NEXT_DEFAULT_SOCKET_RECEIVE_BUFFER_SIZE );
    // server->socket = next_platform_socket_create( server->context, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0.0f, next_global_config.socket_send_buffer_size, next_global_config.socket_receive_buffer_size );
    if ( server->socket == NULL )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "server could not create socket" );
        next_server_destroy( server );
        return NULL;
    }

    char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_printf( NEXT_LOG_LEVEL_INFO, "server started on %s", next_address_to_string( &bind_address, address_string ) );

    server->bind_address = bind_address;
    server->public_address = public_address;
    server->state = NEXT_SERVER_RUNNING;
    server->server_id = next_hash_string( public_address_string );
    server->match_id = next_random_uint64();

    next_printf( NEXT_LOG_LEVEL_INFO, "server id is %016" PRIx64, server->server_id );
    next_printf( NEXT_LOG_LEVEL_INFO, "match id is %016" PRIx64, server->match_id );

    return server;    
}

void next_server_destroy( next_server_t * server )
{
    next_assert( server );
    next_assert( server->state == NEXT_SERVER_STOPPED );        // IMPORTANT: Please stop the server and wait until state is NEXT_SERVER_STOPPED before destroying it

    if ( server->socket )
    {
        next_platform_socket_destroy( server->socket );
    }

    next_clear_and_free( server->context, server, sizeof(next_server_t) );
}

void next_server_update( next_server_t * server )
{
    next_assert( server );

    // todo
    (void) server;
    next_platform_sleep( 1.0 / 100.0 );

    // todo
    if ( server->state == NEXT_SERVER_STOPPING )
    {
        server->state = NEXT_SERVER_STOPPED;
    }
}

uint8_t * net_server_start_packet( struct net_server_t * server, int client_index )
{
    next_assert( server );
    // todo
    (void) client_index;
    return NULL;
}

void net_server_finish_packet( struct net_server_t * server, uint8_t * packet_data, int packet_bytes )
{
    next_assert( server );
    (void) server;
    (void) packet_data;
    (void) packet_bytes;
    // todo
}

void net_server_abort_packet( struct net_server_t * server, uint8_t * packet_data )
{
    next_assert( server );
    // todo
    (void) packet_data;
}

void net_server_send_packets( struct net_server_t * server )
{
    next_assert( server );
    // todo
    (void) server;
}

bool next_server_client_connected( next_server_t * server, int client_index )
{
    next_assert( server );
    (void) client_index;
    // todo
    return false;
}

void next_server_disconnect_client( next_server_t * server, int client_index )
{
    next_assert( server );
    (void) client_index;
    // todo
}

void next_server_stop( next_server_t * server )
{
    next_assert( server );
    server->state = NEXT_SERVER_STOPPING;
}

int next_server_state( next_server_t * server )
{
    next_assert( server );
    return server->state;
}

uint64_t next_server_id( next_server_t * server )
{
    next_assert( server );
    return server->server_id;
}
