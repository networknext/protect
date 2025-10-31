/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#include "next_client.h"
#include "next_config.h"
#include "next_internal_config.h"
#include "next_constants.h"
#include "next_platform.h"
#include "next_packet_filter.h"

#include <memory.h>

// todo
#include <stdio.h>

struct next_client_t
{
    void * context;
    int state;
    uint16_t bound_port;
    int num_updates;
    uint64_t session_id;
    uint64_t server_id;
    next_platform_socket_t * socket;
    void (*packet_received_callback)( next_client_t * client, void * context, const uint8_t * packet_data, int packet_bytes );
};

// todo
// extern next_internal_config_t next_global_config;

next_client_t * next_client_create( void * context, const char * connect_token, void (*packet_received_callback)( next_client_t * client, void * context, const uint8_t * packet_data, int packet_bytes ) )
{
    next_assert( connect_token );
    next_assert( packet_received_callback );

    // todo
    (void) connect_token;
    printf( "connect token: '%s'\n", connect_token );

    next_assert( packet_received_callback );

    next_client_t * client = (next_client_t*) next_malloc( context, sizeof(next_client_t) );
    if ( !client )
        return NULL;

    memset( client, 0, sizeof( next_client_t) );
    
    client->context = context;
    client->state = NEXT_CLIENT_CONNECTING;
    client->packet_received_callback = packet_received_callback;

    next_address_t bind_address;
    memset( &bind_address, 0, sizeof(bind_address) );
    bind_address.type = NEXT_ADDRESS_IPV4;

    // IMPORTANT: for many platforms it's best practice to bind to ipv6 and go dual stack on the client
    if ( next_platform_client_dual_stack() )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "client socket is dual stack ipv4 and ipv6" );
        bind_address.type = NEXT_ADDRESS_IPV6;
    }

    // IMPORTANT: some platforms (GDK) have a preferred port that we must use to access packet tagging
    // If the bind address has set port of 0, substitute the preferred client port here
    if ( bind_address.port == 0 )
    {
        int preferred_client_port = next_platform_preferred_client_port();
        if ( preferred_client_port != 0 )
        {
            next_printf( NEXT_LOG_LEVEL_INFO, "client socket using preferred port %d", preferred_client_port );
            bind_address.port = preferred_client_port;
        }
    }

    client->socket = next_platform_socket_create( client->context, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0.0f, NEXT_DEFAULT_SOCKET_SEND_BUFFER_SIZE, NEXT_DEFAULT_SOCKET_RECEIVE_BUFFER_SIZE );
    // client->socket = next_platform_socket_create( client->context, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0.0f, next_global_config.socket_send_buffer_size, next_global_config.socket_receive_buffer_size );
    if ( client->socket == NULL )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create socket" );
        next_client_destroy( client );
        return NULL;
    }

    char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_printf( NEXT_LOG_LEVEL_INFO, "client bound to %s", next_address_to_string( &bind_address, address_string ) );

    client->bound_port = bind_address.port;

    return client;    
}

void next_client_destroy( next_client_t * client )
{
    // IMPORTANT: Please disconnect and wait for the client to disconnect before destroying the client
    next_assert( client->state == NEXT_CLIENT_DISCONNECTED );

    if ( client->socket )
    {
        next_platform_socket_destroy( client->socket );
    }

    next_clear_and_free( client->context, client, sizeof(next_client_t) );
}

void next_client_update( next_client_t * client )
{
    next_assert( client );

    // todo
    uint8_t packet_data[1024];
    next_address_t from;
    int packet_bytes = next_platform_socket_receive_packet( client->socket, &from, packet_data, sizeof(packet_data) );
    if ( packet_bytes != 0 )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "client received %d byte packet\n", packet_bytes );
    }

    // todo: mock connection
    client->num_updates++;
    if ( client->num_updates == 100 )
    {
        client->state = NEXT_CLIENT_CONNECTED;
    }

    // todo
    (void) client;
    next_platform_sleep( 1.0 / 100.0 );
}

void next_client_send_packet( next_client_t * client, const uint8_t * packet_data, int packet_bytes )
{
    next_assert( client );

    // todo: mock packets for testing xdp client backend
    if ( client->state == NEXT_CLIENT_CONNECTING )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "connecting..." );

        next_address_t from_address;
        next_address_parse( &from_address, "45.79.157.168" );            // home IP address

        next_address_t to_address;
        next_address_parse( &to_address, "45.250.253.243:40000" );       // latitude.newyork

        uint8_t from_address_data[32];
        next_address_data( &from_address, from_address_data );

        uint8_t to_address_data[32];
        next_address_data( &to_address, to_address_data );

        uint8_t test_packet_data[18+100];
        memset( test_packet_data, 0, sizeof(test_packet_data) );

        uint8_t * a = test_packet_data + 1;
        uint8_t * b = test_packet_data + 3;

        uint8_t magic[8];
        memset( magic, 0, sizeof(magic) );

        int test_packet_length = 118;
        next_generate_pittle( a, from_address_data, to_address_data, test_packet_length );
        next_generate_chonkle( b, magic, from_address_data, to_address_data, test_packet_length );

        test_packet_data[0] = 0;

        next_platform_socket_send_packet( client->socket, &to_address, test_packet_data, test_packet_length );
    }

    if ( client->state != NEXT_CLIENT_CONNECTED )
        return;

    // todo
    (void) client;
    (void) packet_data;
    (void) packet_bytes;
}

void next_client_disconnect( next_client_t * client )
{
    next_assert( client );
    client->state = NEXT_CLIENT_DISCONNECTED;
}

int next_client_state( next_client_t * client )
{
    next_assert( client );
    return client->state;
}

uint64_t next_client_session_id( next_client_t * client )
{
    next_assert( client );
    return client->session_id;
}

uint64_t next_client_server_id( next_client_t * client )
{
    next_assert( client );
    return client->server_id;

}
