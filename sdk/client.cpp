/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 1.0
*/

#include "next.h"
#include "next_client.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>

static volatile int quit;

void interrupt_handler( int signal )
{
    (void) signal; quit = 1;
}

void packet_received_callback( next_client_t * client, void * context, const uint8_t * packet_data, int packet_bytes )
{
    (void) client;
    (void) context;
    (void) packet_data;
    (void) packet_bytes;

    // todo
    next_printf( NEXT_LOG_LEVEL_INFO, "client received %d byte packet", packet_bytes );
}

int main()
{
    signal( SIGINT, interrupt_handler ); signal( SIGTERM, interrupt_handler );

    next_config_t config;
    next_default_config( &config );

    if ( next_init( NULL, &config ) != NEXT_OK )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "could not initialize network next" );
        return 1;        
    }

    const char * connect_token = "connect token";

    next_client_t * client = next_client_create( NULL, connect_token, packet_received_callback );
    if ( !client )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "could not create client" );
        return 1;
    }

    next_printf( NEXT_LOG_LEVEL_INFO, "connecting" );

    bool previous_connected = false;

    uint8_t packet_data[100];
    memset( packet_data, 0, sizeof(packet_data) );

    while ( !quit )
    {
        next_client_send_packet( client, packet_data, (int) sizeof(packet_data) );

        next_client_update( client );

        if ( !previous_connected )
        {
            if ( next_client_state( client ) == NEXT_CLIENT_CONNECTED )
            {
                next_printf( NEXT_LOG_LEVEL_INFO, "connected" );

                previous_connected = true;
            }
        }
    }

    next_printf( NEXT_LOG_LEVEL_INFO, "disconnecting" );

    next_client_disconnect( client );

    while ( next_client_state( client ) != NEXT_CLIENT_DISCONNECTED )
    {
        next_client_update( client );
    }

    next_printf( NEXT_LOG_LEVEL_INFO, "disconnected" );

    next_client_destroy( client );

    next_term();

    return 0;
}
