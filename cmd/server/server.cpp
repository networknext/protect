/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 1.0
*/

#include "next.h"
#include "next_server.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>

static volatile int quit;

void interrupt_handler( int signal )
{
    (void) signal; quit = 1;
}

void packet_received_callback( next_server_t * server, void * context, int client_index, const uint8_t * packet_data, int packet_bytes )
{
    (void) server;
    (void) context;
    (void) client_index;
    (void) packet_data;
    (void) packet_bytes;
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

    next_server_t * server = next_server_create( NULL, "0.0.0.0:40000", "127.0.0.1:40000", packet_received_callback );
    if ( !server )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "could not create server" );
        return 1;
    }

    uint8_t packet_data[1024];
    memset( packet_data, 0, sizeof(packet_data) );

    while ( !quit )
    {
        // todo: rework to send to all connected clients, also max clients?
        // next_server_send_packet( server, 0, packet_data, (int) sizeof(packet_data) );

        next_server_update( server );
    }

    next_printf( NEXT_LOG_LEVEL_INFO, "stopping" );

    next_server_stop( server );

    while ( next_server_state( server ) != NEXT_SERVER_STOPPED )
    {
        next_server_update( server );
    }

    next_printf( NEXT_LOG_LEVEL_INFO, "stopped" );

    next_server_destroy( server );

    next_term();

    return 0;
}
