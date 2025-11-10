/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
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

int main()
{
    signal( SIGINT, interrupt_handler ); signal( SIGTERM, interrupt_handler );

    if ( next_init() != NEXT_OK )
    {
        next_error( "could not initialize network next" );
        return 1;        
    }

    next_server_t * server = next_server_create( NULL, "0.0.0.0:40000", "127.0.0.1:40000" );
    if ( !server )
    {
        next_error( "could not create server" );
        return 1;
    }

    while ( !quit )
    {
        next_server_update( server );

        for ( int i = 0; i < NEXT_MAX_CLIENTS; i++ )
        {
            if ( next_server_client_connected( server, i ) )
            {
                uint64_t sequence;
                uint8_t * packet_data = next_server_start_packet( server, i, &sequence );
                if ( packet_data )
                {
                    next_server_finish_packet( server, packet_data, 100 );
                }
            }
        }

        next_server_send_packets( server );
    }

    next_info( "stopping" );

    next_server_stop( server );

    while ( next_server_state( server ) != NEXT_SERVER_STOPPED )
    {
        next_server_update( server );
        next_server_send_packets( server );
    }

    next_info( "stopped" );

    next_server_destroy( server );

    next_term();

    return 0;
}
