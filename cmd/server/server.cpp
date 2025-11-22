/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
*/

#include "next.h"
#include "next_server.h"
#include "next_platform.h"
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

    if ( !next_init() )
    {
        next_error( "could not initialize network next" );
        return 1;        
    }

    // next_server_t * server = next_server_create( NULL, "0.0.0.0:40000", "127.0.0.1:40000" );
    next_server_t * server = next_server_create( NULL, "0.0.0.0:40000", "192.168.1.4:40000" );      // hulk 10G
    if ( !server )
    {
        next_error( "could not create server" );
        return 1;
    }

    while ( !quit )
    {
        next_server_receive_packets( server );

        next_server_process_packets_t * packets = next_server_process_packets( server );

        for ( int i = 0; i < packets->num_packets; i++ )
        {
            next_info( "server received packet %" PRId64 " from client %d (%d bytes)", packets->sequence[i], packets->client_index[i], packets->packet_bytes[i] );
        }

        next_server_update( server );

        for ( int i = 0; i < NEXT_MAX_CLIENTS; i++ )
        {
            if ( next_server_client_connected( server, i ) )
            {
                for ( int j = 0; j < 100; j++ )
                {
                    uint64_t sequence;
                    uint8_t * packet_data = next_server_start_packet( server, i, &sequence );
                    if ( packet_data )
                    {
                        memset( packet_data, 0, 100 );
                        next_server_finish_packet( server, sequence, packet_data, 100 );
                        // next_info( "server sent packet %" PRId64 " to client %d", sequence, i );
                    }
                }
            }
        }

        next_server_send_packets( server );

        next_platform_sleep( 1.0 / 100.0 );       
    }

    next_info( "stopping" );

    next_server_stop( server );

    while ( next_server_state( server ) != NEXT_SERVER_STOPPED )
    {
        next_server_receive_packets( server );
        next_server_update( server );
        next_platform_sleep( 1.0 / 100.0 );
    }

    next_info( "stopped" );

    next_server_destroy( server );

    next_term();

    return 0;
}
