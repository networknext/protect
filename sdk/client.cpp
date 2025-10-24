/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 1.0
*/

#include "next.h"
#include "next_client.h"
#include <stdio.h>
#include <string.h>

void packet_received_callback( next_client_t * client, void * context, const uint8_t * packet_data, int packet_bytes )
{
    (void) client;
    (void) context;
    (void) packet_data;
    (void) packet_bytes;
}

int main()
{
    printf( "hello\n" );
    next_client_t * client = next_client_create( NULL, 0, packet_received_callback );
    for ( int i = 0; i < 100; i++ )
    {
        next_client_update( client );
    }
    next_client_disconnect( client );
    while ( next_client_state( client ) != NEXT_CLIENT_DISCONNECTED )
    {
        next_client_update( client );
    }
    next_client_destroy( client );
    return 0;
}
