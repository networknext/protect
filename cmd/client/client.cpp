/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
*/

#include "next.h"
#include "next_client_socket.h"
#include "next_base64.h"
#include "next_connect_token.h"
#include "next_hydrogen.h"
#include "next_platform.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define CLIENT_DIRECT 1

const uint8_t buyer_public_key[] = { 0x9d, 0x59, 0x40, 0xa4, 0xe2, 0x4a, 0xa3, 0x0a, 0xf2, 0x30, 0xb6, 0x1b, 0x49, 0x7d, 0x60, 0xe8, 0x6d, 0xf9, 0x03, 0x28, 0x5c, 0x96, 0x83, 0x06, 0x89, 0xf5, 0xdd, 0x62, 0x8a, 0x25, 0x95, 0x16 };

const uint8_t buyer_private_key[] = { 0x7b, 0xd7, 0x97, 0x88, 0xcb, 0x67, 0x03, 0xac, 0xdc, 0x75, 0x6d, 0x7a, 0xcc, 0x03, 0x88, 0x67, 0xd4, 0xc6, 0xe8, 0xb5, 0x99, 0x42, 0x77, 0xd9, 0x68, 0xb3, 0xf6, 0xbd, 0xa5, 0xd3, 0x55, 0xfa, 0x9d, 0x59, 0x40, 0xa4, 0xe2, 0x4a, 0xa3, 0x0a, 0xf2, 0x30, 0xb6, 0x1b, 0x49, 0x7d, 0x60, 0xe8, 0x6d, 0xf9, 0x03, 0x28, 0x5c, 0x96, 0x83, 0x06, 0x89, 0xf5, 0xdd, 0x62, 0x8a, 0x25, 0x95, 0x16 };

static volatile int quit;

void interrupt_handler( int signal )
{
    (void) signal; quit = 1;
}

static inline int generate_packet( uint8_t * packet_data, int max_size )
{
    const int packet_bytes = 1 + rand() % ( max_size - 1 );
    const int start = packet_bytes % 256;
    for ( int i = 0; i < packet_bytes; i++ )
    {
        packet_data[i] = (uint8_t) ( start + i ) % 256;
    }
    return packet_bytes;
}

static inline bool verify_packet( uint8_t * packet_data, int packet_bytes )
{
    const int start = packet_bytes % 256;
    for ( int i = 0; i < packet_bytes; i++ )
    {
        if ( packet_data[i] != (uint8_t) ( ( start + i ) % 256 ) )
            return false;
    }
    return true;
}

int main()
{
    signal( SIGINT, interrupt_handler ); signal( SIGTERM, interrupt_handler );

    if ( !next_init() )
    {
        next_error( "could not initialize network next" );
        return 1;        
    }

#if CLIENT_DIRECT

    const char * connect = "69.67.149.151:40000"; //"127.0.0.1:40000";

#else // #if CLIENT_DIRECT

    char connect[NEXT_MAX_CONNECT_TOKEN_BYTES];
    memset( connect, 0, sizeof(connect) );
    {
        next_connect_token_t token;
        memset( &token, 0, sizeof(token) );
        token.expire_timestamp = next_random_uint64();
        token.buyer_id = 0x12345678;
        token.server_id = next_random_uint64();
        token.session_id = next_random_uint64();
        token.user_hash = next_random_uint64();
        token.client_public_address = 0xa89d4f2d;               // 45.79.157.168  (home ip address)
        token.backend_addresses[0] = 0xf3fdfa2d;                // 45.250.253.243 (latitude.newyork)
        token.backend_ports[0] = next_platform_htons( 40000 );
        token.pings_per_second = 10;
        token.pongs_before_select = 10;
        token.max_connect_seconds = 30;
        token.backend_token_refresh_seconds = 30;
        if ( !next_write_connect_token( &token, connect, buyer_private_key ) )
        {
            next_error( "failed to write connect token" );
            return 1;        
        }
    }

#endif // #if CLIENT_DIRECT

    next_client_socket_t * client_socket = next_client_socket_create( NULL, connect );
    if ( !client_socket )
    {
        next_error( "could not create client socket" );
        return 1;
    }

    next_info( "connecting..." );

    bool previous_connected = false;

    int count = 0;

    while ( !quit )
    {
        if ( next_client_socket_state( client_socket ) <= NEXT_CLIENT_SOCKET_DISCONNECTED )
            break;

        next_client_socket_update( client_socket );

        while ( true )
        {
            uint8_t packet_data[NEXT_MTU];
            int packet_bytes = next_client_socket_receive_packet( client_socket, packet_data );
            if ( packet_bytes == 0 )
                break;

            next_info( "client received %d byte packet from server", packet_bytes );

            if ( !verify_packet( packet_data, packet_bytes ) )
            {
                next_error( "packet did not verify" );
                exit( 1 );
            }
        }

        uint8_t packet_data[NEXT_MTU];
        const int packet_bytes = generate_packet( packet_data, NEXT_MTU );
        next_client_socket_send_packet( client_socket, packet_data, packet_bytes );

        if ( !previous_connected )
        {
            if ( next_client_socket_state( client_socket ) == NEXT_CLIENT_SOCKET_CONNECTED )
            {
                next_info( "connected" );

                previous_connected = true;
            }
        }

        next_platform_sleep( 1.0 / 100.0 );
    }

    next_info( "disconnecting" );

    next_client_socket_disconnect( client_socket );

    while ( next_client_socket_state( client_socket ) > NEXT_CLIENT_SOCKET_DISCONNECTED )
    {
        next_client_socket_update( client_socket );
    }

    next_info( "disconnected" );

    next_client_socket_destroy( client_socket );

    next_term();

    return 0;
}
