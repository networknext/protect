/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 1.0
*/

#include "next.h"
#include "next_client.h"
#include "next_base64.h"
#include "next_connect_token.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sodium/sodium.h"

static uint8_t buyer_public_key[] = { 0x0b, 0x05, 0x25, 0xaf, 0xdb, 0xc4, 0x63, 0xc1, 0x96, 0x55, 0x50, 0x4b, 0xad, 0x32, 0x7f, 0x16, 0xe1, 0x17, 0x7d, 0x8c, 0x72, 0xe1, 0xd5, 0x01, 0xb7, 0x2b, 0xdd, 0x42, 0x19, 0x1a, 0xec, 0x55 };

static uint8_t buyer_private_key[] = { 0x7a, 0xdc, 0xf8, 0x9e, 0x37, 0xcd, 0xd8, 0xb8, 0x1c, 0x90, 0x71, 0xfa, 0x82, 0x99, 0xc4, 0xed, 0x45, 0xa8, 0x35, 0xa4, 0xf9, 0x13, 0x06, 0x74, 0xd0, 0x53, 0xee, 0x06, 0xbf, 0x92, 0xec, 0xa3, 0x0b, 0x05, 0x25, 0xaf, 0xdb, 0xc4, 0x63, 0xc1, 0x96, 0x55, 0x50, 0x4b, 0xad, 0x32, 0x7f, 0x16, 0xe1, 0x17, 0x7d, 0x8c, 0x72, 0xe1, 0xd5, 0x01, 0xb7, 0x2b, 0xdd, 0x42, 0x19, 0x1a, 0xec, 0x55 };

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

    char connect_token_string[NEXT_MAX_CONNECT_TOKEN_BYTES];
    memset( connect_token_string, 0, sizeof(connect_token_string) );
    {
        next_connect_token_t token;
        memset( &token, 0, sizeof(token) );
        if ( !next_write_connect_token( &token, connect_token_string, buyer_private_key ) )
        {
            next_printf( NEXT_LOG_LEVEL_ERROR, "failed to write connect token" );
            return 1;        
        }
    }

    next_connect_token_t token;
    if ( !next_read_connect_token( &token, connect_token_string, buyer_public_key ) )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "failed to read connect token" );
        return 1;        
    }

    next_client_t * client = next_client_create( NULL, connect_token_string, packet_received_callback );
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



    // todo: generate buyer keypair
    /*
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];

    crypto_sign_keypair( public_key, private_key );

    char public_key_string[256];
    char private_key_string[256];
    next_base64_encode_data( public_key, crypto_sign_PUBLICKEYBYTES, public_key_string, sizeof(public_key_string) );
    next_base64_encode_data( private_key, crypto_sign_SECRETKEYBYTES, private_key_string, sizeof(private_key_string) );

    printf( "buyer public key base64 = %s\n", public_key_string );
    printf( "buyer private key base64= %s\n", private_key_string );

    printf( "const uint8_t buyer_public_key[] = { " );
    for ( int i = 0; i < (int) crypto_sign_PUBLICKEYBYTES; i++ )
    {
        printf( "0x%02x", public_key[i] );
        if ( i != crypto_sign_PUBLICKEYBYTES - 1 )
        {
            printf( ", " );
        }
        else
        {
            printf( " };\n" );
        }
    }

    printf( "const uint8_t buyer_private_key[] = { " );
    for ( int i = 0; i < (int) crypto_sign_SECRETKEYBYTES; i++ )
    {
        printf( "0x%02x", private_key[i] );
        if ( i != crypto_sign_SECRETKEYBYTES - 1 )
        {
            printf( ", " );
        }
        else
        {
            printf( " };\n" );
        }
    }
    */
