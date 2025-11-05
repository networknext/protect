/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
*/

#include "next_hydrogen.h"
#include "next_base64.h"

#include <stdio.h>

int main()
{
    hydro_sign_keypair keypair;
    hydro_sign_keygen( &keypair );

    char public_key_string[256];
    char private_key_string[256];
    next_base64_encode_data( keypair.pk, hydro_sign_PUBLICKEYBYTES, public_key_string, sizeof(public_key_string) );
    next_base64_encode_data( keypair.sk, hydro_sign_SECRETKEYBYTES, private_key_string, sizeof(private_key_string) );

    printf( "\nbuyer public key base64 = %s\n\n", public_key_string );
    printf( "buyer private key base64 = %s\n\n", private_key_string );

    printf( "const uint8_t buyer_public_key[] = { " );
    for ( int i = 0; i < (int) hydro_sign_PUBLICKEYBYTES; i++ )
    {
        printf( "0x%02x", keypair.pk[i] );
        if ( i != hydro_sign_PUBLICKEYBYTES - 1 )
        {
            printf( ", " );
        }
        else
        {
            printf( " };\n\n" );
        }
    }

    printf( "const uint8_t buyer_private_key[] = { " );
    for ( int i = 0; i < (int) hydro_sign_SECRETKEYBYTES; i++ )
    {
        printf( "0x%02x", keypair.sk[i] );
        if ( i != hydro_sign_SECRETKEYBYTES - 1 )
        {
            printf( ", " );
        }
        else
        {
            printf( " };\n\n" );
        }
    }

    return 0;
}
