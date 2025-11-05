/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#include "next_connect_token.h"
#include "next_base64.h"
#include "next_hydrogen.h"
#include <memory.h>

// todo
#include <stdio.h>

bool next_write_connect_token( next_connect_token_t * token, char * output, const uint8_t * private_key )
{
    next_assert( token );
    next_assert( output );
    next_assert( private_key );

    char context[hydro_sign_CONTEXTBYTES];
    memset( context, 0, sizeof(context) );
    int result = hydro_sign_create(&token->signature[0], (uint8_t*) token, sizeof(next_connect_token_t) - sizeof(token->signature), context, private_key );
    if ( result != 0 )
    {
        output[0] = '\0';
        return false;
    }

    int bytes = next_base64_encode_data( (uint8_t*) token, sizeof(next_connect_token_t), output, NEXT_MAX_CONNECT_TOKEN_BYTES );
    if ( bytes <= 0 )
    {
        output[0] = '\0';
        return false;
    }

    return true;
}

bool next_read_connect_token( next_connect_token_t * token, const char * input, const uint8_t * public_key )
{
    next_assert( token );
    next_assert( input );
    next_assert( public_key );

    if ( next_base64_decode_data( input, (uint8_t*) token, sizeof(next_connect_token_t) ) != sizeof(next_connect_token_t) )
    {
        return false;
    }

    char context[hydro_sign_CONTEXTBYTES];
    memset( context, 0, sizeof(context) );
    int result = hydro_sign_verify( &token->signature[0], (uint8_t*) token, sizeof(next_connect_token_t) - sizeof(token->signature), context, public_key );
    if ( result != 0 )
    {
        return false;
    }
    
    return true;
}
