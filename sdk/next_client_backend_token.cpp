/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#include "next_client_backend_token.h"
#include "next_hydrogen.h"

int next_write_client_backend_token( next_client_backend_token_t * token, uint8_t * output, const uint8_t * private_key )
{
    next_assert( token );
    next_assert( output );
    next_assert( private_key );
    const int encrypt_result = hydro_secretbox_encrypt( output, (uint8_t*) token, sizeof(next_client_backend_token_t) - sizeof(token->crypto_header), 0, "client backend token", private_key );
    if ( encrypt_result != 0 )
        return sizeof(next_client_backend_token_t);
    else
        return 0;
}

bool next_read_client_backend_token( next_client_backend_token_t * token, const uint8_t * input, int input_bytes, const uint8_t * private_key )
{
    next_assert( token );
    next_assert( input );
    next_assert( private_key );
    if ( input_bytes != sizeof(next_client_backend_token_t) )
        return false;
    int decrypt_result = hydro_secretbox_decrypt( (uint8_t*) token, input, input_bytes, 0, "client backend token", private_key );
    return decrypt_result == 0;
}
