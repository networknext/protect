/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#include "next_client_backend_token.h"
#include "next_hydrogen.h"

int next_write_client_backend_token( next_client_backend_token_t * token, uint8_t * output, const uint8_t * private_key )
{
    /*
    int encrypt_result = hydro_secretbox_encrypt(
        ciphertext,
        (const void *)message,
        message_len,
        msg_id,
        context,
        key
    );
    */

    // todo
    return 0;
}

bool next_read_client_backend_token( next_client_backend_token_t * token, const uint8_t * input, int input_bytes, const uint8_t * public_key )
{
    /*
    uint8_t decrypted_message[message_len];
    int decrypt_result = hydro_secretbox_decrypt(
        decrypted_message,
        ciphertext,
        hydro_secretbox_HEADERBYTES + message_len,
        msg_id,
        context,
        key
    );
    */
    
    // todo
    return false;
}
