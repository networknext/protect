/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#ifndef CLIENT_BACKEND_BASE64_H
#define CLIENT_BACKEND_BASE64_H

int client_backend_base64_decode_data( const char * input, uint8_t * output, size_t output_size );

int client_backend_base64_decode_string( const char * input, char * output, size_t output_size );

#endif // #ifndef CLIENT_BACKEND_BASE64_H
