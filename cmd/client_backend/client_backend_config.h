/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
*/

#ifndef CLIENT_BACKEND_CONFIG_H
#define CLIENT_BACKEND_CONFIG_H

#include "client_backend.h"
#include "client_backend_shared.h"

struct config_t
{
    uint32_t public_address;
    uint16_t port;
    uint8_t client_backend_private_key[SIGN_PRIVATE_KEY_BYTES];
};

bool read_config( struct config_t * config );

#endif // #ifndef CLIENT_BACKEND_CONFIG_H
