/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#ifndef CLIENT_BACKEND_CONFIG_H
#define CLIENT_BACKEND_CONFIG_H

#include "client_backend.h"

struct config_t
{
    uint32_t public_address;
    uint16_t port;

    /*
    char relay_name[256];
    uint32_t relay_public_address;
    uint32_t relay_internal_address;
    uint8_t relay_public_key[RELAY_PUBLIC_KEY_BYTES];
    uint8_t relay_private_key[RELAY_PRIVATE_KEY_BYTES];
    uint8_t relay_backend_public_key[RELAY_BACKEND_PUBLIC_KEY_BYTES];
    uint8_t relay_secret_key[RELAY_SECRET_KEY_BYTES];
    uint8_t gateway_ethernet_address[RELAY_ETHERNET_ADDRESS_BYTES];
    uint8_t use_gateway_ethernet_address;
    char relay_backend_url[256];
    */
};

int read_config( struct config_t * config );

#endif // #ifndef CLIENT_BACKEND_CONFIG_H
