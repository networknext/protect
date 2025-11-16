/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
*/

#pragma once

#include "client_backend_constants.h"

#ifdef __linux__
#include <linux/types.h>
#else // #ifdef __linux__
#define __u64 uint64_t
#define __u32 uint32_t
#define __u16 uint16_t
#define __u8 uint8_t
#endif // #ifdef __linux__

#define SIGN_PUBLIC_KEY_BYTES               32
#define SIGN_PRIVATE_KEY_BYTES              64

#define SECRETBOX_PRIVATE_KEY_BYTES         32

struct client_backend_config
{
    __u32 public_address;                                               // big endian
    __u16 port;                                                         // big endian
    __u8 client_backend_private_key[SECRETBOX_PRIVATE_KEY_BYTES];
};

struct client_backend_state
{
    __u64 current_timestamp;
};

struct client_backend_buyer
{
    __u8 public_key[SIGN_PUBLIC_KEY_BYTES];
};
