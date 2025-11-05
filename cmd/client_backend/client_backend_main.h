/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#ifndef CLIENT_BACKEND_MAIN_H
#define CLIENT_BACKEND_MAIN_H

#include "client_backend.h"

struct main_t
{
    // void * curl;

    uint64_t start_time;
    uint32_t public_address;
    uint16_t port;
    bool initialized;
    bool shutting_down;

    /*
    int stats_fd;
    int state_fd;
    int config_fd;
    int session_map_fd;
    int whitelist_map_fd;
    */
};

struct config_t;
struct bpf_t;

bool main_init( struct main_t * main, struct config_t * config, struct bpf_t * bpf );

int main_run( struct main_t * main );

void main_shutdown( struct main_t * main );

#endif // #ifndef CLIENT_BACKEND_MAIN_H
