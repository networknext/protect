/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
*/

#include "platform/platform.h"
#include "shared/shared_encoding.h"

#include "client_backend_main.h"
#include "client_backend_config.h"
#include "client_backend_shared.h"
#include "client_backend_bpf.h"

#include <curl/curl.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>

#ifdef __linux__
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#endif // #ifdef __linux__

bool main_init( struct main_t * main, struct config_t * config, struct bpf_t * bpf )
{
    main->start_time = time( NULL );
    main->port = config->port;
    main->public_address = config->public_address;

    struct client_backend_config xdp_config;
    memset( &xdp_config, 0, sizeof(xdp_config) );
    xdp_config.port = htons( config->port );
    xdp_config.public_address = htonl( config->public_address );
    memcpy( xdp_config.client_backend_private_key, config->client_backend_private_key, SECRETBOX_PRIVATE_KEY_BYTES );

#ifdef __linux__

    main->config_fd = bpf->config_fd;
    main->state_fd = bpf->state_fd;
    main->buyer_fd = bpf->buyer_fd;

    __u32 key = 0;
    int err = bpf_map_update_elem( main->config_fd, &key, &xdp_config, BPF_ANY );
    if ( err != 0 )
    {
        printf( "\nerror: failed to set config: %s\n\n", strerror(errno) );
        return false;
    }

    struct client_backend_state state;
    state.current_timestamp = time(NULL);
    err = bpf_map_update_elem( main->state_fd, &key, &state, BPF_ANY );
    if ( err != 0 )
    {
        printf( "\nerror: failed to set state: %s\n\n", strerror(errno) );
        return false;
    }

    uint64_t buyer_id = 0x12345678;
    struct client_backend_buyer buyer = { { 0x9d, 0x59, 0x40, 0xa4, 0xe2, 0x4a, 0xa3, 0x0a, 0xf2, 0x30, 0xb6, 0x1b, 0x49, 0x7d, 0x60, 0xe8, 0x6d, 0xf9, 0x03, 0x28, 0x5c, 0x96, 0x83, 0x06, 0x89, 0xf5, 0xdd, 0x62, 0x8a, 0x25, 0x95, 0x16 } };
    err = bpf_map_update_elem( main->buyer_fd, &buyer_id, &buyer, BPF_ANY );
    if ( err != 0 )
    {
        printf( "\nerror: failed to add buyer: %s\n\n", strerror(errno) );
        return false;
    }

#endif // #ifdef __linux__

    return true;
}

bool main_update( struct main_t * main );

extern bool quit;
extern bool clean_shutdown;

int main_run( struct main_t * main )
{
    fflush( stdout );

    while ( !quit )
    {
        #ifdef __linux__
        int key = 0;
        struct client_backend_state state;
        state.current_timestamp = time(NULL);
        int err = bpf_map_update_elem( main->state_fd, &key, &state, BPF_ANY );
        if ( err != 0 )
        {
            printf( "\nwarning: failed to set state: %s\n\n", strerror(errno) );
        }
        #endif // #ifdef __linux__

        platform_sleep( 1.0 );
    }

    if ( clean_shutdown )
    {
        printf( "\nClean shutdown...\n" );

        fflush( stdout );

        main->shutting_down = true;

        // ...

        printf( "Clean shutdown completed\n" );

        fflush( stdout );        
    }
    else
    {
        printf( "\nHard shutdown!\n" );

        fflush( stdout );        
    }

    return true;
}

bool main_update( struct main_t * main )
{
    // ...
    return true;
}

void main_shutdown( struct main_t * main )
{
#if 0

    if ( main->curl )
    {
        curl_easy_cleanup( main->curl );
    }

#endif // #if 0

    memset( main, 0, sizeof(struct main_t) );
}

// -----------------------------------------------------------------------------------------------------------------------------
