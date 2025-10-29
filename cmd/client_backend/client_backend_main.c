/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#include "client_backend_main.h"
#include "client_backend_config.h"
#include "client_backend_shared.h"
#include "client_backend_bpf.h"

#include "platform/platform.h"
#include "shared/shared_encoding.h"

#include <curl/curl.h>
#include <sodium.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>

#ifdef __linux__
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#endif // #ifdef __linux__

bool main_init( struct main_t * main, struct config_t * config, struct bpf_t * bpf )
{
    main->start_time = time( NULL );
    main->port = config->port;
    main->public_address = config->public_address;

    /*
    main->relay_backend_url = config->relay_backend_url;
    main->relay_internal_address = config->relay_internal_address;
    memcpy( main->relay_public_key, config->relay_public_key, sizeof(config->relay_public_key) );
    memcpy( main->relay_private_key, config->relay_private_key, sizeof(config->relay_private_key) );
    memcpy( main->relay_backend_public_key, config->relay_backend_public_key, sizeof(config->relay_backend_public_key) );
#if COMPILE_WITH_BPF
    main->stats_fd = bpf->stats_fd;
    main->state_fd = bpf->state_fd;
    main->session_map_fd = bpf->session_map_fd;
    main->whitelist_map_fd = bpf->whitelist_map_fd;
#endif // #if COMPILE_WITH_BPF
    */

    // set config for xdp program

    struct config client_backend_config;
    memset( &client_backend_config, 0, sizeof(struct config) );
    client_backend_config.port = htons( config->port );
    client_backend_config.public_address = htonl( config->public_address );

#ifdef __linux__
    __u32 key = 0;
    int err = bpf_map_update_elem( bpf->config_fd, &key, &config, BPF_ANY );
    if ( err != 0 )
    {
        printf( "\nerror: failed to set config: %s\n\n", strerror(errno) );
        return RELAY_ERROR;
    }
#endif // #ifdef __linux__

    return true;
}

int main_update( struct main_t * main );

extern bool quit;
extern bool clean_shutdown;

int main_run( struct main_t * main )
{
    printf( "Starting main thread\n" );

    fflush( stdout );

    while ( !quit )
    {
        /*
        if ( main_update( main ) == RELAY_OK )
        {
            update_attempts = 0;
        }
        else
        {
            if ( update_attempts++ >= RELAY_MAX_UPDATE_ATTEMPTS )
            {
                printf( "error: could not update relay %d times in a row. shutting down :(", RELAY_MAX_UPDATE_ATTEMPTS );
                fflush( stdout );
                aborted = true;
                quit = 1;
                break;
            }
        }
        */

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

void main_shutdown( struct main_t * main )
{
#if 0

    if ( main->curl )
    {
        curl_easy_cleanup( main->curl );
    }

    if ( main->update_response_memory )
    {
        free( main->update_response_memory );
    }

    if ( main->stats_queue )
    {
        relay_queue_destroy( main->stats_queue );
    }

    if ( main->stats_mutex )
    {
        relay_platform_mutex_destroy( main->stats_mutex );
    }

    if ( main->control_queue )
    {
        relay_queue_destroy( main->control_queue );
    }

    if ( main->control_mutex )
    {
        relay_platform_mutex_destroy( main->control_mutex );
    }

#endif // #if 0

    memset( main, 0, sizeof(struct main_t) );
}

// -----------------------------------------------------------------------------------------------------------------------------
