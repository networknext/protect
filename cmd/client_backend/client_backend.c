/*
    Network Next Client Backend

    Requires Ubuntu 24.04 LTS
*/

#include "client_backend.h"
#include "client_backend_platform.h"
#include "client_backend_main.h"
#include "client_backend_bpf.h"
#include "client_backend_config.h"

#include <memory.h>
#include <stdio.h>
#include <sodium.h>
#include <signal.h>

static struct config_t config;
static struct bpf_t bpf;
static struct main_t main_data;

volatile bool quit;
volatile bool clean_shutdown = false;

void interrupt_handler( int signal )
{
    (void) signal; quit = true;
}

void clean_shutdown_handler( int signal )
{
    (void) signal;
    clean_shutdown = true;
    quit = true;
}

static void cleanup()
{
#if RELAY_DEBUG
    debug_shutdown( &debug );
#else // #if RELAY_DEBUG
    ping_shutdown( &ping );
    main_shutdown( &main_data );
    bpf_shutdown( &bpf );
#endif // #if RELAY_DEBUG
    fflush( stdout );
}

int main( int argc, char *argv[] )
{
    client_backend_platform_init();

    printf( "Network Next Client Backend\n" );

    fflush( stdout );

    signal( SIGINT,  interrupt_handler );
    signal( SIGTERM, clean_shutdown_handler );
    signal( SIGHUP,  clean_shutdown_handler );

    printf( "Reading config\n" );

    fflush( stdout );

    if ( read_config( &config ) != RELAY_OK )
    {
        cleanup();
        return 1;
    }

    fflush( stdout );

    printf( "Initializing BPF\n" );

    fflush( stdout );

    if ( bpf_init( &bpf, config.relay_public_address, config.relay_internal_address ) != RELAY_OK )
    {
        cleanup();
        return 1;
    }

    fflush( stdout );

    printf( "Starting backend\n" );

    fflush( stdout );

    if ( main_init( &main_data, &config, &bpf ) != RELAY_OK )
    {
        cleanup();
        return 1;
    }

    int result = main_run( &main_data );

    cleanup();

    return result;
}
