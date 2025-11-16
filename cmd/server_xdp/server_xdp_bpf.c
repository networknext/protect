/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
*/

#include "client_backend_bpf.h"

#include <stdio.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <stdlib.h>

#ifdef __linux__
#include "client_backend_xdp_source.h"
#endif // #ifdef __linux__

bool bpf_init( struct bpf_t * bpf, uint32_t public_address )
{
#ifdef __linux__

    // we can only run xdp programs as root

    if ( geteuid() != 0 ) 
    {
        printf( "\nerror: this program must be run as root\n\n" );
        return true;
    }

    // find the network interface that matches the public address

    char network_interface_name[1024];
    memset( network_interface_name, 0, sizeof(network_interface_name) );
    {
        bool found = false;

        struct ifaddrs * addrs;
        if ( getifaddrs( &addrs ) != 0 )
        {
            printf( "\nerror: getifaddrs failed\n\n" );
            return false;
        }

        for ( struct ifaddrs * iap = addrs; iap != NULL; iap = iap->ifa_next ) 
        {
            if ( iap->ifa_addr && ( iap->ifa_flags & IFF_UP ) && iap->ifa_addr->sa_family == AF_INET )
            {
                struct sockaddr_in * sa = (struct sockaddr_in*) iap->ifa_addr;
                if ( ntohl( sa->sin_addr.s_addr ) == public_address )
                {
                    strncpy( network_interface_name, iap->ifa_name, sizeof(network_interface_name) );
                    printf( "found network interface: '%s'\n", network_interface_name );
                    bpf->interface_index = if_nametoindex( iap->ifa_name );
                    if ( !bpf->interface_index ) 
                    {
                        printf( "\nerror: if_nametoindex failed\n\n" );
                        return false;
                    }
                    found = true;
                    break;
                }
            }
        }

        freeifaddrs( addrs );

        if ( !found )
        {
            printf( "\nerror: could not find any network interface matching public address" );
            return false;
        }
    }

    // are we in AWS?

    bool running_in_aws = false;
    {
        printf( "Checking if we are running in AWS...\n" );
        char command_line[2048];
        strncpy( command_line, "curl -s \"http://169.254.169.254/latest/meta-data\" --max-time 2 -s 2>/dev/null", sizeof(command_line) );
        printf( "command line: '%s'\n", command_line );
        FILE * file = popen( command_line, "r" );
        if ( file )
        {
            char buffer[1024];
            while ( fgets( buffer, sizeof(buffer), file ) != NULL )
            {
                if ( strstr( buffer, "ami-id" ) != NULL )
                {
                    printf( "Detected that we are running in AWS\n" );
                    running_in_aws = true;
                    break;
                }
            }
            pclose( file );
        }
        if ( !running_in_aws )
        {
            printf( "We are not running in AWS\n" );
        }
        fflush( stdout );
    }

    // we need to set an MTU of 1500 in AWS, otherwise we can't attach the XDP program

    if ( running_in_aws )
    {
        printf( "Setting MTU 1500\n" );
        char command[2048];
        snprintf( command, sizeof(command), "ifconfig %s mtu 1500 up", (const char*) &network_interface_name[0] );
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL )
        {
            if ( strlen( buffer ) > 0 )
            {
                printf( "%s", buffer );
            }
        }
        pclose( file );
        fflush( stdout );
    }

    // we need to only use half the network queues available on the NIC on AWS

    if ( running_in_aws )
    {
        printf( "AWS workaround for NIC queues\n" );
        fflush( stdout );

        // first we need to find how many combined queues we have

        int max_queues = 2;
        {
            char command[2048];
            snprintf( command, sizeof(command), "ethtool -l %s | grep -m 1 Combined |  perl -ne '/Combined:\\s*(\\d+)/ and print \"$1\\n\";'", (const char*) &network_interface_name[0] );
            FILE * file = popen( command, "r" );
            char buffer[1024];
            while ( fgets( buffer, sizeof(buffer), file ) != NULL )
            {
                if ( strlen( buffer ) > 0 )
                {
                    int result = atoi( buffer );
                    if ( result > 0 )
                    {
                        max_queues = result;
                        printf( "Maximum NIC combined queues is %d\n", max_queues );
                    }
                    break;
                }
            }
            pclose( file );
            fflush( stdout );
        }

        // now reduce to use only half max queues

        int num_queues = max_queues / 2;

        printf( "Setting NIC combined queues to %d\n", num_queues );

        char command[2048];
        snprintf( command, sizeof(command), "ethtool -L %s combined %d", (const char*) &network_interface_name[0], num_queues );
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
        pclose( file );

        fflush( stdout );
    }

    // be extra safe and let's make sure no xdp programs are running on this interface before we start
    {
        char command[2048];
        snprintf( command, sizeof(command), "xdp-loader unload %s --all", network_interface_name );
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
        pclose( file );
    }

    // delete all bpf maps we use so stale data doesn't stick around
    {
        {
            const char * command = "rm -f /sys/fs/bpf/client_backend_config_map";
            FILE * file = popen( command, "r" );
            char buffer[1024];
            while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
            pclose( file );
        }

        {
            const char * command = "rm -f /sys/fs/bpf/client_backend_state_map";
            FILE * file = popen( command, "r" );
            char buffer[1024];
            while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
            pclose( file );
        }
    }

    // write out source tar.gz for client_backend_xdp.o
    {
        FILE * file = fopen( "client_backend_xdp_source.tar.gz", "wb" );
        if ( !file )
        {
            printf( "\nerror: could not open client_backend_xdp_source.tar.gz for writing" );
            return false;
        }

        fwrite( ___cmd_client_backend_client_backend_xdp_source_tar_gz, sizeof(___cmd_client_backend_client_backend_xdp_source_tar_gz), 1, file );

        fclose( file );
    }

    // unzip source build client_backend_xdp.o from source with make
    {
        const char * command = "rm -f Makefile && rm -f *.c && rm -f *.h && rm -f *.o && rm -f Makefile && tar -zxf client_backend_xdp_source.tar.gz && make client_backend_xdp.o";
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
        pclose( file );
    }

    // clean up after ourselves
    {
        const char * command = "rm -f Makefile && rm -f *.c && rm -f *.h && rm -f *.tar.gz";
        FILE * file = popen( command, "r" );
        char buffer[1024];
        while ( fgets( buffer, sizeof(buffer), file ) != NULL ) {}
        pclose( file );
    }

    // load the client_backend_xdp program and attach it to the network interface

    printf( "loading client_backend_xdp...\n" );

    fflush( stdout );

    bpf->program = xdp_program__open_file( "client_backend_xdp.o", "client_backend_xdp", NULL );
    if ( libxdp_get_error( bpf->program ) ) 
    {
        printf( "\nerror: could not load client_backend_xdp program\n\n");
        return false;
    }

    printf( "client_backend_xdp loaded successfully.\n" );

    fflush( stdout );

    printf( "attaching client_backend_xdp to network interface\n" );

    fflush( stdout );

    int ret = xdp_program__attach( bpf->program, bpf->interface_index, XDP_MODE_NATIVE, 0 );
    if ( ret == 0 )
    {
        bpf->attached_native = true;
    } 
    else
    {
        printf( "falling back to skb mode...\n" );
        ret = xdp_program__attach( bpf->program, bpf->interface_index, XDP_MODE_SKB, 0 );
        if ( ret == 0 )
        {
            bpf->attached_skb = true;
        }
        else
        {
            printf( "\nerror: failed to attach client_backend_xdp program to interface\n\n" );
            return false;
        }
    }

    // get file descriptors for maps so we can communicate with the client_backend_xdp program running in kernel space

    bpf->config_fd = bpf_obj_get( "/sys/fs/bpf/client_backend_config_map" );
    if ( bpf->config_fd <= 0 )
    {
        printf( "\nerror: could not get client backend config map: %s\n\n", strerror(errno) );
        return false;
    }

    bpf->state_fd = bpf_obj_get( "/sys/fs/bpf/client_backend_state_map" );
    if ( bpf->state_fd <= 0 )
    {
        printf( "\nerror: could not get client backend state map: %s\n\n", strerror(errno) );
        return false;
    }

    bpf->buyer_fd = bpf_obj_get( "/sys/fs/bpf/client_backend_buyer_map" );
    if ( bpf->buyer_fd <= 0 )
    {
        printf( "\nerror: could not get client backend buyer map: %s\n\n", strerror(errno) );
        return false;
    }

#endif // #ifdef __linux__

    return true;
}

void bpf_shutdown( struct bpf_t * bpf )
{
    assert( bpf );

#ifdef __linux__

    if ( bpf->program != NULL )
    {
        if ( bpf->attached_native )
        {
            xdp_program__detach( bpf->program, bpf->interface_index, XDP_MODE_NATIVE, 0 );
        }
        if ( bpf->attached_skb )
        {
            xdp_program__detach( bpf->program, bpf->interface_index, XDP_MODE_SKB, 0 );
        }
        xdp_program__close( bpf->program );
    }

#endif // #ifdef __linux__
}
