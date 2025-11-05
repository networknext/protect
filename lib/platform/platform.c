/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#include "platform.h"

#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>

// -----------------------------------------------------------------------------------------------------------------------------------------------

static double time_start;

int platform_init()
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC_RAW, &ts );
    time_start = ts.tv_sec + ( (double) ( ts.tv_nsec ) ) / 1000000000.0;
    return PLATFORM_OK;
}

double platform_time()
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC_RAW, &ts );
    double current = ts.tv_sec + ( (double) ( ts.tv_nsec ) ) / 1000000000.0;
    return current - time_start;
}

void platform_sleep( double time )
{
    usleep( (int) ( time * 1000000 ) );
}

// -----------------------------------------------------------------------------------------------------------------------------------------------

void platform_random_bytes( uint8_t * buffer, int bytes )
{
    // todo
    // randombytes_buf( buffer, bytes );
}

// -----------------------------------------------------------------------------------------------------------------------------------------------

bool platform_parse_address( char * address_string, uint32_t * address, uint16_t * port )
{
    assert( address_string );
    assert( address );
    assert( port );

    *port = 0;

    int address_string_length = (int) strlen( address_string );

    int base_index = address_string_length - 1;

    for ( int i = 0; i < 6; ++i )
    {
        const int index = base_index - i;
        if ( index < 0 )
            break;
        if ( address_string[index] == ':' )
        {
            *port = (uint16_t)( atoi( &address_string[index + 1] ) );
            address_string[index] = '\0';
        }
    }

    if ( inet_pton( AF_INET, address_string, address ) != 1 ) 
    {
        return false;
    }

    *address = htonl( *address );

    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------------

struct platform_socket_t * platform_socket_create( uint32_t address, uint16_t port, int socket_type, float timeout_seconds, int send_buffer_size, int receive_buffer_size )
{
    struct platform_socket_t * s = (struct platform_socket_t*) malloc( sizeof( struct platform_socket_t ) );

    assert( s );

    // create socket

    s->type = socket_type;

    s->handle = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );

    if ( s->handle < 0 )
    {
        printf( "error: failed to create socket\n" );
        return NULL;
    }

    // increase socket send and receive buffer sizes

    if ( setsockopt( s->handle, SOL_SOCKET, SO_SNDBUF, (char*)( &send_buffer_size ), sizeof( int ) ) != 0 )
    {
        printf( "failed to set socket send buffer size to %d\n", send_buffer_size );
        platform_socket_destroy( s );
        return NULL;
    }

    if ( setsockopt( s->handle, SOL_SOCKET, SO_RCVBUF, (char*)( &receive_buffer_size ), sizeof( int ) ) != 0 )
    {
        printf( "failed to set socket receive buffer size to %d\n", receive_buffer_size );
        platform_socket_destroy( s );
        return NULL;
    }

    // bind to port

    struct sockaddr_in socket_address;
    memset( &socket_address, 0, sizeof( socket_address ) );
    socket_address.sin_family = AF_INET;
    socket_address.sin_addr.s_addr = htonl( address );
    socket_address.sin_port = htons( port );
    if ( bind( s->handle, (struct sockaddr*) &socket_address, sizeof( socket_address ) ) < 0 )
    {
        printf( "failed to bind socket\n" );
        platform_socket_destroy( s );
        return NULL;
    }

    // set don't fragment bit

#ifdef __linux__

    int val = IP_PMTUDISC_DO;

    setsockopt( s->handle, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val) );

#endif // #ifdef __linux__

    // set non-blocking io and receive timeout

    if ( socket_type == PLATFORM_SOCKET_NON_BLOCKING )
    {
        if ( fcntl( s->handle, F_SETFL, O_NONBLOCK, 1 ) == -1 )
        {
            printf( "failed to set socket to non-blocking\n" );
            platform_socket_destroy( s );
            return NULL;
        }
    }
    else if ( timeout_seconds > 0.0f )
    {
        // set receive timeout
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = (int) ( timeout_seconds * 1000000.0f );
        if ( setsockopt( s->handle, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof( tv ) ) < 0 )
        {
            printf( "failed to set socket receive timeout\n" );
            platform_socket_destroy( s );
            return NULL;
        }
    }
    else
    {
        // socket is blocking with no timeout
    }

    return s;
}

void platform_socket_destroy( struct platform_socket_t * socket )
{
    assert( socket );
    if ( socket->handle != 0 )
    {
        close( socket->handle );
    }
    free( socket );
}

void platform_socket_send_packet( struct platform_socket_t * socket, uint32_t to_address, uint16_t to_port, const void * packet_data, int packet_bytes )
{
    assert( socket );
    assert( packet_data );
    assert( packet_bytes > 0 );

    struct sockaddr_in socket_address;
    memset( &socket_address, 0, sizeof( socket_address ) );
    socket_address.sin_family = AF_INET;
    socket_address.sin_addr.s_addr = htonl( to_address );
    socket_address.sin_port = htons( to_port );

    sendto( socket->handle, (const char*)( packet_data ), packet_bytes, 0, (struct sockaddr*)( &socket_address ), sizeof(struct sockaddr_in) );
}

int platform_socket_receive_packet( struct platform_socket_t * socket, uint32_t * from_address, uint16_t * from_port, void * packet_data, int max_packet_size )
{
    assert( socket );
    assert( from_address );
    assert( from_port );
    assert( packet_data );
    assert( max_packet_size > 0 );

    struct sockaddr_storage sockaddr_from;

    socklen_t from_length = sizeof( sockaddr_from );

    int result = (int) recvfrom( socket->handle, (char*) packet_data, max_packet_size, socket->type == PLATFORM_SOCKET_NON_BLOCKING ? MSG_DONTWAIT : 0, (struct sockaddr*) &sockaddr_from, &from_length );
    if ( result <= 0 )
        return 0;

    if ( sockaddr_from.ss_family == AF_INET )
    {
        struct sockaddr_in * addr_ipv4 = (struct sockaddr_in*) &sockaddr_from;
        *from_address = ntohl( addr_ipv4->sin_addr.s_addr );
        *from_port = ntohs( addr_ipv4->sin_port );
        return result;
    }

    return 0;
}

// -----------------------------------------------------------------------------------------------------------------------------------------------

struct platform_thread_t * platform_thread_create( platform_thread_func_t * thread_function, void * arg )
{
    struct platform_thread_t * thread = (struct platform_thread_t*) malloc( sizeof( struct platform_thread_t) );

    assert( thread );

    if ( pthread_create( &thread->handle, NULL, thread_function, arg ) != 0 )
    {
        free( thread );
        return NULL;
    }

    return thread;
}

void platform_thread_join( struct platform_thread_t * thread )
{
    assert( thread );
    pthread_join( thread->handle, NULL );
}

void platform_thread_destroy( struct platform_thread_t * thread )
{
    assert( thread );
    free( thread );
}

// -----------------------------------------------------------------------------------------------------------------------------------------------

struct platform_mutex_t * platform_mutex_create()
{
    struct platform_mutex_t * mutex = (struct platform_mutex_t*) malloc( sizeof(struct platform_mutex_t) ); assert( mutex );

    assert( mutex );

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype( &attr, 0 );
    int result = pthread_mutex_init( &mutex->handle, &attr );
    pthread_mutexattr_destroy( &attr );

    if ( result != 0 )
    {
        free( mutex );
        return NULL;
    }

    return mutex;
}

void platform_mutex_acquire( struct platform_mutex_t * mutex )
{
    assert( mutex );
    pthread_mutex_lock( &mutex->handle );
}

void platform_mutex_release( struct platform_mutex_t * mutex )
{
    assert( mutex );
    pthread_mutex_unlock( &mutex->handle );
}

void platform_mutex_destroy( struct platform_mutex_t * mutex )
{
    assert( mutex );
    pthread_mutex_destroy( &mutex->handle );
    free( mutex );
}

// -----------------------------------------------------------------------------------------------------------------------------------------------
