/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#include "next_tests.h"
#include "next.h"

#if NEXT_DEVELOPMENT

#include "next_platform.h"
#include "next_address.h"
#include "next_base64.h"
#include "next_hash.h"
#include "next_replay_protection.h"
#include "next_route_token.h"
#include "next_continue_token.h"
#include "next_header.h"
#include "next_packet_filter.h"
#include "next_packet_loss_tracker.h"
#include "next_out_of_order_tracker.h"
#include "next_jitter_tracker.h"
#include "next_value_tracker.h"
#include "next_connect_token.h"
#include "next_client_backend_token.h"
#include "next_hydrogen.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void next_check_handler( const char * condition,
                                const char * function,
                                const char * file,
                                int line )
{
    printf( "check failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
    fflush( stdout );
#ifndef NDEBUG
    #if defined( __GNUC__ )
        __builtin_trap();
    #elif defined( _MSC_VER )
        __debugbreak();
    #endif
#endif
    exit( 1 );
}

#define next_check( condition )                                                                                 \
do                                                                                                              \
{                                                                                                               \
    if ( !(condition) )                                                                                         \
    {                                                                                                           \
        next_check_handler( #condition, (const char*) __FUNCTION__, (const char*) __FILE__, __LINE__ );         \
    }                                                                                                           \
} while(0)

void test_time()
{
    double start = next_platform_time();
    next_platform_sleep( 0.1 );
    double finish = next_platform_time();
    next_check( finish > start );
}

void test_endian()
{
    uint32_t value = 0x11223344;
    char bytes[4];
    memcpy( bytes, &value, 4 );

#if NEXT_LITTLE_ENDIAN

    next_check( bytes[0] == 0x44 );
    next_check( bytes[1] == 0x33 );
    next_check( bytes[2] == 0x22 );
    next_check( bytes[3] == 0x11 );

#else // #if NEXT_LITTLE_ENDIAN

    next_check( bytes[3] == 0x44 );
    next_check( bytes[2] == 0x33 );
    next_check( bytes[1] == 0x22 );
    next_check( bytes[0] == 0x11 );

#endif // #if NEXT_LITTLE_ENDIAN
}

void test_base64()
{
    const char * input = "a test string. let's see if it works properly";
    char encoded[1024];
    char decoded[1024];
    next_check( next_base64_encode_string( input, encoded, sizeof(encoded) ) > 0 );
    next_check( next_base64_decode_string( encoded, decoded, sizeof(decoded) ) > 0 );
    next_check( strcmp( decoded, input ) == 0 );
    next_check( next_base64_decode_string( encoded, decoded, 10 ) == 0 );
}

void test_hash()
{
    uint64_t hash = next_datacenter_id( "local" );
    next_check( hash == 0x249f1fb6f3a680e8ULL );
}

void test_copy_string()
{
    // copy valid string
    {
        char buffer[256];
        size_t result = next_copy_string( buffer, "hello", sizeof(buffer) );
        next_check( result == 5 );
        next_check( strncmp( buffer, "hello", sizeof(buffer) ) == 0 );
    }

    // copy empty string
    {
        char buffer[256];
        size_t result = next_copy_string( buffer, "", sizeof(buffer) );
        next_check( result == 0 );
        next_check( strncmp( buffer, "", sizeof(buffer) ) == 0 );
    }

    // truncated string
    {
        char buffer[4];
        size_t result = next_copy_string( buffer, "hello my baby, hello my darling", sizeof(buffer) );
        next_check( result == 3 );
        next_check( strncmp( buffer, "hel", sizeof(buffer) ) == 0 );
    }
}

void test_address()
{
    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "[" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "[]" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "[]:" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, ":" ) == NEXT_ERROR );
#if !defined(WINVER) || WINVER > 0x502 // windows xp sucks
        next_check( next_address_parse( &address, "1" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "12" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "123" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "1234" ) == NEXT_ERROR );
#endif
        next_check( next_address_parse( &address, "1234.0.12313.0000" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "1234.0.12313.0000.0.0.0.0.0" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131" ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "." ) == NEXT_ERROR );
        next_check( next_address_parse( &address, ".." ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "..." ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "...." ) == NEXT_ERROR );
        next_check( next_address_parse( &address, "....." ) == NEXT_ERROR );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "107.77.207.77" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV4 );
        next_check( address.port == 0 );
        next_check( address.data.ipv4[0] == 107 );
        next_check( address.data.ipv4[1] == 77 );
        next_check( address.data.ipv4[2] == 207 );
        next_check( address.data.ipv4[3] == 77 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "127.0.0.1" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV4 );
        next_check( address.port == 0 );
        next_check( address.data.ipv4[0] == 127 );
        next_check( address.data.ipv4[1] == 0 );
        next_check( address.data.ipv4[2] == 0 );
        next_check( address.data.ipv4[3] == 1 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "107.77.207.77:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV4 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv4[0] == 107 );
        next_check( address.data.ipv4[1] == 77 );
        next_check( address.data.ipv4[2] == 207 );
        next_check( address.data.ipv4[3] == 77 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "127.0.0.1:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV4 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv4[0] == 127 );
        next_check( address.data.ipv4[1] == 0 );
        next_check( address.data.ipv4[2] == 0 );
        next_check( address.data.ipv4[3] == 1 );
    }

#if NEXT_PLATFORM_HAS_IPV6
    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "fe80::202:b3ff:fe1e:8329" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 0 );
        next_check( address.data.ipv6[0] == 0xfe80 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0202 );
        next_check( address.data.ipv6[5] == 0xb3ff );
        next_check( address.data.ipv6[6] == 0xfe1e );
        next_check( address.data.ipv6[7] == 0x8329 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "::" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 0 );
        next_check( address.data.ipv6[0] == 0x0000 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0000 );
        next_check( address.data.ipv6[5] == 0x0000 );
        next_check( address.data.ipv6[6] == 0x0000 );
        next_check( address.data.ipv6[7] == 0x0000 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "::1" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 0 );
        next_check( address.data.ipv6[0] == 0x0000 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0000 );
        next_check( address.data.ipv6[5] == 0x0000 );
        next_check( address.data.ipv6[6] == 0x0000 );
        next_check( address.data.ipv6[7] == 0x0001 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "[fe80::202:b3ff:fe1e:8329]:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv6[0] == 0xfe80 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0202 );
        next_check( address.data.ipv6[5] == 0xb3ff );
        next_check( address.data.ipv6[6] == 0xfe1e );
        next_check( address.data.ipv6[7] == 0x8329 );
        next_check( !next_address_is_ipv4_in_ipv6( &address ) );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "[::]:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv6[0] == 0x0000 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0000 );
        next_check( address.data.ipv6[5] == 0x0000 );
        next_check( address.data.ipv6[6] == 0x0000 );
        next_check( address.data.ipv6[7] == 0x0000 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "[::1]:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv6[0] == 0x0000 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0000 );
        next_check( address.data.ipv6[5] == 0x0000 );
        next_check( address.data.ipv6[6] == 0x0000 );
        next_check( address.data.ipv6[7] == 0x0001 );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "[::ffff:127.0.0.1]:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv6[0] == 0x0000 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0000 );
        next_check( address.data.ipv6[5] == 0xFFFF );
        next_check( address.data.ipv6[6] == 0x7F00 );
        next_check( address.data.ipv6[7] == 0x0001 );
        next_check( next_address_is_ipv4_in_ipv6( &address ) );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "[::ffff:0.0.0.0]:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv6[0] == 0x0000 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0000 );
        next_check( address.data.ipv6[5] == 0xFFFF );
        next_check( address.data.ipv6[6] == 0x0000 );
        next_check( address.data.ipv6[7] == 0x0000 );
        next_check( next_address_is_ipv4_in_ipv6( &address ) );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "[::ffff:1.2.3.4]:40000" ) == NEXT_OK );
        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv6[0] == 0x0000 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0000 );
        next_check( address.data.ipv6[5] == 0xFFFF );
        next_check( address.data.ipv6[6] == 0x0102 );
        next_check( address.data.ipv6[7] == 0x0304 );
        next_check( next_address_is_ipv4_in_ipv6( &address ) );
    }

    {
        struct next_address_t address;
        next_check( next_address_parse( &address, "[::ffff:1.2.3.4]:40000" ) == NEXT_OK );
        next_check( next_address_is_ipv4_in_ipv6( &address ) );

        next_address_convert_ipv6_to_ipv4( &address );
        next_check( address.type == NEXT_ADDRESS_IPV4 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv4[0] == 1 );
        next_check( address.data.ipv4[1] == 2 );
        next_check( address.data.ipv4[2] == 3 );
        next_check( address.data.ipv4[3] == 4 );

        next_address_convert_ipv4_to_ipv6( &address );

        next_check( address.type == NEXT_ADDRESS_IPV6 );
        next_check( address.port == 40000 );
        next_check( address.data.ipv6[0] == 0x0000 );
        next_check( address.data.ipv6[1] == 0x0000 );
        next_check( address.data.ipv6[2] == 0x0000 );
        next_check( address.data.ipv6[3] == 0x0000 );
        next_check( address.data.ipv6[4] == 0x0000 );
        next_check( address.data.ipv6[5] == 0xFFFF );
        next_check( address.data.ipv6[6] == 0x0102 );
        next_check( address.data.ipv6[7] == 0x0304 );
        next_check( next_address_is_ipv4_in_ipv6( &address ) );
    }
#endif // #if NEXT_PLATFORM_HAS_IPV6
}

void test_replay_protection()
{
    next_replay_protection_t replay_protection;

    int i;
    for ( i = 0; i < 2; ++i )
    {
        next_replay_protection_reset( &replay_protection );

        next_check( replay_protection.most_recent_sequence == 0 );

        // the first time we receive packets, they should not be already received

        #define MAX_SEQUENCE ( NEXT_REPLAY_PROTECTION_BUFFER_SIZE * 4 )

        uint64_t sequence;
        for ( sequence = 0; sequence < MAX_SEQUENCE; ++sequence )
        {
            next_check( next_replay_protection_already_received( &replay_protection, sequence ) == 0 );
            next_replay_protection_advance_sequence( &replay_protection, sequence );
        }

        // old packets outside buffer should be considered already received

        next_check( next_replay_protection_already_received( &replay_protection, 0 ) == 1 );

        // packets received a second time should be detected as already received

        for ( sequence = MAX_SEQUENCE - 10; sequence < MAX_SEQUENCE; ++sequence )
        {
            next_check( next_replay_protection_already_received( &replay_protection, sequence ) == 1 );
        }

        // jumping ahead to a much higher sequence should be considered not already received

        next_check( next_replay_protection_already_received( &replay_protection, MAX_SEQUENCE + NEXT_REPLAY_PROTECTION_BUFFER_SIZE ) == 0 );

        // old packets should be considered already received

        for ( sequence = 0; sequence < MAX_SEQUENCE; ++sequence )
        {
            next_check( next_replay_protection_already_received( &replay_protection, sequence ) == 1 );
        }
    }
}

static bool equal_within_tolerance( float a, float b, float tolerance = 0.001f )
{
    return fabs(double(a)-double(b)) <= tolerance;
}

void test_random_bytes()
{
    const int BufferSize = 999;
    uint8_t buffer[BufferSize];
    next_random_bytes( buffer, BufferSize );
    for ( int i = 0; i < 100; ++i )
    {
        uint8_t next_buffer[BufferSize];
        next_random_bytes( next_buffer, BufferSize );
        next_check( memcmp( buffer, next_buffer, BufferSize ) != 0 );
        memcpy( buffer, next_buffer, BufferSize );
    }
}

void test_random_float()
{
    for ( int i = 0; i < 1000; ++i )
    {
        float value = next_random_float();
        next_check( value >= 0.0f );
        next_check( value <= 1.0f );
    }
}

void test_platform_socket()
{
    // non-blocking socket (ipv4)
    {
        next_address_t bind_address;
        next_address_t local_address;
        next_address_parse( &bind_address, "0.0.0.0" );
        next_address_parse( &local_address, "127.0.0.1" );
        next_platform_socket_t * socket = next_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0, 64*1024, 64*1024 );
        local_address.port = bind_address.port;
        next_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        next_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        next_address_t from;
        while ( next_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) ) )
        {
            next_check( next_address_equal( &from, &local_address ) );
        }
        next_platform_socket_destroy( socket );
    }

    // blocking socket with timeout (ipv4)
    {
        next_address_t bind_address;
        next_address_t local_address;
        next_address_parse( &bind_address, "0.0.0.0" );
        next_address_parse( &local_address, "127.0.0.1" );
        next_platform_socket_t * socket = next_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_BLOCKING, 0.01f, 64*1024, 64*1024 );
        local_address.port = bind_address.port;
        next_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        next_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        next_address_t from;
        while ( next_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) ) )
        {
            next_check( next_address_equal( &from, &local_address ) );
        }
        next_platform_socket_destroy( socket );
    }

    // blocking socket with no timeout (ipv4)
    {
        next_address_t bind_address;
        next_address_t local_address;
        next_address_parse( &bind_address, "0.0.0.0" );
        next_address_parse( &local_address, "127.0.0.1" );
        next_platform_socket_t * socket = next_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_BLOCKING, -1.0f, 64*1024, 64*1024 );
        local_address.port = bind_address.port;
        next_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        next_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        next_address_t from;
        next_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) );
        next_check( next_address_equal( &from, &local_address ) );
        next_platform_socket_destroy( socket );
    }

#if NEXT_PLATFORM_HAS_IPV6

    // non-blocking socket (ipv6)
    {
        next_address_t bind_address;
        next_address_t local_address;
        next_address_parse( &bind_address, "[::]" );
        next_address_parse( &local_address, "[::1]" );
        next_platform_socket_t * socket = next_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0, 64*1024, 64*1024 );
        local_address.port = bind_address.port;
        next_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        next_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        next_address_t from;
        while ( next_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) ) )
        {
            next_check( next_address_equal( &from, &local_address ) );
        }
        next_platform_socket_destroy( socket );
    }

    // blocking socket with timeout (ipv6)
    {
        next_address_t bind_address;
        next_address_t local_address;
        next_address_parse( &bind_address, "[::]" );
        next_address_parse( &local_address, "[::1]" );
        next_platform_socket_t * socket = next_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_BLOCKING, 0.01f, 64*1024, 64*1024 );
        local_address.port = bind_address.port;
        next_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        next_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        next_address_t from;
        while ( next_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) ) )
        {
            next_check( next_address_equal( &from, &local_address ) );
        }
        next_platform_socket_destroy( socket );
    }

    // blocking socket with no timeout (ipv6)
    {
        next_address_t bind_address;
        next_address_t local_address;
        next_address_parse( &bind_address, "[::]" );
        next_address_parse( &local_address, "[::1]" );
        next_platform_socket_t * socket = next_platform_socket_create( NULL, &bind_address, NEXT_PLATFORM_SOCKET_BLOCKING, -1.0f, 64*1024, 64*1024 );
        local_address.port = bind_address.port;
        next_check( socket );
        uint8_t packet[256];
        memset( packet, 0, sizeof(packet) );
        next_platform_socket_send_packet( socket, &local_address, packet, sizeof(packet) );
        next_address_t from;
        next_platform_socket_receive_packet( socket, &from, packet, sizeof(packet) );
        next_check( next_address_equal( &from, &local_address ) );
        next_platform_socket_destroy( socket );
    }

#endif // #if NEXT_PLATFORM_HAS_IPV6
}

static bool threads_work = false;

static void test_thread_function(void*)
{
    threads_work = true;
}

void test_platform_thread()
{
    next_platform_thread_t * thread = next_platform_thread_create( NULL, test_thread_function, NULL );
    next_check( thread );
    next_platform_thread_join( thread );
    next_platform_thread_destroy( thread );
    next_check( threads_work );
}

void test_platform_mutex()
{
    next_platform_mutex_t mutex;
    int result = next_platform_mutex_create( &mutex );
    next_check( result == NEXT_OK );
    next_platform_mutex_acquire( &mutex );
    next_platform_mutex_release( &mutex );
    {
        next_platform_mutex_guard( &mutex );
        // ...
    }
    next_platform_mutex_destroy( &mutex );
}

void test_value_tracker()
{
    // initial values without any samples added should be 0/0/0
    {
        next_value_tracker_t tracker;
        next_value_tracker_reset( &tracker );
        float min_value, max_value, avg_value;
        next_value_tracker_calculate( &tracker, &min_value, &max_value, &avg_value );
        next_check( min_value == 0.0f );
        next_check( max_value == 0.0f );
        next_check( avg_value == 0.0f );
    }

    // add just one sample and min/max/avg should be set to that sample value
    {
        next_value_tracker_t tracker;
        next_value_tracker_reset( &tracker );
        next_value_tracker_add_sample( &tracker, 1.0f );
        float min_value, max_value, avg_value;
        next_value_tracker_calculate( &tracker, &min_value, &max_value, &avg_value );
        next_check( min_value == 1.0f );
        next_check( max_value == 1.0f );
        next_check( avg_value == 1.0f );
        next_value_tracker_calculate( &tracker, &min_value, &max_value, &avg_value );
        next_check( min_value == 0.0f );
        next_check( max_value == 0.0f );
        next_check( avg_value == 0.0f );
    }

    // add a bunch of samples and we should see min/max/avg
    {
        next_value_tracker_t tracker;
        next_value_tracker_reset( &tracker );
        for ( int i = 0; i < 100; i++ )
        {
            next_value_tracker_add_sample( &tracker, float(i%10) );
        }
        float min_value, max_value, avg_value;
        next_value_tracker_calculate( &tracker, &min_value, &max_value, &avg_value );
        next_check( min_value == 0.0f );
        next_check( max_value == 9.0f );
        next_check( avg_value == 4.5f );
        next_value_tracker_calculate( &tracker, &min_value, &max_value, &avg_value );
        next_check( min_value == 0.0f );
        next_check( max_value == 0.0f );
        next_check( avg_value == 0.0f );
    }

    // add more samples than history size and it should still work
    {
        next_value_tracker_t tracker;
        next_value_tracker_reset( &tracker );
        for ( int i = 0; i < NEXT_VALUE_TRACKER_HISTORY * 2; i++ )
        {
            next_value_tracker_add_sample( &tracker, float(i%10) );
        }
        float min_value, max_value, avg_value;
        next_value_tracker_calculate( &tracker, &min_value, &max_value, &avg_value );
        next_check( min_value == 0.0f );
        next_check( max_value == 9.0f );
        next_check( fabs( 4.5f - avg_value ) < 0.1f );
        next_value_tracker_calculate( &tracker, &min_value, &max_value, &avg_value );
        next_check( min_value == 0.0f );
        next_check( max_value == 0.0f );
        next_check( avg_value == 0.0f );
    }
}

void test_packet_filter()
{
    uint8_t output[NEXT_MAX_PACKET_BYTES];
    memset( output, 0, sizeof(output) );
    output[0] = 1;

    for ( int i = 0; i < 10000; ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];

        next_random_bytes( magic, 8 );
        next_random_bytes( from_address, 4 );
        next_random_bytes( to_address, 4 );

        int packet_length = 18 + ( i % ( sizeof(output) - 18 ) );
        
        next_generate_pittle( output + 1, from_address, to_address, packet_length );

        next_generate_chonkle( output + 3, magic, from_address, to_address, packet_length );

        next_check( next_basic_packet_filter( output, packet_length ) );

#if NEXT_ADVANCED_PACKET_FILTER
        next_check( next_advanced_packet_filter( output, magic, from_address, to_address, packet_length ) );
#endif // #if NEXT_ADVANCED_PACKET_FILTER
    }
}

void test_basic_packet_filter()
{
    uint8_t output[256];
    memset( output, 0, sizeof(output) );
    uint64_t pass = 0;
    uint64_t iterations = 100;
    srand( 100 );
    for ( int i = 0; i < int(iterations); ++i )
    {
        for ( int j = 0; j < int(sizeof(output)); ++j )
        {
            output[j] = uint8_t( rand() % 256 );
        }
        if ( next_basic_packet_filter( output, rand() % sizeof(output) ) )
        {
            pass++;
        }
    }
    next_check( pass == 0 );
}

#if NEXT_ADVANCED_PACKET_FILTER

void test_advanced_packet_filter()
{
    uint8_t output[256];
    memset( output, 0, sizeof(output) );
    uint64_t pass = 0;
    uint64_t iterations = 100;
    srand( 100 );
    for ( int i = 0; i < int(iterations); ++i )
    {
        uint8_t magic[8];
        uint8_t from_address[4];
        uint8_t to_address[4];
        next_crypto_random_bytes( magic, 8 );
        next_crypto_random_bytes( from_address, 4 );
        next_crypto_random_bytes( to_address, 4 );
        int packet_length = 18 + ( i % ( sizeof(output) - 18 ) );
        for ( int j = 0; j < int(sizeof(output)); ++j )
        {
            output[j] = uint8_t( rand() % 256 );
        }
        if ( next_advanced_packet_filter( output, magic, from_address, to_address, packet_length ) )
        {
            pass++;
        }
    }
    next_check( pass == 0 );
}

#endif // #if NEXT_ADVANCED_PACKET_FILTER

void test_address_data_ipv4()
{
    next_address_t address;
    next_address_parse( &address, "127.0.0.1:50000" );
    next_check( address.type == NEXT_ADDRESS_IPV4 );
    uint8_t address_data[4];
    next_address_data( &address, address_data );
    next_check( address_data[0] == 127 );
    next_check( address_data[1] == 0 );
    next_check( address_data[2] == 0 );
    next_check( address_data[3] == 1 );
}

void test_anonymize_address_ipv4()
{
    next_address_t address;
    next_address_parse( &address, "1.2.3.4:5" );

    next_check( address.type == NEXT_ADDRESS_IPV4 );
    next_check( address.data.ipv4[0] == 1 );
    next_check( address.data.ipv4[1] == 2 );
    next_check( address.data.ipv4[2] == 3 );
    next_check( address.data.ipv4[3] == 4 );
    next_check( address.port == 5 );

    next_address_anonymize( &address );

    next_check( address.type == NEXT_ADDRESS_IPV4 );
    next_check( address.data.ipv4[0] == 1 );
    next_check( address.data.ipv4[1] == 2 );
    next_check( address.data.ipv4[2] == 3 );
    next_check( address.data.ipv4[3] == 0 );
    next_check( address.port == 0 );
}

#if NEXT_PLATFORM_HAS_IPV6

void test_anonymize_address_ipv6()
{
    next_address_t address;
    next_address_parse( &address, "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:40000" );

    next_check( address.type == NEXT_ADDRESS_IPV6 );
    next_check( address.data.ipv6[0] == 0x2001 );
    next_check( address.data.ipv6[1] == 0x0db8 );
    next_check( address.data.ipv6[2] == 0x85a3 );
    next_check( address.data.ipv6[3] == 0x0000 );
    next_check( address.data.ipv6[4] == 0x0000 );
    next_check( address.data.ipv6[5] == 0x8a2e );
    next_check( address.data.ipv6[6] == 0x0370 );
    next_check( address.data.ipv6[7] == 0x7334 );
    next_check( address.port == 40000 );

    next_address_anonymize( &address );

    next_check( address.type == NEXT_ADDRESS_IPV6 );
    next_check( address.data.ipv6[0] == 0x2001 );
    next_check( address.data.ipv6[1] == 0x0db8 );
    next_check( address.data.ipv6[2] == 0x85a3 );
    next_check( address.data.ipv6[3] == 0x0000 );
    next_check( address.data.ipv6[4] == 0x0000 );
    next_check( address.data.ipv6[5] == 0x0000 );
    next_check( address.data.ipv6[6] == 0x0000 );
    next_check( address.data.ipv6[7] == 0x0000 );
    next_check( address.port == 0 );
}

#endif // #if NEXT_PLATFORM_HAS_IPV6

void test_packet_loss_tracker()
{
    next_packet_loss_tracker_t tracker;
    next_packet_loss_tracker_reset( &tracker );

    next_check( next_packet_loss_tracker_update( &tracker ) == 0 );

    uint64_t sequence = 0;

    for ( int i = 0; i < NEXT_PACKET_LOSS_TRACKER_SAFETY; ++i )
    {
        next_packet_loss_tracker_packet_received( &tracker, sequence );
        sequence++;
    }

    next_check( next_packet_loss_tracker_update( &tracker ) == 0 );

    for ( int i = 0; i < 200; ++i )
    {
        next_packet_loss_tracker_packet_received( &tracker, sequence );
        sequence++;
    }

    next_check( next_packet_loss_tracker_update( &tracker ) == 0 );

    for ( int i = 0; i < 200; ++i )
    {
        if ( sequence & 1 )
        {
            next_packet_loss_tracker_packet_received( &tracker, sequence );
        }
        sequence++;
    }

    next_check( next_packet_loss_tracker_update( &tracker ) == ( 200 - NEXT_PACKET_LOSS_TRACKER_SAFETY ) / 2 );

    next_check( next_packet_loss_tracker_update( &tracker ) == 0 );

    next_packet_loss_tracker_reset( &tracker );

    sequence = 0;

    next_packet_loss_tracker_packet_received( &tracker, 200 + NEXT_PACKET_LOSS_TRACKER_SAFETY - 1 );

    next_check( next_packet_loss_tracker_update( &tracker ) == 200 );

    next_packet_loss_tracker_packet_received( &tracker, 1000 );

    next_check( next_packet_loss_tracker_update( &tracker ) > 500 );

    next_packet_loss_tracker_packet_received( &tracker, 0xFFFFFFFFFFFFFFFULL );

    next_check( next_packet_loss_tracker_update( &tracker ) == 0 );
}

void test_out_of_order_tracker()
{
    next_out_of_order_tracker_t tracker;
    next_out_of_order_tracker_reset( &tracker );

    next_check( tracker.num_out_of_order_packets == 0 );

    uint64_t sequence = 0;

    for ( int i = 0; i < 1000; ++i )
    {
        next_out_of_order_tracker_packet_received( &tracker, sequence );
        sequence++;
    }

    next_check( tracker.num_out_of_order_packets == 0 );

    sequence = 500;

    for ( int i = 0; i < 500; ++i )
    {
        next_out_of_order_tracker_packet_received( &tracker, sequence );
        sequence++;
    }

    next_check( tracker.num_out_of_order_packets == 499 );

    next_out_of_order_tracker_reset( &tracker );

    next_check( tracker.last_packet_processed == 0 );
    next_check( tracker.num_out_of_order_packets == 0 );

    for ( int i = 0; i < 1000; ++i )
    {
        uint64_t mod_sequence = ( sequence / 2 ) * 2;
        if ( sequence % 2 )
            mod_sequence -= 1;
        next_out_of_order_tracker_packet_received( &tracker, mod_sequence );
        sequence++;
    }

    next_check( tracker.num_out_of_order_packets == 500 );
}

void test_jitter_tracker()
{
    next_jitter_tracker_t tracker;
    next_jitter_tracker_reset( &tracker );

    next_check( tracker.jitter == 0.0 );

    uint64_t sequence = 0;

    double t = 0.0;
    double dt = 1.0 / 60.0;

    for ( int i = 0; i < 1000; ++i )
    {
        next_jitter_tracker_packet_received( &tracker, sequence, t );
        sequence++;
        t += dt;
    }

    next_check( tracker.jitter < 0.000001 );

    for ( int i = 0; i < 1000; ++i )
    {
        t = i * dt;
        if ( (i%3) == 0 )
        {
            t += 2;
        }
        if ( (i%5) == 0 )
        {
            t += 5;
        }
        if ( (i%6) == 0 )
        {
            t -= 10;
        }
        next_jitter_tracker_packet_received( &tracker, sequence, t );
        sequence++;
    }

    next_check( tracker.jitter > 1.0 );

    next_jitter_tracker_reset( &tracker );

    next_check( tracker.jitter == 0.0 );

    for ( int i = 0; i < 1000; ++i )
    {
        t = i * dt;
        if ( (i%3) == 0 )
        {
            t += 0.01f;
        }
        if ( (i%5) == 0 )
        {
            t += 0.05;
        }
        if ( (i%6) == 0 )
        {
            t -= 0.1f;
        }
        next_jitter_tracker_packet_received( &tracker, sequence, t );
        sequence++;
    }

    next_check( tracker.jitter > 0.05 );
    next_check( tracker.jitter < 0.1 );

    for ( int i = 0; i < 10000; ++i )
    {
        t = i * dt;
        next_jitter_tracker_packet_received( &tracker, sequence, t );
        sequence++;
    }

    next_check( tracker.jitter >= 0.0 );
    next_check( tracker.jitter <= 0.000001 );
}

extern void * next_default_malloc_function( void * context, size_t bytes );

extern void next_default_free_function( void * context, void * p );

static void context_check_free( void * context, void * p )
{
    (void) p;
    next_check( context );
    next_check( *((int *)context) == 23 );
    next_default_free_function( context, p );;
}

void test_connect_token()
{
    hydro_sign_keypair keypair;
    hydro_sign_keygen( &keypair );

    next_connect_token_t input_token;
    memset( &input_token, 0, sizeof(input_token) );
    input_token.expire_timestamp = next_random_uint64();
    input_token.buyer_id = next_random_uint64();
    input_token.server_id = next_random_uint64();
    input_token.session_id = next_random_uint64();
    input_token.user_hash = next_random_uint64();
    input_token.client_public_address = next_random_uint32();
    for ( int i = 0; i < NEXT_MAX_CONNECT_TOKEN_BACKENDS; i++ )
    {
        input_token.backend_addresses[i] = next_random_uint32();
        input_token.backend_ports[i] = (uint16_t) next_random_uint32();
    }        
    input_token.pings_per_second = 10;
    input_token.max_connect_seconds = 30;
    input_token.backend_token_refresh_seconds = 30;

    char connect_token_string[NEXT_MAX_CONNECT_TOKEN_BYTES];
    memset( connect_token_string, 0, sizeof(connect_token_string) );
    {
        next_check( next_write_connect_token( &input_token, connect_token_string, keypair.sk ) );
    }

    next_connect_token_t output_token;
    next_check( next_read_connect_token( &output_token, connect_token_string, keypair.pk ) );

    next_check( memcmp( &input_token, &output_token, sizeof(next_connect_token_t) - sizeof(input_token.signature) ) == 0 );
}

void test_client_backend_token()
{
    uint8_t key[hydro_secretbox_KEYBYTES];
    hydro_secretbox_keygen( key );

    uint8_t buffer[1024];

    next_client_backend_token_t input_token;
    memset( &input_token, 0, sizeof(input_token) );
    input_token.expire_timestamp = next_random_uint64();
    input_token.buyer_id = next_random_uint64();
    input_token.server_id = next_random_uint64();
    input_token.session_id = next_random_uint64();
    input_token.user_hash = next_random_uint64();

    next_check( next_write_client_backend_token( &input_token, buffer, key ) == sizeof(next_client_backend_token_t) );

    next_client_backend_token_t output_token;
    memset( &output_token, 0, sizeof(output_token) );

    next_check( next_read_client_backend_token( &output_token, buffer, sizeof(next_client_backend_token_t), key ) );

    next_check( memcmp( &input_token, &output_token, sizeof(next_client_backend_token_t) ) == 0 );
}

#define RUN_TEST( test_function )                                           \
    do                                                                      \
    {                                                                       \
        next_printf( NEXT_LOG_LEVEL_NONE, "    " #test_function );          \
        fflush( stdout );                                                   \
        test_function();                                                    \
    }                                                                       \
    while (0)

void next_run_tests()
{
    // while ( true )
    {
        RUN_TEST( test_time );
        RUN_TEST( test_endian );
        RUN_TEST( test_base64 );
        RUN_TEST( test_hash );
        RUN_TEST( test_copy_string );
        RUN_TEST( test_address );
        RUN_TEST( test_random_bytes );
        RUN_TEST( test_random_float );
        RUN_TEST( test_platform_socket );
        RUN_TEST( test_platform_thread );
        RUN_TEST( test_platform_mutex );
        RUN_TEST( test_value_tracker );
        RUN_TEST( test_packet_filter );
        RUN_TEST( test_basic_packet_filter );
#if NEXT_ADVANCED_PACKET_FILTER
        RUN_TEST( test_advanced_packet_filter );
#endif // #if NEXT_ADVANCED_PACKET_FILTER
        RUN_TEST( test_replay_protection );
        RUN_TEST( test_address_data_ipv4 );
        RUN_TEST( test_anonymize_address_ipv4 );
#if NEXT_PLATFORM_HAS_IPV6
        RUN_TEST( test_anonymize_address_ipv6 );
#endif // #if NEXT_PLATFORM_HAS_IPV6
        RUN_TEST( test_packet_loss_tracker );
        RUN_TEST( test_out_of_order_tracker );
        RUN_TEST( test_jitter_tracker );
        RUN_TEST( test_connect_token );
        RUN_TEST( test_client_backend_token );
    }
}

#else // #if NEXT_DEVELOPMENT

#include <stdio.h>

void next_run_tests()
{
    printf( "\n[tests are not included in this build]\n\n" );
}

#endif // #if NEXT_DEVELOPMENT
