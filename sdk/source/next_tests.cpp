/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#include "next_tests.h"
#include "next.h"

#if NEXT_DEVELOPMENT

#include "next_platform.h"
#include "next_address.h"
#include "next_read_write.h"
#include "next_serialize.h"
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
#include "next_internal_config.h"
#include "next_value_tracker.h"
#include "next_connect_token.h"

#include "hydrogen.h"

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

using namespace next;

void test_bitpacker()
{
    const int BufferSize = 256;

    uint8_t buffer[BufferSize];

    BitWriter writer( buffer, BufferSize );

    next_check( writer.GetData() == buffer );
    next_check( writer.GetBitsWritten() == 0 );
    next_check( writer.GetBytesWritten() == 0 );
    next_check( writer.GetBitsAvailable() == BufferSize * 8 );

    writer.WriteBits( 0, 1 );
    writer.WriteBits( 1, 1 );
    writer.WriteBits( 10, 8 );
    writer.WriteBits( 255, 8 );
    writer.WriteBits( 1000, 10 );
    writer.WriteBits( 50000, 16 );
    writer.WriteBits( 9999999, 32 );
    writer.FlushBits();

    const int bitsWritten = 1 + 1 + 8 + 8 + 10 + 16 + 32;

    next_check( writer.GetBytesWritten() == 10 );
    next_check( writer.GetBitsWritten() == bitsWritten );
    next_check( writer.GetBitsAvailable() == BufferSize * 8 - bitsWritten );

    const int bytesWritten = writer.GetBytesWritten();

    next_check( bytesWritten == 10 );

    memset( buffer + bytesWritten, 0, size_t(BufferSize) - bytesWritten );

    BitReader reader( buffer, bytesWritten );

    next_check( reader.GetBitsRead() == 0 );
    next_check( reader.GetBitsRemaining() == bytesWritten * 8 );

    uint32_t a = reader.ReadBits( 1 );
    uint32_t b = reader.ReadBits( 1 );
    uint32_t c = reader.ReadBits( 8 );
    uint32_t d = reader.ReadBits( 8 );
    uint32_t e = reader.ReadBits( 10 );
    uint32_t f = reader.ReadBits( 16 );
    uint32_t g = reader.ReadBits( 32 );

    next_check( a == 0 );
    next_check( b == 1 );
    next_check( c == 10 );
    next_check( d == 255 );
    next_check( e == 1000 );
    next_check( f == 50000 );
    next_check( g == 9999999 );

    next_check( reader.GetBitsRead() == bitsWritten );
    next_check( reader.GetBitsRemaining() == bytesWritten * 8 - bitsWritten );
}

const int MaxItems = 11;

struct TestData
{
    TestData()
    {
        memset( this, 0, sizeof( TestData ) );
    }

    int a,b,c;
    uint32_t d : 8;
    uint32_t e : 8;
    uint32_t f : 8;
    bool g;
    int numItems;
    int items[MaxItems];
    float float_value;
    double double_value;
    uint64_t uint64_value;
    uint8_t bytes[17];
    char string[256];
    // next_address_t address_a, address_b, address_c;
};

struct TestContext
{
    int min;
    int max;
};

struct TestObject
{
    TestData data;

    void Init()
    {
        data.a = 1;
        data.b = -2;
        data.c = 150;
        data.d = 55;
        data.e = 255;
        data.f = 127;
        data.g = true;

        data.numItems = MaxItems / 2;
        for ( int i = 0; i < data.numItems; ++i )
            data.items[i] = i + 10;

        data.float_value = 3.1415926f;
        data.double_value = 1 / 3.0;
        data.uint64_value = 0x1234567898765432L;

        for ( int i = 0; i < (int) sizeof( data.bytes ); ++i )
            data.bytes[i] = ( i * 37 ) % 255;

        strcpy( data.string, "hello world!" );

        // todo
        /*
        memset( &data.address_a, 0, sizeof(next_address_t) );

        next_address_parse( &data.address_b, "127.0.0.1:50000" );

        next_address_parse( &data.address_c, "[::1]:50000" );
        */
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        serialize_int( stream, data.a, -1000, +1000 );
        serialize_int( stream, data.b, -1000, +1000 );

        serialize_int( stream, data.c, -100, 10000 );

        serialize_bits( stream, data.d, 6 );
        serialize_bits( stream, data.e, 8 );
        serialize_bits( stream, data.f, 7 );

        serialize_align( stream );

        serialize_bool( stream, data.g );

        serialize_int( stream, data.numItems, 0, MaxItems - 1 );
        for ( int i = 0; i < data.numItems; ++i )
            serialize_bits( stream, data.items[i], 8 );

        serialize_float( stream, data.float_value );

        serialize_double( stream, data.double_value );

        serialize_uint64( stream, data.uint64_value );

        serialize_bytes( stream, data.bytes, sizeof( data.bytes ) );

        serialize_string( stream, data.string, sizeof( data.string ) );

        // todo
        /*
        serialize_address( stream, data.address_a );
        serialize_address( stream, data.address_b );
        serialize_address( stream, data.address_c );
        */

        return true;
    }

    bool operator == ( const TestObject & other ) const
    {
        return memcmp( &data, &other.data, sizeof( TestData ) ) == 0;
    }

    bool operator != ( const TestObject & other ) const
    {
        return ! ( *this == other );
    }
};

void test_stream()
{
    const int BufferSize = 1024;

    uint8_t buffer[BufferSize];

    TestContext context;
    context.min = -10;
    context.max = +10;

    WriteStream writeStream( buffer, BufferSize );

    TestObject writeObject;
    writeObject.Init();
    writeObject.Serialize( writeStream );
    writeStream.Flush();

    const int bytesWritten = writeStream.GetBytesProcessed();

    memset( buffer + bytesWritten, 0, size_t(BufferSize) - bytesWritten );

    TestObject readObject;

    ReadStream readStream( buffer, bytesWritten );
    readObject.Serialize( readStream );

    next_check( readObject == writeObject );
}

void test_bits_required()
{
    next_check( bits_required( 0, 0 ) == 0 );
    next_check( bits_required( 0, 1 ) == 1 );
    next_check( bits_required( 0, 2 ) == 2 );
    next_check( bits_required( 0, 3 ) == 2 );
    next_check( bits_required( 0, 4 ) == 3 );
    next_check( bits_required( 0, 5 ) == 3 );
    next_check( bits_required( 0, 6 ) == 3 );
    next_check( bits_required( 0, 7 ) == 3 );
    next_check( bits_required( 0, 8 ) == 4 );
    next_check( bits_required( 0, 255 ) == 8 );
    next_check( bits_required( 0, 65535 ) == 16 );
    next_check( bits_required( 0, 4294967295U ) == 32 );
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
    // todo: convert to hydrogen
    /*
    const int BufferSize = 999;
    uint8_t buffer[BufferSize];
    next_crypto_random_bytes( buffer, BufferSize );
    for ( int i = 0; i < 100; ++i )
    {
        uint8_t next_buffer[BufferSize];
        next_crypto_random_bytes( next_buffer, BufferSize );
        next_check( memcmp( buffer, next_buffer, BufferSize ) != 0 );
        memcpy( buffer, next_buffer, BufferSize );
    }
    */
}

void test_random_float()
{
    // todo: convert to hydrogen
    /*
    for ( int i = 0; i < 1000; ++i )
    {
        float value = next_random_float();
        next_check( value >= 0.0f );
        next_check( value <= 1.0f );
    }
    */
}

void test_basic_read_and_write()
{
    uint8_t buffer[1024];

    uint8_t * p = buffer;
    next_write_uint8( &p, 105 );
    next_write_uint16( &p, 10512 );
    next_write_uint32( &p, 105120000 );
    next_write_uint64( &p, 105120000000000000LL );
    next_write_float32( &p, 100.0f );
    next_write_float64( &p, 100000000000000.0 );
    next_write_bytes( &p, (uint8_t*)"hello", 6 );

    const uint8_t * q = buffer;

    uint8_t a = next_read_uint8( &q );
    uint16_t b = next_read_uint16( &q );
    uint32_t c = next_read_uint32( &q );
    uint64_t d = next_read_uint64( &q );
    float e = next_read_float32( &q );
    double f = next_read_float64( &q );
    uint8_t g[6];
    next_read_bytes( &q, g, 6 );

    next_check( a == 105 );
    next_check( b == 10512 );
    next_check( c == 105120000 );
    next_check( d == 105120000000000000LL );
    next_check( e == 100.0f );
    next_check( f == 100000000000000.0 );
    next_check( memcmp( g, "hello", 6 ) == 0 );
}

void test_address_read_and_write()
{
    struct next_address_t a, b, c;

    memset( &a, 0, sizeof(a) );
    memset( &b, 0, sizeof(b) );
    memset( &c, 0, sizeof(c) );

    next_address_parse( &b, "127.0.0.1:50000" );

    next_address_parse( &c, "[::1]:50000" );

    uint8_t buffer[1024];

    uint8_t * p = buffer;

    next_write_address( &p, &a );
    next_write_address( &p, &b );
    next_write_address( &p, &c );

    struct next_address_t read_a, read_b, read_c;

    const uint8_t * q = buffer;

    next_read_address( &q, &read_a );
    next_read_address( &q, &read_b );
    next_read_address( &q, &read_c );

    next_check( next_address_equal( &a, &read_a ) );
    next_check( next_address_equal( &b, &read_b ) );
    next_check( next_address_equal( &c, &read_c ) );
}

void test_address_ipv4_read_and_write()
{
    struct next_address_t address;

    next_address_parse( &address, "127.0.0.1:50000" );

    uint8_t buffer[1024];

    uint8_t * p = buffer;

    next_write_address_ipv4( &p, &address );

    struct next_address_t read;

    const uint8_t * q = buffer;

    next_read_address_ipv4( &q, &read );

    next_check( next_address_equal( &address, &read ) );
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
    for ( int i = 0; i < MAX_CONNECT_TOKEN_BACKENDS; i++ )
    {
        input_token.client_backend_addresses[i] = next_random_uint32();
        input_token.client_backend_ports[i] = next_random_uint32();
    }        
    input_token.pings_per_second = 10;
    input_token.max_connect_seconds = 30;

    char connect_token_string[NEXT_MAX_CONNECT_TOKEN_BYTES];
    memset( connect_token_string, 0, sizeof(connect_token_string) );
    {
        next_check( next_write_connect_token( &input_token, connect_token_string, keypair.sk ) );
    }

    next_connect_token_t output_token;
    next_check( next_read_connect_token( &output_token, connect_token_string, keypair.pk ) );

    next_check( memcmp( &input_token, &output_token, sizeof(next_connect_token_t) - sizeof(input_token.signature) ) == 0 );
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
        RUN_TEST( test_bitpacker );
        RUN_TEST( test_bits_required );
        RUN_TEST( test_stream );
        RUN_TEST( test_address );
        RUN_TEST( test_replay_protection );
        RUN_TEST( test_random_bytes );
        RUN_TEST( test_random_float );
        RUN_TEST( test_basic_read_and_write );
        RUN_TEST( test_address_read_and_write );
        RUN_TEST( test_address_ipv4_read_and_write );
        RUN_TEST( test_platform_socket );
        RUN_TEST( test_platform_thread );
        RUN_TEST( test_platform_mutex );
        RUN_TEST( test_value_tracker );
        RUN_TEST( test_connect_token );
    }
}

#else // #if NEXT_DEVELOPMENT

#include <stdio.h>

void next_run_tests()
{
    printf( "\n[tests are not included in this build]\n\n" );
}

#endif // #if NEXT_DEVELOPMENT
