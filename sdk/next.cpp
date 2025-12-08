/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#include "next.h"
#include "next_platform.h"
#include "next_address.h"
#include "next_base64.h"
#include "next_hash.h"
#include "next_replay_protection.h"
#include "next_header.h"
#include "next_packet_filter.h"
#include "next_packet_loss_tracker.h"
#include "next_out_of_order_tracker.h"
#include "next_jitter_tracker.h"
#include "next_hydrogen.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <float.h>
#include <string.h>
#include <inttypes.h>
#if defined( _MSC_VER )
#include <malloc.h>
#endif // #if defined( _MSC_VER )
#include <time.h>
#include <atomic>

#if defined( _MSC_VER )
#pragma warning(push)
#pragma warning(disable:4996)
#pragma warning(disable:4127)
#pragma warning(disable:4244)
#pragma warning(disable:4668)
#endif

// -------------------------------------------------

void next_printf( const char * format, ... );

static void default_assert_function( const char * condition, const char * function, const char * file, int line )
{
    next_error( "assert failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
    fflush( stdout );
    #if defined(_MSC_VER)
        __debugbreak();
    #elif defined(__ORBIS__)
        __builtin_trap();
    #elif defined(__PROSPERO__)
        __builtin_trap();
    #elif defined(__clang__)
        __builtin_debugtrap();
    #elif defined(__GNUC__)
        __builtin_trap();
    #elif defined(linux) || defined(__linux) || defined(__linux__) || defined(__APPLE__)
        raise(SIGTRAP);
    #else
        #error "asserts not supported on this platform!"
    #endif
}

void (*next_assert_function_pointer)( const char * condition, const char * function, const char * file, int line ) = default_assert_function;

void next_assert_function( void (*function)( const char * condition, const char * function, const char * file, int line ) )
{
    if ( function )
    {
        next_assert_function_pointer = function;
    }
    else
    {
        next_assert_function_pointer = default_assert_function;
    }
}

// -------------------------------------------------------------

static int log_quiet = 0;

void next_quiet( bool flag )
{
   log_quiet = flag;
}

static int log_level = NEXT_LOG_LEVEL_INFO;

void next_log_level( int level )
{
    log_level = level;
}

const char * next_log_level_string( int level )
{
    if ( level == NEXT_LOG_LEVEL_SPAM )
        return "spam";
    else if ( level == NEXT_LOG_LEVEL_DEBUG )
        return "debug";
    else if ( level == NEXT_LOG_LEVEL_INFO )
        return "info";
    else if ( level == NEXT_LOG_LEVEL_ERROR )
        return "error";
    else if ( level == NEXT_LOG_LEVEL_WARN )
        return "warning";
    else
        return "???";
}

static void default_log_function( int level, const char * format, ... )
{
#if !NETWORK_NEXT_UNREAL_ENGINE     // IMPORTANT: Unreal doesn't like printf
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof( buffer ), format, args );
    if ( level != NEXT_LOG_LEVEL_NONE )
    {
        if ( !log_quiet )
        {
            const char * level_string = next_log_level_string( level );
            printf( "%.6f: %s: %s\n", next_platform_time(), level_string, buffer );
        }
    }
    else
    {
        printf( "%s\n", buffer );
    }
    va_end( args );
    fflush( stdout );
#endif // #if !NETWORK_NEXT_UNREAL_ENGINE
}

static void (*log_function)( int level, const char * format, ... ) = default_log_function;

void next_log_function( void (*function)( int level, const char * format, ... ) )
{
    if ( function )
    {
        log_function = function;
    }
    else
    {
        log_function = default_log_function;
    }
}

void next_printf( int level, const char * format, ... )
{
    if ( level > log_level )
        return;
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof( buffer ), format, args );
    log_function( level, "%s", buffer );
    va_end( args );
}

void next_info( const char * format, ... )
{
    if ( NEXT_LOG_LEVEL_INFO > log_level )
        return;
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof( buffer ), format, args );
    log_function( NEXT_LOG_LEVEL_INFO, "%s", buffer );
    va_end( args );
}

void next_warn( const char * format, ... )
{
    if ( NEXT_LOG_LEVEL_WARN > log_level )
        return;
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof( buffer ), format, args );
    log_function( NEXT_LOG_LEVEL_WARN, "%s", buffer );
    va_end( args );
}

void next_error( const char * format, ... )
{
    if ( NEXT_LOG_LEVEL_ERROR > log_level )
        return;
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof( buffer ), format, args );
    log_function( NEXT_LOG_LEVEL_ERROR, "%s", buffer );
    va_end( args );
}

void next_debug( const char * format, ... )
{
    if ( NEXT_LOG_LEVEL_DEBUG > log_level )
        return;
    va_list args;
    va_start( args, format );
    char buffer[1024];
    vsnprintf( buffer, sizeof( buffer ), format, args );
    log_function( NEXT_LOG_LEVEL_DEBUG, "%s", buffer );
    va_end( args );
}

// ------------------------------------------------------------

void * next_default_malloc_function( void * context, size_t bytes )
{
    (void) context;
    return malloc( bytes );
}

void next_default_free_function( void * context, void * p )
{
    (void) context;
    free( p );
}

static void * (*next_malloc_function)( void * context, size_t bytes ) = next_default_malloc_function;
static void (*next_free_function)( void * context, void * p ) = next_default_free_function;

void next_allocator( void * (*malloc_function)( void * context, size_t bytes ), void (*free_function)( void * context, void * p ) )
{
    next_assert( malloc_function );
    next_assert( free_function );
    next_malloc_function = malloc_function;
    next_free_function = free_function;
}

void * next_malloc( void * context, size_t bytes )
{
    next_assert( next_malloc_function );
    return next_malloc_function( context, bytes );
}

void next_free( void * context, void * p )
{
    next_assert( next_free_function );
    return next_free_function( context, p );
}

void next_clear_and_free( void * context, void * p, size_t p_size )
{
    memset( p, 0, p_size );
    next_free( context, p );
}

// -------------------------------------------------------------

const char * next_user_id_string( uint64_t user_id, char * buffer, size_t buffer_size )
{
    snprintf( buffer, buffer_size, "%" PRIx64, user_id );
    return buffer;
}

uint64_t next_protocol_version()
{
#if !NEXT_DEVELOPMENT
    #define VERSION_STRING(major,minor) #major #minor
    return next_hash_string( VERSION_STRING(NEXT_VERSION_MAJOR_INT, NEXT_VERSION_MINOR_INT) );
#else // #if !NEXT_DEVELOPMENT
    return 0;
#endif // #if !NEXT_DEVELOPMENT
}

float next_random_float()
{
    uint32_t uint32_value;
    hydro_random_buf( (uint8_t*)&uint32_value, sizeof(uint32_value) );
    uint64_t uint64_value = uint64_t(uint32_value);
    double double_value = double(uint64_value) / 0xFFFFFFFF;
    return float(double_value);
}

uint8_t next_random_uint8()
{
    uint8_t value;
    hydro_random_buf( &value, sizeof(value) );
    return value;
}

uint16_t next_random_uint16()
{
    uint16_t value;
    hydro_random_buf( (uint8_t*)&value, sizeof(value) );
    return value;
}

uint32_t next_random_uint32()
{
    uint32_t value;
    hydro_random_buf( (uint8_t*)&value, sizeof(value) );
    return value;
}

uint64_t next_random_uint64()
{
    uint64_t value;
    hydro_random_buf( (uint8_t*)&value, sizeof(value) );
    return value;
}

void next_random_bytes( uint8_t * data, size_t bytes )
{
    hydro_random_buf( (uint8_t*)data, bytes );
}

// -------------------------------------------------------------

size_t next_copy_string( char * dest, const char * source, size_t dest_size )
{
    next_assert( dest );
    next_assert( source );
    next_assert( dest_size >= 1 );
    memset( dest, 0, dest_size );
    size_t i = 0;
    for ( ; i < dest_size - 1; i++ )
    {
        if ( source[i] == '\0' )
            break;
        dest[i] = source[i];
    }
    return i;
}

// -------------------------------------------------------------

int next_signed_packets[256];

int next_encrypted_packets[256];

const char * next_platform_string( int platform_id )
{
    switch ( platform_id )
    {
        case NEXT_PLATFORM_WINDOWS:       return "windows";
        case NEXT_PLATFORM_MAC:           return "mac";
        case NEXT_PLATFORM_LINUX:         return "linux";
        case NEXT_PLATFORM_SWITCH:        return "switch";
        case NEXT_PLATFORM_PS4:           return "ps4";
        case NEXT_PLATFORM_PS5:           return "ps5";
        case NEXT_PLATFORM_IOS:           return "ios";
        case NEXT_PLATFORM_XBOX_ONE:      return "xboxone";
        case NEXT_PLATFORM_XBOX_SERIES_X: return "seriesx";
        default:
            break;
    }
    return "unknown";
}

const char * next_connection_string( int connection_type )
{
    switch ( connection_type )
    {
        case NEXT_CONNECTION_TYPE_WIRED:    return "wired";
        case NEXT_CONNECTION_TYPE_WIFI:     return "wi-fi";
        case NEXT_CONNECTION_TYPE_CELLULAR: return "cellular";
        default:
            break;
    }
    return "unknown";
}

void * next_global_context = NULL;

bool next_init( void * context )
{
    next_assert( next_global_context == NULL );

    next_global_context = context;

    if ( !next_platform_init() )
    {
        next_error( "failed to initialize platform" );
        return false;
    }

    next_info( "network next version is %s", NEXT_VERSION_FULL );

    const char * platform_string = next_platform_string( next_platform_id() );
    const char * connection_string = next_connection_string( next_platform_connection_type() );

    next_info( "platform is %s (%s)", platform_string, connection_string );

    if ( hydro_init() != 0 ) 
    {
        next_error( "failed to initialize hydrogen" );
        return false;
    }

    const char * log_level_override = next_platform_getenv( "NEXT_LOG_LEVEL" );
    if ( log_level_override )
    {
        log_level = atoi( log_level_override );
        next_info( "log level overridden to %d", log_level );
    }

    return true;
}

void next_term()
{
    next_platform_term();

    next_global_context = NULL;
}

// ---------------------------------------------------------------

// IMPORTANT: off by default.
bool next_packet_tagging_enabled = false;

bool next_packet_tagging_can_be_enabled()
{
    return next_platform_packet_tagging_can_be_enabled();
}

void next_enable_packet_tagging()
{
    if ( next_platform_packet_tagging_can_be_enabled() )
    {
        next_info( "enabled packet tagging" );
        next_packet_tagging_enabled = true;
    }
}

void next_disable_packet_tagging()
{
    if ( next_platform_packet_tagging_can_be_enabled() )
    {
        next_info( "disabled packet tagging" );
        next_packet_tagging_enabled = false;
    }
}

// ---------------------------------------------------------------

#ifdef _MSC_VER
#pragma warning(pop)
#endif
