/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#ifndef PLATFORM_H
#define PLATFORM_H

#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define PLATFORM_OK             1
#define PLATFORM_ERROR          0

#define PLATFORM_ADDRESS_NONE   0
#define PLATFORM_ADDRESS_IPV4   1
#define PLATFORM_ADDRESS_IPV6   2

#if !defined ( PLATFORM_LITTLE_ENDIAN ) && !defined( PLATFORM_BIG_ENDIAN )

  #ifdef __BYTE_ORDER__
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
      #define PLATFORM_LITTLE_ENDIAN 1
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
      #define PLATFORM_BIG_ENDIAN 1
    #else
      #error Unknown machine endianess detected. Please define PLATFORM_LITTLE_ENDIAN or PLATFORM_BIG_ENDIAN.
    #endif // __BYTE_ORDER__

  // Detect with GLIBC's endian.h
  #elif defined(__GLIBC__)
    #include <endian.h>
    #if (__BYTE_ORDER == __LITTLE_ENDIAN)
      #define PLATFORM_LITTLE_ENDIAN 1
    #elif (__BYTE_ORDER == __BIG_ENDIAN)
      #define PLATFORM_BIG_ENDIAN 1
    #else
      #error Unknown machine endianess detected. Please define PLATFORM_LITTLE_ENDIAN or PLATFORM_BIG_ENDIAN.
    #endif // __BYTE_ORDER

  // Detect with _LITTLE_ENDIAN and _BIG_ENDIAN macro
  #elif defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
    #define PLATFORM_LITTLE_ENDIAN 1
  #elif defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN)
    #define PLATFORM_BIG_ENDIAN 1

  // Detect with architecture macros
  #elif    defined(__sparc)     || defined(__sparc__)                           \
        || defined(_POWER)      || defined(__powerpc__)                         \
        || defined(__ppc__)     || defined(__hpux)      || defined(__hppa)      \
        || defined(_MIPSEB)     || defined(_POWER)      || defined(__s390__)
    #define PLATFORM_BIG_ENDIAN 1
  #elif    defined(__i386__)    || defined(__alpha__)   || defined(__ia64)      \
        || defined(__ia64__)    || defined(_M_IX86)     || defined(_M_IA64)     \
        || defined(_M_ALPHA)    || defined(__amd64)     || defined(__amd64__)   \
        || defined(_M_AMD64)    || defined(__x86_64)    || defined(__x86_64__)  \
        || defined(_M_X64)      || defined(__bfin__)
    #define PLATFORM_LITTLE_ENDIAN 1
  #elif defined(_MSC_VER) && defined(_M_ARM)
    #define PLATFORM_LITTLE_ENDIAN 1
  #else
    #error Unknown machine endianess detected. Please define PLATFORM_LITTLE_ENDIAN or PLATFORM_BIG_ENDIAN.
  #endif

#endif

inline uint64_t bswap( uint32_t value )
{
#ifdef __GNUC__
    return __builtin_bswap32( value );
#else // #ifdef __GNUC__
    uint32_t output;
    output  = ( value & 0xFF000000 ) >> 24;
    output |= ( value & 0x00FF0000 ) >> 8;
    output |= ( value & 0x0000FF00 ) << 8;
    output |= ( value & 0x000000FF ) << 24;
#endif // #ifdef __GNUC__
}

inline uint16_t platform_ntohs( uint16_t in )
{
#if PLATFORM_BIG_ENDIAN
    return in;
#else // #if PLATFORM_BIG_ENDIAN
    return (uint16_t)( ( ( in << 8 ) & 0xFF00 ) | ( ( in >> 8 ) & 0x00FF ) );
#endif // #if PLATFORM_BIG_ENDIAN
}

inline uint16_t platform_htons( uint16_t in )
{
#if PLATFORM_BIG_ENDIAN
    return in;
#else // #if PLATFORM_BIG_ENDIAN
    return (uint16_t)( ( ( in << 8 ) & 0xFF00 ) | ( ( in >> 8 ) & 0x00FF ) );
#endif // #if PLATFORM_BIG_ENDIAN
}

inline uint32_t platform_ntohl( uint32_t in )
{
#if PLATFORM_BIG_ENDIAN
    return in;
#else // #if PLATFORM_BIG_ENDIAN
    return bswap( in );
#endif // #if PLATFORM_BIG_ENDIAN
}

inline uint32_t platform_htonl( uint32_t in )
{
#if PLATFORM_BIG_ENDIAN
    return in;
#else // #if PLATFORM_BIG_ENDIAN
    return bswap( in );
#endif // #if PLATFORM_BIG_ENDIAN
}

// -----------------------------------------------------------------------------------------------------------------------------------------------

#define PLATFORM_SOCKET_NON_BLOCKING       0
#define PLATFORM_SOCKET_BLOCKING           1

typedef int platform_socket_handle_t;

struct platform_socket_t
{
    int type;
    platform_socket_handle_t handle;
};

struct platform_thread_t
{
    pthread_t handle;
};

typedef void* (platform_thread_func_t)(void*);

struct platform_mutex_t
{
    pthread_mutex_t handle;
};

// -----------------------------------------------------------------------------------------------------------------------------------------------

int platform_init();

double platform_time();

void platform_sleep( double time );

// -----------------------------------------------------------------------------------------------------------------------------------------------

void platform_random_bytes( uint8_t * buffer, int bytes );

// -----------------------------------------------------------------------------------------------------------------------------------------------

bool platform_parse_address( char * address_string, uint32_t * address, uint16_t * port );

// -----------------------------------------------------------------------------------------------------------------------------------------------

struct platform_socket_t * platform_socket_create( uint32_t address, uint16_t port, int socket_type, float timeout_seconds, int send_buffer_size, int receive_buffer_size );

void platform_socket_destroy( struct platform_socket_t * socket );

void platform_socket_send_packet( struct platform_socket_t * socket, uint32_t to_address, uint16_t to_port, const void * packet_data, int packet_bytes );

int platform_socket_receive_packet( struct platform_socket_t * socket, uint32_t * from_address, uint16_t * from_port, void * packet_data, int max_packet_size );

// -----------------------------------------------------------------------------------------------------------------------------------------------

struct platform_thread_t * platform_thread_create( platform_thread_func_t * thread_function, void * arg );

void platform_thread_join( struct platform_thread_t * thread );

void platform_thread_destroy( struct platform_thread_t * thread );

bool platform_thread_set_high_priority( struct platform_thread_t * thread );

// -----------------------------------------------------------------------------------------------------------------------------------------------

struct platform_mutex_t * platform_mutex_create();

void platform_mutex_acquire( struct platform_mutex_t * mutex );

void platform_mutex_release( struct platform_mutex_t * mutex );

void platform_mutex_destroy( struct platform_mutex_t * mutex );

// -----------------------------------------------------------------------------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

#endif // #ifndef PLATFORM_H
