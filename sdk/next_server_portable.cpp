/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#ifndef __linux__

#include "next_server.h"
#include "next_constants.h"
#include "next_platform.h"
#include "next_packet_filter.h"
#include "next_hash.h"

#include <memory.h>
#include <stdio.h>
#include <atomic>

struct next_server_send_buffer_t
{
    std::atomic<int> num_packets;
    next_address_t to[NEXT_SERVER_MAX_SEND_PACKETS];
    size_t packet_bytes[NEXT_SERVER_MAX_SEND_PACKETS];
    uint8_t packet_type[NEXT_SERVER_MAX_SEND_PACKETS];
    uint8_t data[NEXT_MAX_PACKET_BYTES*NEXT_SERVER_MAX_SEND_PACKETS];
};

struct next_server_receive_buffer_t
{
    int current_packet;
    next_address_t from[NEXT_SERVER_MAX_RECEIVE_PACKETS];
    uint8_t * packet_data[NEXT_SERVER_MAX_RECEIVE_PACKETS];
    size_t packet_bytes[NEXT_SERVER_MAX_RECEIVE_PACKETS];
    uint8_t data[NEXT_MAX_PACKET_BYTES*NEXT_SERVER_MAX_RECEIVE_PACKETS];
};

struct next_server_t
{
    void * context;
    int num_queues;
    int state;
    next_address_t bind_address;
    next_address_t public_address;
    uint64_t server_id;
    uint64_t match_id;

    std::atomic<uint64_t> packet_id;

    next_platform_socket_t * socket;
    next_server_send_buffer_t send_buffer;
    next_server_receive_buffer_t receive_buffer;
    next_server_process_packets_t process_packets;
};

void next_server_destroy( next_server_t * server );

next_server_t * next_server_create( void * context, const char * bind_address_string, const char * public_address_string, int num_queues )
{
    (void) num_queues;  // not used

    next_assert( bind_address_string );
    next_assert( public_address_string );

    const char * num_queues_env = getenv( "NEXT_SERVER_NUM_QUEUES" );
    if ( num_queues_env )
    {
        num_queues = atoi( num_queues_env );
    }

    const char * bind_address_env = getenv( "NEXT_SERVER_BIND_ADDRESS" );
    if ( bind_address_env )
    {
        bind_address_string = bind_address_env;
    }

    const char * public_address_env = getenv( "NEXT_SERVER_PUBLIC_ADDRESS" );
    if ( public_address_env )
    {
        public_address_string = public_address_env;
    }

    next_info( "server public address is %s", public_address_string );

    next_address_t bind_address;
    if ( !next_address_parse( &bind_address, bind_address_string ) )
    {
        next_error( "server could not parse bind address" );
        return NULL;
    }

    next_address_t public_address;
    if ( !next_address_parse( &public_address, public_address_string ) )
    {
        next_error( "server could not parse public address" );
        return NULL;
    }

    if ( public_address.type != NEXT_ADDRESS_IPV4 )
    {
        next_error( "we only support ipv4 servers at the moment" );
        return NULL;
    }

    next_server_t * server = (next_server_t*) next_malloc( context, sizeof(next_server_t) );
    if ( !server )
        return NULL;

    memset( server, 0, sizeof( next_server_t) );
    
    server->context = context;

    server->num_queues = num_queues;

    server->socket = next_platform_socket_create( server->context, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0.0f, NEXT_SOCKET_SEND_BUFFER_SIZE, NEXT_SOCKET_RECEIVE_BUFFER_SIZE );
    if ( server->socket == NULL )
    {
        next_error( "server could not create socket" );
        next_server_destroy( server );
        return NULL;
    }

    char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_info( "server started on %s", next_address_to_string( &bind_address, address_string ) );

    server->bind_address = bind_address;
    server->public_address = public_address;
    server->state = NEXT_SERVER_RUNNING;
    server->server_id = next_hash_string( public_address_string );
    server->match_id = next_random_uint64();

    next_info( "server id is %016" PRIx64, server->server_id );
    next_info( "match id is %016" PRIx64, server->match_id );

    return server;    
}

void next_server_destroy( next_server_t * server )
{
    next_assert( server );
    next_assert( server->state == NEXT_SERVER_STOPPED );        // IMPORTANT: Please stop the server and wait until state is NEXT_SERVER_STOPPED before destroying it

    if ( server->socket )
    {
        next_platform_socket_destroy( server->socket );
    }

    next_clear_and_free( server->context, server, sizeof(next_server_t) );
}

void next_server_update( next_server_t * server )
{
    next_assert( server );

    // todo: mock stopping -> stopped transition
    if ( server->state == NEXT_SERVER_STOPPING )
    {
        server->state = NEXT_SERVER_STOPPED;
    }
}

void next_server_stop( next_server_t * server )
{
    next_assert( server );
    server->state = NEXT_SERVER_STOPPING;
}

int next_server_state( next_server_t * server )
{
    next_assert( server );
    return server->state;
}

uint64_t next_server_id( next_server_t * server )
{
    next_assert( server );
    return server->server_id;
}

uint8_t * next_server_start_packet_internal( struct next_server_t * server, const next_address_t * to, uint8_t packet_type, uint64_t * packet_id )
{
    next_assert( server );
    next_assert( to );

    const int packet_index = server->send_buffer.num_packets.fetch_add( 1 );

    if ( packet_index >= NEXT_SERVER_MAX_SEND_PACKETS )
        return NULL;

    uint8_t * packet_data = server->send_buffer.data + packet_index * NEXT_MAX_PACKET_BYTES;

    packet_data += NEXT_HEADER_BYTES;

    server->send_buffer.to[packet_index] = *to;
    server->send_buffer.packet_type[packet_index] = packet_type;
    server->send_buffer.packet_bytes[packet_index] = 0;

    *packet_id = server->packet_id.fetch_add(1);

    return packet_data;
}

uint8_t * next_server_start_packet( struct next_server_t * server, const next_address_t * to, uint64_t * packet_id )
{
    next_assert( server );
    next_assert( to );
    next_assert( to->type == NEXT_ADDRESS_IPV4 );
    next_assert( packet_id );

    // direct packet

    uint8_t * packet_data = next_server_start_packet_internal( server, to, NEXT_PACKET_DIRECT, packet_id );
    if ( !packet_data )
        return NULL;

    return packet_data;
}

void next_server_finish_packet( struct next_server_t * server, uint64_t packet_id, uint8_t * packet_data, int packet_bytes )
{
    next_assert( server );
    next_assert( packet_bytes >= 0 );
    next_assert( packet_bytes <= NEXT_MTU );

    (void) packet_id;

    size_t offset = ( packet_data - server->send_buffer.data );

    offset -= offset % NEXT_MAX_PACKET_BYTES;

    next_assert( offset < NEXT_MAX_PACKET_BYTES*NEXT_SERVER_MAX_SEND_PACKETS );

    const int packet_index = (int) ( offset / NEXT_MAX_PACKET_BYTES );

    next_assert( packet_index >= 0 );  
    next_assert( packet_index < NEXT_SERVER_MAX_SEND_PACKETS );  

    next_assert( packet_data );
    next_assert( packet_bytes > 0 );
    next_assert( packet_bytes <= NEXT_MTU );

    server->send_buffer.packet_bytes[packet_index] = packet_bytes + NEXT_HEADER_BYTES;

    // write the packet header

    packet_data -= NEXT_HEADER_BYTES;

    packet_data[0] = server->send_buffer.packet_type[packet_index];

    uint8_t to_address_data[32];
    next_address_data( &server->send_buffer.to[packet_index], to_address_data );

    uint8_t from_address_data[32];
    next_address_data( &server->public_address, from_address_data );

    uint8_t * a = packet_data + 1;
    uint8_t * b = packet_data + 3;

    uint8_t magic[8];
    memset( magic, 0, sizeof(magic) );

    next_generate_pittle( a, from_address_data, to_address_data, packet_bytes );
    next_generate_chonkle( b, magic, from_address_data, to_address_data, packet_bytes );
}

void next_server_abort_packet( struct next_server_t * server, uint64_t packet_id, uint8_t * packet_data )
{
    next_assert( server );

    (void) packet_id;

    size_t offset = ( packet_data - server->send_buffer.data );

    offset -= offset % NEXT_MAX_PACKET_BYTES;

    next_assert( offset < NEXT_MAX_PACKET_BYTES*NEXT_SERVER_MAX_SEND_PACKETS );

    const int packet_index = (int) ( offset / NEXT_MAX_PACKET_BYTES );

    next_assert( packet_index >= 0 );  
    next_assert( packet_index < NEXT_SERVER_MAX_SEND_PACKETS );  

    server->send_buffer.packet_bytes[packet_index] = 0;
}

void next_server_send_packets( struct next_server_t * server )
{
    next_assert( server );

    int num_packets = server->send_buffer.num_packets;
    if ( num_packets > NEXT_SERVER_MAX_SEND_PACKETS )
    {
        num_packets = NEXT_SERVER_MAX_SEND_PACKETS;
    }

    for ( int i = 0; i < num_packets; i++ )
    {
        uint8_t * packet_data = server->send_buffer.data + i * NEXT_MAX_PACKET_BYTES;

        const int packet_bytes = (int) server->send_buffer.packet_bytes[i];

        if ( packet_bytes > 0 )
        {
            next_assert( packet_data );
            next_assert( packet_bytes <= NEXT_MAX_PACKET_BYTES );
            next_platform_socket_send_packet( server->socket, &server->send_buffer.to[i], packet_data, (int) server->send_buffer.packet_bytes[i] );
        }
    }

    server->send_buffer.num_packets = 0;
}

void next_server_process_packet_internal( next_server_t * server, next_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    const uint8_t packet_type = packet_data[0];

    // ...

    (void) packet_type;
}

void next_server_process_direct_packet( next_server_t * server, next_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    if ( packet_bytes < NEXT_HEADER_BYTES )
        return;

    if ( server->process_packets.num_packets == NEXT_SERVER_MAX_RECEIVE_PACKETS )
        return;

    const int index = server->process_packets.num_packets++;

    packet_data += NEXT_HEADER_BYTES;
    packet_bytes -= NEXT_HEADER_BYTES;

    next_assert( packet_bytes >= 0 );

    server->process_packets.from[index] = *from;
    server->process_packets.packet_data[index] = packet_data;
    server->process_packets.packet_bytes[index] = packet_bytes;
}

void next_server_receive_packets( next_server_t * server )
{
    next_assert( server );

    server->process_packets.num_packets = 0;

    server->receive_buffer.current_packet = 0;

    while ( 1 )
    {
        if ( server->receive_buffer.current_packet >= NEXT_SERVER_MAX_RECEIVE_PACKETS )
            break;

        uint8_t * packet_data = server->receive_buffer.data + NEXT_MAX_PACKET_BYTES * server->receive_buffer.current_packet;

        struct next_address_t from;
        int packet_bytes = next_platform_socket_receive_packet( server->socket, &from, packet_data, NEXT_MAX_PACKET_BYTES );
        if ( packet_bytes == 0 )
            break;

        // basic packet filter

        if ( !next_basic_packet_filter( packet_data, packet_bytes ) )
        {
            next_debug( "basic packet filter dropped packet" );
            continue;
        }

#if NEXT_ADVANCED_PACKET_FILTER

        // todo: advanced packet filter

#endif // #if NEXT_ADVANCED_PACKET_FILTER

        const uint8_t packet_type = packet_data[0];

        if ( packet_type == NEXT_PACKET_DIRECT )
        {  
            next_server_process_direct_packet( server, &from, packet_data, packet_bytes );
        }
        else
        {
            next_server_process_packet_internal( server, &from, packet_data, packet_bytes );            
        }
    }
}

struct next_server_process_packets_t * next_server_process_packets( struct next_server_t * server )
{
    next_assert( server );
    return &server->process_packets;
}

int next_server_num_queues( struct next_server_t * server )
{
    next_assert( server );
    return server->num_queues;
}

#else // #ifndef __linux__

int next_server_portable_cpp_dummy = 0;

#endif // #ifndef __linux__
