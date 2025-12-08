/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#include "next.h"

#if NEXT_XDP == 0

#include "next_server_socket.h"
#include "next_constants.h"
#include "next_platform.h"
#include "next_packet_filter.h"
#include "next_hash.h"

#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <atomic>

struct next_server_socket_send_buffer_t
{
    std::atomic<int> num_packets;
    next_address_t to[NEXT_SERVER_SOCKET_MAX_SEND_PACKETS];
    size_t packet_bytes[NEXT_SERVER_SOCKET_MAX_SEND_PACKETS];
    uint8_t packet_type[NEXT_SERVER_SOCKET_MAX_SEND_PACKETS];
    uint8_t data[NEXT_FRAME_SIZE*NEXT_SERVER_SOCKET_MAX_SEND_PACKETS];
};

struct next_server_socket_receive_buffer_t
{
    int current_packet;
    next_address_t from[NEXT_SERVER_SOCKET_MAX_RECEIVE_PACKETS];
    uint8_t * packet_data[NEXT_SERVER_SOCKET_MAX_RECEIVE_PACKETS];
    size_t packet_bytes[NEXT_SERVER_SOCKET_MAX_RECEIVE_PACKETS];
    uint8_t data[NEXT_FRAME_SIZE*NEXT_SERVER_SOCKET_MAX_RECEIVE_PACKETS];
};

struct next_server_socket_t
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
    next_server_socket_send_buffer_t send_buffer;
    next_server_socket_receive_buffer_t receive_buffer;
    next_server_socket_process_packets_t process_packets;
};

void next_server_socket_destroy( next_server_socket_t * server_socket );

next_server_socket_t * next_server_socket_create( void * context, const char * public_address_string, int num_queues )
{
    (void) num_queues;  // not used

    next_assert( public_address_string );

    const char * num_queues_env = getenv( "NEXT_SERVER_NUM_QUEUES" );
    if ( num_queues_env )
    {
        num_queues = atoi( num_queues_env );
    }

    const char * public_address_env = getenv( "NEXT_SERVER_PUBLIC_ADDRESS" );
    if ( public_address_env )
    {
        public_address_string = public_address_env;
    }

    next_info( "server socket public address is %s", public_address_string );

    next_address_t public_address;
    if ( !next_address_parse( &public_address, public_address_string ) )
    {
        next_error( "could not parse public address" );
        return NULL;
    }

    if ( public_address.type != NEXT_ADDRESS_IPV4 )
    {
        next_error( "we only support ipv4 servers at the moment" );
        return NULL;
    }

    next_address_t bind_address = public_address;
    bind_address.data.ipv4[0] = 0;
    bind_address.data.ipv4[1] = 0;
    bind_address.data.ipv4[2] = 0;
    bind_address.data.ipv4[3] = 0;

    next_server_socket_t * server_socket = (next_server_socket_t*) next_malloc( context, sizeof(next_server_socket_t) );
    if ( !server_socket )
        return NULL;

    memset( server_socket, 0, sizeof( next_server_socket_t) );
    
    server_socket->context = context;

    server_socket->num_queues = num_queues;

    server_socket->socket = next_platform_socket_create( server_socket->context, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0.0f, NEXT_SOCKET_SEND_BUFFER_SIZE, NEXT_SOCKET_RECEIVE_BUFFER_SIZE );
    if ( server_socket->socket == NULL )
    {
        next_error( "could not create server socket" );
        next_server_socket_destroy( server_socket );
        return NULL;
    }

    char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_info( "server socket started on %s", next_address_to_string( &bind_address, address_string ) );

    server_socket->bind_address = bind_address;
    server_socket->public_address = public_address;
    server_socket->state = NEXT_SERVER_SOCKET_RUNNING;
    server_socket->server_id = next_hash_string( public_address_string );
    server_socket->match_id = next_random_uint64();

    next_info( "server id is %016" PRIx64, server_socket->server_id );
    next_info( "match id is %016" PRIx64, server_socket->match_id );

    return server_socket;    
}

void next_server_socket_destroy( next_server_socket_t * server_socket )
{
    next_assert( server_socket );
    next_assert( server_socket->state == NEXT_SERVER_SOCKET_STOPPED );        // IMPORTANT: Please stop the server and wait until state is NEXT_SERVER_STOPPED before destroying it

    if ( server_socket->socket )
    {
        next_platform_socket_destroy( server_socket->socket );
    }

    next_clear_and_free( server_socket->context, server_socket, sizeof(next_server_socket_t) );
}

void next_server_socket_update( next_server_socket_t * server_socket )
{
    next_assert( server_socket );

    if ( server_socket->state == NEXT_SERVER_SOCKET_STOPPING )
    {
        server_socket->state = NEXT_SERVER_SOCKET_STOPPED;
    }
}

void next_server_socket_stop( next_server_socket_t * server_socket )
{
    next_assert( server_socket );
    server_socket->state = NEXT_SERVER_SOCKET_STOPPING;
}

int next_server_socket_state( next_server_socket_t * server_socket )
{
    next_assert( server_socket );
    return server_socket->state;
}

uint64_t next_server_socket_id( next_server_socket_t * server_socket )
{
    next_assert( server_socket );
    return server_socket->server_id;
}

uint8_t * next_server_socket_start_packet_internal( struct next_server_socket_t * server_socket, const next_address_t * to, uint8_t packet_type, uint64_t * packet_id )
{
    next_assert( server_socket );
    next_assert( to );

    const int packet_index = server_socket->send_buffer.num_packets.fetch_add( 1 );

    if ( packet_index >= NEXT_SERVER_SOCKET_MAX_SEND_PACKETS )
        return NULL;

    uint8_t * packet_data = server_socket->send_buffer.data + packet_index * NEXT_FRAME_SIZE;

    packet_data += NEXT_HEADER_BYTES;

    server_socket->send_buffer.to[packet_index] = *to;
    server_socket->send_buffer.packet_type[packet_index] = packet_type;
    server_socket->send_buffer.packet_bytes[packet_index] = 0;

    *packet_id = server_socket->packet_id.fetch_add(1);

    return packet_data;
}

uint8_t * next_server_socket_start_packet( struct next_server_socket_t * server_socket, const next_address_t * to, uint64_t * packet_id )
{
    next_assert( server_socket );
    next_assert( to );
    next_assert( to->type == NEXT_ADDRESS_IPV4 );
    next_assert( packet_id );

    // direct packet

    uint8_t * packet_data = next_server_socket_start_packet_internal( server_socket, to, NEXT_PACKET_DIRECT, packet_id );
    if ( !packet_data )
        return NULL;

    return packet_data;
}

void next_server_socket_finish_packet( struct next_server_socket_t * server_socket, uint64_t packet_id, uint8_t * packet_data, int packet_bytes )
{
    next_assert( server_socket );
    next_assert( packet_bytes >= 0 );
    next_assert( packet_bytes <= NEXT_MTU );

    (void) packet_id;

    size_t offset = ( packet_data - server_socket->send_buffer.data );

    offset -= offset % NEXT_FRAME_SIZE;

    const int packet_index = (int) ( offset / NEXT_FRAME_SIZE );

    next_assert( packet_index >= 0 );  
    next_assert( packet_index < NEXT_SERVER_SOCKET_MAX_SEND_PACKETS );  

    next_assert( packet_data );
    next_assert( packet_bytes > 0 );
    next_assert( packet_bytes <= NEXT_MTU );

    server_socket->send_buffer.packet_bytes[packet_index] = packet_bytes + NEXT_HEADER_BYTES;

    // write the packet header

    packet_data -= NEXT_HEADER_BYTES;

    packet_data[0] = server_socket->send_buffer.packet_type[packet_index];

    uint8_t to_address_data[32];
    next_address_data( &server_socket->send_buffer.to[packet_index], to_address_data );

    uint8_t from_address_data[32];
    next_address_data( &server_socket->public_address, from_address_data );

    uint8_t * a = packet_data + 1;
    uint8_t * b = packet_data + 3;

    uint8_t magic[8];
    memset( magic, 0, sizeof(magic) );

    next_generate_pittle( a, from_address_data, to_address_data, packet_bytes );
    next_generate_chonkle( b, magic, from_address_data, to_address_data, packet_bytes );
}

void next_server_socket_abort_packet( struct next_server_socket_t * server_socket, uint64_t packet_id, uint8_t * packet_data )
{
    next_assert( server_socket );

    (void) packet_id;

    size_t offset = ( packet_data - server_socket->send_buffer.data );

    offset -= offset % NEXT_FRAME_SIZE;

    const int packet_index = (int) ( offset / NEXT_FRAME_SIZE );

    next_assert( packet_index >= 0 );  
    next_assert( packet_index < NEXT_SERVER_SOCKET_MAX_SEND_PACKETS );  

    server_socket->send_buffer.packet_bytes[packet_index] = 0;
}

void next_server_socket_send_packets( struct next_server_socket_t * server_socket )
{
    next_assert( server_socket );

    int num_packets = server_socket->send_buffer.num_packets;
    if ( num_packets > NEXT_SERVER_SOCKET_MAX_SEND_PACKETS )
    {
        num_packets = NEXT_SERVER_SOCKET_MAX_SEND_PACKETS;
    }

    for ( int i = 0; i < num_packets; i++ )
    {
        uint8_t * packet_data = server_socket->send_buffer.data + i * NEXT_FRAME_SIZE;

        const int packet_bytes = (int) server_socket->send_buffer.packet_bytes[i];

        if ( packet_bytes > 0 )
        {
            next_assert( packet_data );
            next_assert( packet_bytes <= NEXT_MAX_PACKET_BYTES );
            next_platform_socket_send_packet( server_socket->socket, &server_socket->send_buffer.to[i], packet_data, packet_bytes );
        }
    }

    server_socket->send_buffer.num_packets = 0;
}

void next_server_socket_process_packet_internal( next_server_socket_t * server_socket, next_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    const uint8_t packet_type = packet_data[0];

    // ...

    (void) packet_type;
}

void next_server_socket_process_direct_packet( next_server_socket_t * server_socket, next_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    if ( packet_bytes < NEXT_HEADER_BYTES )
        return;

    if ( server_socket->process_packets.num_packets == NEXT_SERVER_SOCKET_MAX_RECEIVE_PACKETS )
        return;

    const int index = server_socket->process_packets.num_packets++;

    packet_data += NEXT_HEADER_BYTES;
    packet_bytes -= NEXT_HEADER_BYTES;

    next_assert( packet_bytes >= 0 );

    server_socket->process_packets.from[index] = *from;
    server_socket->process_packets.packet_data[index] = packet_data;
    server_socket->process_packets.packet_bytes[index] = packet_bytes;
}

void next_server_socket_receive_packets( next_server_socket_t * server_socket )
{
    next_assert( server_socket );

    server_socket->process_packets.num_packets = 0;

    server_socket->receive_buffer.current_packet = 0;

    while ( 1 )
    {
        if ( server_socket->receive_buffer.current_packet >= NEXT_SERVER_SOCKET_MAX_RECEIVE_PACKETS )
            break;

        uint8_t * packet_data = server_socket->receive_buffer.data + NEXT_FRAME_SIZE * server_socket->receive_buffer.current_packet;

        struct next_address_t from;
        int packet_bytes = next_platform_socket_receive_packet( server_socket->socket, &from, packet_data, NEXT_MAX_PACKET_BYTES );
        if ( packet_bytes == 0 )
            break;

        const uint8_t packet_type = packet_data[0];

        // basic packet filter

        if ( !next_basic_packet_filter( packet_data, packet_bytes ) )
        {
            next_debug( "basic packet filter dropped packet" );
            continue;
        }

#if NEXT_ADVANCED_PACKET_FILTER

        // todo: advanced packet filter

#endif // #if NEXT_ADVANCED_PACKET_FILTER

        if ( packet_type == NEXT_PACKET_DIRECT )
        {  
            next_server_socket_process_direct_packet( server_socket, &from, packet_data, packet_bytes );
        }
        else
        {
            next_server_socket_process_packet_internal( server_socket, &from, packet_data, packet_bytes );            
        }

        server_socket->receive_buffer.current_packet++;
    }
}

struct next_server_socket_process_packets_t * next_server_socket_process_packets( struct next_server_socket_t * server_socket )
{
    next_assert( server_socket );

    return &server_socket->process_packets;
}

int next_server_socket_num_queues( struct next_server_socket_t * server_socket )
{
    next_assert( server_socket );
    return server_socket->num_queues;
}

#else // #if NEXT_XDP == 0

int next_server_socket_portable_cpp_dummy = 0;

#endif // #if NEXT_XDP == 0
