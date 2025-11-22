/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#ifndef __linux__

#include "next_server.h"
#include "next_config.h"
#include "next_constants.h"
#include "next_platform.h"
#include "next_packet_filter.h"
#include "next_hash.h"

#include <memory.h>
#include <stdio.h>
#include <atomic>

struct next_server_send_buffer_t
{
    next_platform_mutex_t mutex;
    size_t current_packet;
    next_address_t to[NEXT_SERVER_MAX_SEND_PACKETS];
    size_t packet_bytes[NEXT_SERVER_MAX_SEND_PACKETS];
    uint8_t packet_type[NEXT_SERVER_MAX_SEND_PACKETS];
    uint8_t data[NEXT_MAX_PACKET_BYTES*NEXT_SERVER_MAX_SEND_PACKETS];
};

struct next_server_receive_buffer_t
{
    int current_packet;
    int client_index[NEXT_SERVER_MAX_RECEIVE_PACKETS];
    uint64_t sequence[NEXT_SERVER_MAX_RECEIVE_PACKETS];
    uint8_t * packet_data[NEXT_SERVER_MAX_RECEIVE_PACKETS];
    size_t packet_bytes[NEXT_SERVER_MAX_RECEIVE_PACKETS];
    uint8_t data[NEXT_MAX_PACKET_BYTES*NEXT_SERVER_MAX_RECEIVE_PACKETS];
};

struct next_server_t
{
    void * context;
    int state;
    next_address_t bind_address;
    next_address_t public_address;
    uint64_t server_id;
    uint64_t match_id;
    void (*packet_received_callback)( next_server_t * server, void * context, int client_index, const uint8_t * packet_data, int packet_bytes );

    bool client_connected[NEXT_MAX_CLIENTS];
    bool client_direct[NEXT_MAX_CLIENTS];
    next_address_t client_address[NEXT_MAX_CLIENTS];
    double client_last_packet_receive_time[NEXT_MAX_CLIENTS];

    next_platform_mutex_t client_payload_mutex;
    uint64_t client_payload_sequence[NEXT_MAX_CLIENTS];

    std::atomic<uint64_t> send_sequence;

    next_platform_socket_t * socket;
    next_server_send_buffer_t send_buffer;
    next_server_receive_buffer_t receive_buffer;
    next_server_process_packets_t process_packets;
};

void next_server_destroy( next_server_t * server );

next_server_t * next_server_create( void * context, const char * bind_address_string, const char * public_address_string )
{
    next_assert( bind_address_string );
    next_assert( public_address_string );

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

    if ( !next_platform_mutex_create( &server->client_payload_mutex ) )
    {
        next_error( "server failed to create client payload mutex" );
        next_server_destroy( server );
        return NULL;
    }

    if ( !next_platform_mutex_create( &server->send_buffer.mutex ) )
    {
        next_error( "server failed to create send buffer mutex" );
        next_server_destroy( server );
        return NULL;
    }

    return server;    
}

void next_server_destroy( next_server_t * server )
{
    next_assert( server );
    next_assert( server->state == NEXT_SERVER_STOPPED );        // IMPORTANT: Please stop the server and wait until state is NEXT_SERVER_STOPPED before destroying it

    next_platform_mutex_destroy( &server->client_payload_mutex );

    if ( server->socket )
    {
        next_platform_socket_destroy( server->socket );
    }

    next_platform_mutex_destroy( &server->send_buffer.mutex );

    next_clear_and_free( server->context, server, sizeof(next_server_t) );
}

void next_server_client_timed_out( next_server_t * server, int client_index )
{
    next_assert( client_index >= 0 );
    next_assert( client_index < NEXT_MAX_CLIENTS );
    char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_info( "client %s timed out from slot %d", next_address_to_string( &server->client_address[client_index], buffer ), client_index );
    server->client_connected[client_index] = 0;
    memset( &server->client_address[client_index], 0, sizeof(next_address_t) );
}

void next_server_client_disconnected( next_server_t * server, int client_index )
{
    next_assert( client_index >= 0 );
    next_assert( client_index < NEXT_MAX_CLIENTS );
    char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_info( "client %s disconnected from slot %d", next_address_to_string( &server->client_address[client_index], buffer ), client_index );
    server->client_connected[client_index] = 0;
    memset( &server->client_address[client_index], 0, sizeof(next_address_t) );
}

void next_server_update_timeout( next_server_t * server )
{
    double current_time = next_platform_time();

    for ( int i = 0; i < NEXT_MAX_CLIENTS; i++ )
    {
        if ( server->client_connected[i] )
        {
            if ( server->client_direct[i] )
            {
                if ( server->client_last_packet_receive_time[i] + NEXT_DIRECT_TIMEOUT < current_time )
                {
                    next_server_client_timed_out( server, i );
                }
            }
            else
            {
                // todo: next timeout
            }
        }
    }
}

void next_server_update( next_server_t * server )
{
    next_assert( server );

    // todo: mock stopping -> stopped transition
    if ( server->state == NEXT_SERVER_STOPPING )
    {
        server->state = NEXT_SERVER_STOPPED;
    }

    next_server_update_timeout( server );
}

bool next_server_client_connected( next_server_t * server, int client_index )
{
    next_assert( server );
    next_assert( client_index >= 0 );
    next_assert( client_index <= NEXT_MAX_CLIENTS );
    return server->client_connected[client_index];
}

void next_server_disconnect_client( next_server_t * server, int client_index )
{
    next_assert( server );
    next_assert( client_index >= 0 );
    next_assert( client_index <= NEXT_MAX_CLIENTS );

    if ( !server->client_connected[client_index] )
        return;

    next_server_client_disconnected( server, client_index );
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

uint8_t * next_server_start_packet_internal( struct next_server_t * server, next_address_t * to, uint8_t packet_type )
{
    next_assert( server );
    next_assert( to );

    next_platform_mutex_acquire( &server->send_buffer.mutex );

    uint8_t * packet_data = NULL;
    int packet = server->send_buffer.current_packet;
    if ( server->send_buffer.current_packet < NEXT_SERVER_MAX_SEND_PACKETS )
    {
        packet_data = server->send_buffer.data + packet * NEXT_MAX_PACKET_BYTES;
        server->send_buffer.current_packet++;
    }

    next_platform_mutex_release( &server->send_buffer.mutex );

    if ( !packet_data )
        return NULL;

    packet_data += NEXT_HEADER_BYTES;

    server->send_buffer.to[packet] = *to;
    server->send_buffer.packet_type[packet] = packet_type;
    server->send_buffer.packet_bytes[packet] = 0;

    return packet_data;
}

uint8_t * next_server_start_packet( struct next_server_t * server, int client_index, uint64_t * out_sequence )
{
    next_assert( server );
    next_assert( client_index >= 0 );
    next_assert( client_index < NEXT_MAX_CLIENTS );
    next_assert( out_sequence );

    if ( !server->client_connected[client_index] )
        return NULL;

    uint64_t sequence = server->send_sequence.fetch_add(1);

    if ( server->client_direct[client_index] )
    {
        // direct packet

        uint8_t * packet_data = next_server_start_packet_internal( server, &server->client_address[client_index], NEXT_PACKET_DIRECT );
        if ( !packet_data )
            return NULL;

        uint64_t endian_sequence = sequence;
        next_endian_fix( &endian_sequence );
        memcpy( packet_data, (char*)&endian_sequence, 8 );

        packet_data += 8;

        *out_sequence = sequence;

        return packet_data;
    }
    else
    {
        // todo: next packet

        return NULL;
    }
}

void next_server_finish_packet( struct next_server_t * server, uint64_t sequence, uint8_t * packet_data, int packet_bytes )
{
    next_assert( server );
    next_assert( packet_bytes >= 0 );
    next_assert( packet_bytes <= NEXT_MTU );

    size_t offset = ( packet_data - server->send_buffer.data );

    offset -= offset % NEXT_MAX_PACKET_BYTES;

    next_assert( offset < NEXT_MAX_PACKET_BYTES*NEXT_SERVER_MAX_SEND_PACKETS );

    const int packet = (int) ( offset / NEXT_MAX_PACKET_BYTES );

    next_assert( packet >= 0 );  
    next_assert( packet < NEXT_SERVER_MAX_SEND_PACKETS );  

    next_assert( packet_data );
    next_assert( packet_bytes > 0 );
    next_assert( packet_bytes <= NEXT_MTU );

    server->send_buffer.packet_bytes[packet] = packet_bytes + NEXT_HEADER_BYTES + 8;

    // write the packet header

    packet_data -= NEXT_HEADER_BYTES + 8;

    packet_data[0] = server->send_buffer.packet_type[packet];

    uint8_t to_address_data[32];
    next_address_data( &server->send_buffer.to[packet], to_address_data );

    uint8_t from_address_data[32];
    next_address_data( &server->public_address, from_address_data );

    uint8_t * a = packet_data + 1;
    uint8_t * b = packet_data + 3;

    uint8_t magic[8];
    memset( magic, 0, sizeof(magic) );

    next_generate_pittle( a, from_address_data, to_address_data, packet_bytes );
    next_generate_chonkle( b, magic, from_address_data, to_address_data, packet_bytes );
}

void next_server_abort_packet( struct next_server_t * server, uint64_t sequence, uint8_t * packet_data )
{
    next_assert( server );

    size_t offset = ( packet_data - server->send_buffer.data );

    offset -= offset % NEXT_MAX_PACKET_BYTES;

    next_assert( offset < NEXT_MAX_PACKET_BYTES*NEXT_SERVER_MAX_SEND_PACKETS );

    const int packet = (int) ( offset / NEXT_MAX_PACKET_BYTES );

    next_assert( packet >= 0 );  
    next_assert( packet < NEXT_SERVER_MAX_SEND_PACKETS );  

    server->send_buffer.packet_bytes[packet] = 0;
}

void next_server_send_packets( struct next_server_t * server )
{
    next_assert( server );

    const int num_packets = (int) server->send_buffer.current_packet;

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

    server->send_buffer.current_packet = 0;
}

void next_server_process_packet_internal( next_server_t * server, next_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    const uint8_t packet_type = packet_data[0];

    if ( packet_type == NEXT_PACKET_DISCONNECT && packet_bytes == sizeof(next_disconnect_packet_t) )
    {
        int client_index = -1;
        for ( int i = 0; i < NEXT_MAX_CLIENTS; i++ )
        {
            if ( next_address_equal( from, &server->client_address[i] ) )
            {
                client_index = i;
                break;
            }
        }

        if ( client_index == -1 )
            return;

        next_server_disconnect_client( server, client_index );
    }
}

void next_server_process_direct_packet( next_server_t * server, next_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    if ( packet_bytes < NEXT_HEADER_BYTES + 8 )
        return;

    if ( server->process_packets.num_packets == NEXT_SERVER_MAX_RECEIVE_PACKETS )
        return;

    int client_index = -1;
    int first_free_slot = -1;
    for ( int i = 0; i < NEXT_MAX_CLIENTS; i++ )
    {
        if ( first_free_slot == -1 && !server->client_connected[i] )
        {
            first_free_slot = i;
        }
        if ( next_address_equal( from, &server->client_address[i] ) )
        {
            client_index = i;
            break;
        }
    }

    if ( client_index == -1 )
    {
        if ( first_free_slot != -1 )
        {
            client_index = first_free_slot;
            char buffer[NEXT_MAX_ADDRESS_STRING_LENGTH];
            next_info( "client %s connected in slot %d", next_address_to_string( from, buffer ) );
            server->client_connected[client_index] = true;
            server->client_direct[client_index] = true;
            server->client_address[client_index] = *from;
        }
        else
        {
            // all client slots are full
            return;
        }
    }

    server->client_last_packet_receive_time[client_index] = next_platform_time();

    const int index = server->process_packets.num_packets++;

    uint64_t sequence;
    memcpy( (char*) &sequence, packet_data + NEXT_HEADER_BYTES, 8 );
    next_endian_fix( &sequence );

    packet_data += NEXT_HEADER_BYTES + 8;
    packet_bytes -= NEXT_HEADER_BYTES + 8;

    next_assert( packet_bytes >= 0 );

    server->process_packets.client_index[index] = client_index;
    server->process_packets.sequence[index] = sequence;
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

#else // #ifndef __linux__

int next_server_portable_cpp_dummy = 0;

#endif // #ifndef __linux__
