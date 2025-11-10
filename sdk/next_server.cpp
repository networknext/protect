/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#include "next_server.h"
#include "next_config.h"
#include "next_constants.h"
#include "next_platform.h"
#include "next_hash.h"

#include <memory.h>

#define NEXT_MAX_CLIENTS                                  1024

#define NEXT_NUM_SERVER_FRAMES                   ( 10 * 1024 )

struct next_server_send_packet_info_t
{
    uint64_t sequence;
    int client_index;
    int header_bytes;
    size_t packet_size;
    size_t max_packet_size;
};

struct next_server_send_buffer_t
{
    next_platform_mutex_t mutex;
    size_t current_frame;
    next_server_send_packet_info_t info[NEXT_NUM_SERVER_FRAMES];
    uint8_t data[NEXT_MAX_PACKET_BYTES*NEXT_NUM_SERVER_FRAMES];
};

struct next_server_receive_packet_info_t
{
    int client_index;
    int header_bytes;
    uint64_t sequence;
    size_t packet_size;
};

struct next_server_receive_buffer_t
{
    int current_frame;
    next_server_receive_packet_info_t info[NEXT_NUM_SERVER_FRAMES];
    uint8_t data[NEXT_MAX_PACKET_BYTES*NEXT_NUM_SERVER_FRAMES];
};

struct next_server_t
{
    void * context;
    int state;
    next_address_t bind_address;
    next_address_t public_address;
    uint64_t server_id;
    uint64_t match_id;
    next_platform_socket_t * socket;
    void (*packet_received_callback)( next_server_t * server, void * context, int client_index, const uint8_t * packet_data, int packet_bytes );
    next_server_send_buffer_t send_buffer;
    next_server_receive_buffer_t receive_buffer;
    bool client_connected[NEXT_MAX_CLIENTS];
    next_address_t client_address[NEXT_MAX_CLIENTS];
    uint64_t client_sequence[NEXT_MAX_CLIENTS];
};

next_server_t * next_server_create( void * context, const char * bind_address_string, const char * public_address_string )
{
    next_assert( bind_address_string );
    next_assert( public_address_string );

    next_address_t bind_address;
    if ( next_address_parse( &bind_address, bind_address_string ) != NEXT_OK )
    {
        next_error( "server could not parse bind address" );
        return NULL;
    }

    next_address_t public_address;
    if ( next_address_parse( &public_address, public_address_string ) != NEXT_OK )
    {
        next_error( "server could not parse public address" );
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

void next_server_receive_packets( next_server_t * server )
{
    next_assert( server );

    server->receive_buffer.current_frame = 0;

    while ( 1 )
    {
        if ( server->receive_buffer.current_frame >= NEXT_NUM_SERVER_FRAMES )
            break;

        next_server_receive_packet_info_t * packet_info = server->receive_buffer.info + server->receive_buffer.current_frame;

        memset( packet_info, 0, sizeof(next_server_receive_packet_info_t) );

        uint8_t * packet_data = server->receive_buffer.data + NEXT_MAX_PACKET_BYTES * server->receive_buffer.current_frame;

        struct next_address_t from;
        int packet_size = next_platform_socket_receive_packet( server->socket, &from, packet_data, NEXT_MAX_PACKET_BYTES );
        if ( packet_size == 0 )
            break;

        const uint8_t packet_type = packet_data[0] & 0xF;

        // todo
        (void) packet_type;
        /*
        if ( packet_type != NET_PAYLOAD_PACKET )
        {  
            net_server_process_packet( server, &from, packet_data, packet_size );
        }
        else
        */
        {
            // todo: handle payload
            /*
            const int client_index = net_server_find_client_index_by_address( server, &from );
            if ( client_index >= 0 )
            {
                packet_info->packet_size = packet_size;
                packet_info->client_index = client_index;
            }
            */
        }

        server->receive_buffer.current_frame++;
    }
}

void next_server_update( next_server_t * server )
{
    next_assert( server );

    // todo
    (void) server;
    next_platform_sleep( 1.0 / 100.0 );

    // todo
    if ( server->state == NEXT_SERVER_STOPPING )
    {
        server->state = NEXT_SERVER_STOPPED;
    }
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

    // todo
    (void) client_index;
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

uint8_t * next_server_start_packet( struct next_server_t * server, int client_index, uint64_t * out_sequence )
{
    next_assert( server );
    next_assert( client_index >= 0 );
    next_assert( out_sequence );

    next_platform_mutex_acquire( &server->send_buffer.mutex );

    uint64_t sequence = 0;
    uint8_t * packet_data = NULL;

    // todo: next_restrict
    next_server_send_packet_info_t * __restrict__ packet_info = NULL;

    if ( server->send_buffer.current_frame < NEXT_NUM_SERVER_FRAMES )
    {
        sequence = ++server->client_sequence[client_index];
        packet_info = server->send_buffer.info + server->send_buffer.current_frame;
        packet_data = server->send_buffer.data + server->send_buffer.current_frame * NEXT_MAX_PACKET_BYTES;
        server->send_buffer.current_frame++;
    }

    next_platform_mutex_release( &server->send_buffer.mutex );

    if ( !packet_data )
        return NULL;

    packet_data += NEXT_HEADER_BYTES;

    next_assert( packet_info );

    memset( packet_info, 0, sizeof(next_server_send_packet_info_t) );

    packet_info->sequence = sequence;
    packet_info->client_index = client_index;

    *out_sequence = sequence;

    return packet_data;
}

void next_server_finish_packet( struct next_server_t * server, uint8_t * packet_data, int packet_bytes )
{
    next_assert( server );

    size_t offset = ( packet_data - server->send_buffer.data );

    offset -= offset % NEXT_MAX_PACKET_BYTES;

    next_assert( offset < NEXT_MAX_PACKET_BYTES*NEXT_NUM_SERVER_FRAMES );

    const int frame = (int) ( offset / NEXT_MAX_PACKET_BYTES );

    next_assert( frame >= 0 );  
    next_assert( frame < NEXT_NUM_SERVER_FRAMES );  

    next_server_send_packet_info_t * packet_info = server->send_buffer.info + frame;

    const int client_index = packet_info->client_index;

    next_assert( client_index >= 0 );
    next_assert( client_index < NEXT_MAX_CLIENTS );

    if ( !server->client_connected[client_index] )
    {
        next_server_abort_packet( server, packet_data );
        return;
    }

    next_assert( packet_data );
    next_assert( packet_size > 0 );
    next_assert( packet_size <= NEXT_MAX_PACKET_BYTES );

    packet_info->packet_size = packet_bytes + NEXT_HEADER_BYTES;

    // todo: we should write the header here
}

void next_server_abort_packet( struct next_server_t * server, uint8_t * packet_data )
{
    next_assert( server );

    size_t offset = ( packet_data - server->send_buffer.data );

    offset -= offset % NEXT_MAX_PACKET_BYTES;

    next_assert( offset < NEXT_MAX_PACKET_BYTES*NEXT_NUM_SERVER_FRAMES );

    const int frame = (int) ( offset / NEXT_MAX_PACKET_BYTES );

    next_assert( frame >= 0 );  
    next_assert( frame < NEXT_NUM_SERVER_FRAMES );  

    next_server_send_packet_info_t * packet_info = server->send_buffer.info + frame;

    packet_info->packet_size = 0;
}

void next_server_send_packets( struct next_server_t * server )
{
    next_assert( server );

    const int num_packets = (int) server->send_buffer.current_frame;

    server->send_buffer.current_frame = 0;

    for ( int i = 0; i < num_packets; i++ )
    {
        uint8_t * packet_data = server->send_buffer.data + i*NEXT_MAX_PACKET_BYTES;

        // todo: next_restrict
        next_server_send_packet_info_t * __restrict__ packet_info = server->send_buffer.info + i;

        const int packet_bytes = (int) packet_info->packet_size;

        if ( packet_bytes > 0 )
        {
            next_assert( packet_data );
            next_assert( packet_bytes <= NET_MAX_PACKET_BYTES );

            const int client_index = packet_info->client_index;

            next_assert( client_index >= 0 );
            next_assert( client_index < NET_MAX_CLIENTS );
            
            if ( server->client_connected[client_index] )
            {
                next_platform_socket_send_packet( server->socket, &server->client_address[client_index], packet_data, (int) packet_info->packet_size );
            }
        }
    }    
}
