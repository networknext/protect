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
    (void) client_index;
    // todo
    return false;
}

void next_server_disconnect_client( next_server_t * server, int client_index )
{
    next_assert( server );
    (void) client_index;
    // todo
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

uint8_t * next_server_start_packet( struct next_server_t * server, int client_index )
{
    next_assert( server );
    (void) server;
    (void) client_index;
    return NULL;
}

void next_server_finish_packet( struct next_server_t * server, uint8_t * packet_data, int packet_bytes )
{
    next_assert( server );
    (void) server;
    (void) packet_data;
    (void) packet_bytes;
}

void next_server_abort_packet( struct next_server_t * server, uint8_t * packet_data )
{
    next_assert( server );
    (void) server;
    (void) packet_data;
}

void next_server_send_packets( struct next_server_t * server )
{
    next_assert( server );
    (void) server;
}


#if 0 

uint8_t * net_server_start_packet( struct net_server_t * server, int client_index, uint16_t * out_sequence, WriteStream & stream )
{
    core_assert( server );
    core_assert( client_index >= 0 );
    core_assert( client_index < server->max_clients );
    core_assert( out_sequence );

    platform_mutex_acquire( &server->send_buffer.mutex );

    uint8_t * packet_data = NULL;

    net_server_send_packet_info_t * platform_restrict packet_info = NULL;

    uint64_t sequence;

    uint16_t endpoint_sequence;
    uint16_t endpoint_ack;
    uint64_t endpoint_ack_bits;

    if ( server->send_buffer.current_frame < NET_NUM_SERVER_FRAMES )
    {
        sequence = server->client_sequence[client_index]++;
        packet_info = server->send_buffer.info + server->send_buffer.current_frame;
        packet_data = server->send_buffer.data + server->send_buffer.current_frame*NET_MAX_PACKET_BYTES;
        net_endpoint_get_header( server->client_endpoint[client_index], &endpoint_sequence, &endpoint_ack, &endpoint_ack_bits );
        server->send_buffer.current_frame++;
    }

    platform_mutex_release( &server->send_buffer.mutex );

    if ( !packet_data )
        return NULL;

    core_assert( packet_info );

    memset( packet_info, 0, sizeof(net_server_send_packet_info_t) );

    packet_info->magic_1 = NET_SERVER_SEND_PACKET_INFO_MAGIC;
    packet_info->magic_2 = NET_SERVER_SEND_PACKET_INFO_MAGIC;
    packet_info->sequence = sequence;
    packet_info->client_index = client_index;
    packet_info->endpoint_sequence = endpoint_sequence;
    packet_info->endpoint_ack = endpoint_ack;
    packet_info->endpoint_ack_bits = endpoint_ack_bits;

    stream.Initialize( packet_data, NET_MAX_PACKET_BYTES );

    // write the main packet header

    uint8_t header[256];

    uint8_t * p = header;

    uint8_t sequence_bytes = (uint8_t) net_sequence_number_bytes_required( packet_info->endpoint_sequence );

    core_assert( sequence_bytes >= 1 );
    core_assert( sequence_bytes <= 8 );

    const uint8_t packet_type = NET_PAYLOAD_PACKET;

    net_write_uint8( &p, packet_type );

    net_write_uint64( &p, packet_info->sequence );

    packet_info->header_bytes = p - header;

    // write the endpoint header

    net_write_endpoint_header( &p, packet_info->endpoint_sequence, packet_info->endpoint_ack, packet_info->endpoint_ack_bits );

    // copy the header to the front of the stream, the rest of the packet will be written to the stream after the header

    const int header_bytes = p - header;

    write_bytes( stream, header, header_bytes );

    *out_sequence = packet_info->endpoint_sequence;

    return packet_data;
}

void net_server_finish_packet( struct net_server_t * server, WriteStream & stream )
{
    core_assert( server );

    // look up packet info for this packet

    uint8_t * packet_data = stream.GetData();

    const size_t offset = ( packet_data - server->send_buffer.data );

    core_assert( offset >= 0 );
    core_assert( ( offset % NET_MAX_PACKET_BYTES ) == 0 );
   
    const int frame = (int) ( offset / NET_MAX_PACKET_BYTES );

    core_assert( frame >= 0 );  
    core_assert( frame < NET_NUM_SERVER_FRAMES );  

    net_server_send_packet_info_t * packet_info = server->send_buffer.info + frame;

    core_assert( packet_info->magic_1 == NET_SERVER_SEND_PACKET_INFO_MAGIC );
    core_assert( packet_info->magic_2 == NET_SERVER_SEND_PACKET_INFO_MAGIC );

    const int client_index = packet_info->client_index;

    core_assert( client_index >= 0 );
    core_assert( client_index < NET_MAX_CLIENTS );

    // IMPORTANT: If the client is not connected, just abort the packet.
    // This lets us *always* write packets as if all 1000 clients are connected
    if ( !server->client_connected[client_index] )
    {
        net_server_abort_packet( server, stream );
        return;
    }

    // flush the packet and check packet size is OK

    stream.Flush();

    const int packet_size = stream.GetBytesProcessed();

    core_assert( packet_data );
    core_assert( packet_size > 0 );
    core_assert( packet_size <= NET_MAX_PACKET_BYTES );

    // encrypt the packet

    uint8_t * packet_key = NULL;

    if ( net_encryption_manager_touch( &server->encryption_manager,
                                       server->client_encryption_index[client_index],
                                       &server->client_address[client_index],
                                       server->time ) )
    {
        packet_key = net_encryption_manager_get_send_key( &server->encryption_manager, server->client_encryption_index[client_index] );
    }

    if ( packet_key )
    {
        uint8_t additional_data[NET_VERSION_INFO_BYTES+8+1];
        {
            uint8_t * q = additional_data;
            net_write_bytes( &q, NET_VERSION_INFO, NET_VERSION_INFO_BYTES );
            net_write_uint64( &q, server->config.protocol_id );
            net_write_uint8( &q, packet_data[0] );
        }

        uint8_t nonce[12];
        {
            uint8_t * q = nonce;
            net_write_uint32( &q, 0 );
            net_write_uint64( &q, packet_info->sequence );
        }

        if ( net_crypto_encrypt_aead( packet_data + packet_info->header_bytes, 
                                      packet_size - packet_info->header_bytes,
                                      additional_data, sizeof( additional_data ), 
                                      nonce, packet_key ) )
        {
            packet_info->packet_size = packet_size + NET_CRYPTO_MAC_BYTES;
        }
    }
}

void net_server_abort_packet( struct net_server_t * server, WriteStream & stream )
{
    core_assert( server );

    stream.Flush();

    uint8_t * packet_data = stream.GetData();

    const int packet_size = stream.GetBytesProcessed();

    core_assert( packet_data );
    core_assert( packet_size > 0 );
    core_assert( packet_size <= NET_MAX_PACKET_BYTES );

    const size_t offset = ( packet_data - server->send_buffer.data );

    core_assert( offset >= 0 );
    core_assert( ( offset % NET_MAX_PACKET_BYTES ) == 0 );
   
    const int frame = (int) ( offset / NET_MAX_PACKET_BYTES );

    core_assert( frame >= 0 );  
    core_assert( frame < NET_NUM_SERVER_FRAMES );  

    net_server_send_packet_info_t * packet_info = server->send_buffer.info + frame;

    packet_info->packet_size = 0;
}

void net_server_send_packets( struct net_server_t * server )
{
    core_assert( server );

    const int num_packets = (int) server->send_buffer.current_frame;

    server->send_buffer.current_frame = 0;

    for ( int i = 0; i < num_packets; i++ )
    {
        uint8_t * packet_data = server->send_buffer.data + i*NET_MAX_PACKET_BYTES;

        net_server_send_packet_info_t * platform_restrict packet_info = server->send_buffer.info + i;

        core_assert( packet_info->magic_1 == NET_SERVER_SEND_PACKET_INFO_MAGIC );
        core_assert( packet_info->magic_2 == NET_SERVER_SEND_PACKET_INFO_MAGIC );

        const int packet_bytes = (int) packet_info->packet_size;

        if ( packet_bytes > 0 )
        {
            core_assert( packet_data );
            core_assert( packet_bytes <= NET_MAX_PACKET_BYTES );

            const int client_index = packet_info->client_index;

            core_assert( client_index >= 0 );
            core_assert( client_index < NET_MAX_CLIENTS );
            
            if ( server->client_connected[client_index] )
            {
#if NET_DEVELOPMENT
                if ( server->config.network_simulator )
                {
                    net_simulator_send_packet( server->config.network_simulator, &server->address, &server->client_address[client_index], packet_data, (int) packet_info->packet_size );
                    server->counters[NET_SERVER_COUNTER_PACKETS_SENT_SIMULATOR]++;
                }
                else
#endif // #if NET_DEVELOPMENT
                {
                    net_socket_send_packet( server->socket, &server->client_address[client_index], packet_data, (int) packet_info->packet_size );
                    server->counters[NET_SERVER_COUNTER_PACKETS_SENT]++;
                }

                const int wire_header_bytes = 16 + 8 + 8 + 1;

                net_endpoint_packet_sent( server->client_endpoint[client_index], packet_info->endpoint_sequence, wire_header_bytes + packet_bytes );
            }
        }
    }    
}

#endif // #if 0
