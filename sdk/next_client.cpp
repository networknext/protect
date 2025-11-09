/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#include "next_client.h"
#include "next_config.h"
#include "next_constants.h"
#include "next_platform.h"
#include "next_packet_filter.h"
#include "next_connect_token.h"
#include "next_client_backend_token.h"
#include "next_platform.h"

#include <memory.h>

#pragma pack(push,1)

struct next_client_backend_init_request_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint8_t sdk_version_major;
    uint8_t sdk_version_minor;
    uint8_t sdk_version_patch;
    struct next_connect_token_t connect_token;
    uint64_t request_id;
};

struct next_client_backend_init_response_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint64_t request_id;
    struct next_client_backend_token_t backend_token;
};

struct next_client_backend_ping_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint8_t sdk_version_major;
    uint8_t sdk_version_minor;
    uint8_t sdk_version_patch;
    uint64_t request_id;
    uint64_t ping_sequence;
    struct next_client_backend_token_t backend_token;
};

struct next_client_backend_pong_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint64_t request_id;
    uint64_t ping_sequence;
};

struct next_client_backend_refresh_token_request_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint8_t sdk_version_major;
    uint8_t sdk_version_minor;
    uint8_t sdk_version_patch;
    uint64_t request_id;
    struct next_client_backend_token_t backend_token;
};

struct next_client_backend_refresh_token_response_packet_t
{
    uint8_t type;
    uint8_t prefix[17];
    uint64_t request_id;
    struct next_client_backend_token_t backend_token;
};

#pragma pack(pop)

struct next_client_backend_init_data_t
{
    double next_update_time;
    uint64_t request_id;
    uint64_t ping_sequence;
    uint64_t pong_sequence;
    bool initialized;
    int num_pongs_received;
    next_client_backend_token_t backend_token;
};

struct next_client_t
{
    void * context;

    int state;

    uint16_t bound_port;

    double init_start_time;
    next_connect_token_t connect_token;
    next_client_backend_init_data_t backend_init_data[NEXT_MAX_CONNECT_TOKEN_BACKENDS];

    double last_refresh_backend_token_time;
    double last_request_backend_token_refresh_time;
    uint64_t refresh_backend_token_request_id;

    next_address_t client_backend_address;
    next_client_backend_token_t backend_token;
    uint64_t session_id;
    uint64_t server_id;

    next_platform_socket_t * socket;

    void (*packet_received_callback)( next_client_t * client, void * context, const uint8_t * packet_data, int packet_bytes );
};

next_client_t * next_client_create( void * context, const char * connect_token_string, const uint8_t * buyer_public_key, void (*packet_received_callback)( next_client_t * client, void * context, const uint8_t * packet_data, int packet_bytes ) )
{
    next_assert( connect_token );
    next_assert( buyer_public_key );
    next_assert( packet_received_callback );

    next_connect_token_t connect_token;
    if ( !next_read_connect_token( &connect_token, connect_token_string, buyer_public_key ) )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "connect token is invalid" );
        return NULL;
    }

    int num_backends_found = 0;
    for ( int i = 0; i < NEXT_MAX_CONNECT_TOKEN_BACKENDS; i++ )
    {
        if ( connect_token.backend_addresses[i] != 0 )
        {
            num_backends_found++;
        }
    }

    if ( num_backends_found == 0 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "no backends found in connect token" );
        return NULL;
    }

    if ( connect_token.pings_per_second == 0 )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "pings per-second is zero in connect token" );
        return NULL;
    }

    next_client_t * client = (next_client_t*) next_malloc( context, sizeof(next_client_t) );
    if ( !client )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "could not allocate next_client_t" );
        return NULL;
    }

    memset( client, 0, sizeof( next_client_t) );
    
    const uint64_t current_time = next_platform_time();

    client->context = context;
    client->connect_token = connect_token;
    client->state = NEXT_CLIENT_INITIALIZING;
    client->init_start_time = current_time;
    client->last_refresh_backend_token_time = current_time;
    client->refresh_backend_token_request_id = next_random_uint64();
    client->packet_received_callback = packet_received_callback;

    next_address_t bind_address;
    memset( &bind_address, 0, sizeof(bind_address) );
    bind_address.type = NEXT_ADDRESS_IPV4;

    // IMPORTANT: for many platforms it's best practice to bind to ipv6 and go dual stack on the client
    if ( next_platform_client_dual_stack() )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "client socket is dual stack ipv4 and ipv6" );
        bind_address.type = NEXT_ADDRESS_IPV6;
    }

    // IMPORTANT: some platforms (GDK) have a preferred port that we must use to access packet tagging
    // If the bind address has set port of 0, substitute the preferred client port here
    if ( bind_address.port == 0 )
    {
        int preferred_client_port = next_platform_preferred_client_port();
        if ( preferred_client_port != 0 )
        {
            next_printf( NEXT_LOG_LEVEL_INFO, "client socket using preferred port %d", preferred_client_port );
            bind_address.port = preferred_client_port;
        }
    }

    client->socket = next_platform_socket_create( client->context, &bind_address, NEXT_PLATFORM_SOCKET_NON_BLOCKING, 0.0f, NEXT_SOCKET_SEND_BUFFER_SIZE, NEXT_SOCKET_RECEIVE_BUFFER_SIZE );
    if ( client->socket == NULL )
    {
        next_printf( NEXT_LOG_LEVEL_ERROR, "client could not create socket" );
        next_client_destroy( client );
        return NULL;
    }

    char address_string[NEXT_MAX_ADDRESS_STRING_LENGTH];
    next_printf( NEXT_LOG_LEVEL_INFO, "client bound to %s", next_address_to_string( &bind_address, address_string ) );

    client->bound_port = bind_address.port;

    return client;    
}

void next_client_destroy( next_client_t * client )
{
    // IMPORTANT: Please call disconnect and wait for the client to disconnect before destroying the client
    next_assert( client->state == NEXT_CLIENT_DISCONNECTED );

    if ( client->socket )
    {
        next_platform_socket_destroy( client->socket );
    }

    next_clear_and_free( client->context, client, sizeof(next_client_t) );
}

void next_client_send_packet_internal( next_client_t * client, next_address_t * to_address, uint8_t * packet_data, int packet_bytes )
{
    uint8_t to_address_data[32];
    next_address_data( to_address, to_address_data );

    next_address_t from_address;
    memset( &from_address, 0, sizeof(from_address) );
    from_address.type = NEXT_ADDRESS_IPV4;
    memcpy( from_address.data.ipv4, (uint8_t*) &client->connect_token.client_public_address, 4 );

    uint8_t from_address_data[32];
    next_address_data( &from_address, from_address_data );

    uint8_t * a = packet_data + 1;
    uint8_t * b = packet_data + 3;

    uint8_t magic[8];
    memset( magic, 0, sizeof(magic) );

    next_generate_pittle( a, from_address_data, to_address_data, packet_bytes );
    next_generate_chonkle( b, magic, from_address_data, to_address_data, packet_bytes );

    next_platform_socket_send_packet( client->socket, to_address, packet_data, packet_bytes );
}

void next_client_update_initialize( next_client_t * client )
{
    /*
        Our strategy is to ping n client backends and accept the first backend that we init with and receive n pongs from
        This biases us towards selecting the client backend with the lowest latency lowest packet loss for the client
    */

    if ( client->state != NEXT_CLIENT_INITIALIZING )
        return;

    double current_time = next_platform_time();

    if ( client->init_start_time + client->connect_token.max_connect_seconds < current_time )
    {
        next_printf( NEXT_LOG_LEVEL_INFO, "client init timed out" );
        client->state = NEXT_CLIENT_INIT_TIMED_OUT;
        return;
    }

    next_address_t from;
    next_address_load_ipv4( &from, client->connect_token.client_public_address, 0 );

    for ( int i = 0; i < NEXT_MAX_CONNECT_TOKEN_BACKENDS; i++ )
    {
        if ( client->connect_token.backend_addresses[i] == 0 )
        {
            continue;
        }

        if ( client->backend_init_data[i].next_update_time == 0.0 )
        {
            client->backend_init_data[i].next_update_time = current_time + next_random_float() * ( 1.0 / client->connect_token.pings_per_second );
            client->backend_init_data[i].request_id = next_random_uint64();
            continue;
        }

        if ( client->backend_init_data[i].next_update_time > current_time )
        {
            continue;
        }
        
        client->backend_init_data[i].next_update_time += ( 1.0 / client->connect_token.pings_per_second );            

        next_address_t to;
        next_address_load_ipv4( &to, client->connect_token.backend_addresses[i], client->connect_token.backend_ports[i] );

        if ( !client->backend_init_data[i].initialized )
        {
            next_client_backend_init_request_packet_t packet;
            packet.type = NEXT_CLIENT_BACKEND_PACKET_INIT_REQUEST;
            packet.sdk_version_major = NEXT_VERSION_MAJOR_INT;
            packet.sdk_version_major = NEXT_VERSION_MINOR_INT;
            packet.sdk_version_major = NEXT_VERSION_PATCH_INT;
            packet.connect_token = client->connect_token;
            packet.request_id = client->backend_init_data[i].request_id;
            // todo: endian fixup
            next_client_send_packet_internal( client, &to, (uint8_t*) &packet, sizeof(next_client_backend_init_request_packet_t) );
        }
        else
        {
            next_printf( NEXT_LOG_LEVEL_INFO, "sent ping packet to client backend %d", i );

            next_client_backend_ping_packet_t packet;
            packet.type = NEXT_CLIENT_BACKEND_PACKET_PING; 
            packet.sdk_version_major = NEXT_VERSION_MAJOR_INT;
            packet.sdk_version_major = NEXT_VERSION_MINOR_INT;
            packet.sdk_version_major = NEXT_VERSION_PATCH_INT;
            packet.request_id = client->backend_init_data[i].request_id;
            packet.ping_sequence = client->backend_init_data[i].ping_sequence++;
            packet.backend_token = client->backend_init_data[i].backend_token;
            // todo: endian fixup
            next_client_send_packet_internal( client, &to, (uint8_t*) &packet, sizeof(next_client_backend_ping_packet_t) );
        }
    }
}

void next_client_process_packet( next_client_t * client, next_address_t * from, uint8_t * packet_data, int packet_bytes )
{
    // we only support ipv4 at the moment

    if ( from->type != NEXT_ADDRESS_IPV4 )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "ignored packet from non-ipv4 address" );
        return;
    }

    // basic packet filter

    if ( !next_basic_packet_filter( packet_data, packet_bytes ) )
    {
        next_printf( NEXT_LOG_LEVEL_DEBUG, "basic packet filter dropped packet" );
        return;
    }

#if NEXT_ADVANCED_PACKET_FILTER

    // todo: advanced packet filter

#endif // #if NEXT_ADVANCED_PACKET_FILTER

    // process packet type

    const uint8_t packet_type = packet_data[0];

    if ( client->state == NEXT_CLIENT_CONNECTED )
    {
        // common case: client is connected

        if ( packet_type == NEXT_CLIENT_BACKEND_PACKET_REFRESH_TOKEN_RESPONSE && packet_bytes == sizeof(next_client_backend_refresh_token_response_packet_t) )
        {
            const next_client_backend_refresh_token_response_packet_t * packet = (const next_client_backend_refresh_token_response_packet_t*) packet_data;

            if ( packet->request_id != client->refresh_backend_token_request_id )
                return;

            next_printf( NEXT_LOG_LEVEL_INFO, "client refreshed backend token" );

            client->backend_token = packet->backend_token;
            client->last_refresh_backend_token_time = next_platform_time();
            client->refresh_backend_token_request_id = next_random_uint64();
        }
    }
    else if ( client->state == NEXT_CLIENT_INITIALIZING )
    {
        // client is initializing

        const uint32_t from_ipv4 = next_address_ipv4( from );
        const uint16_t from_port = next_platform_htons( from->port );

        if ( packet_type == NEXT_CLIENT_BACKEND_PACKET_INIT_RESPONSE && packet_bytes == sizeof(next_client_backend_init_response_packet_t) )
        {
            const next_client_backend_init_response_packet_t * packet = (const next_client_backend_init_response_packet_t*) packet_data;

            // todo: endian fixup

            for ( int i = 0; i < NEXT_MAX_CONNECT_TOKEN_BACKENDS; i++ )
            {
                if ( client->connect_token.backend_addresses[i] != from_ipv4 || client->connect_token.backend_ports[i] != from_port )
                    continue;

                if ( client->backend_init_data[i].initialized )
                    break;

                if ( client->backend_init_data[i].request_id != packet->request_id )
                    break;

                client->backend_init_data[i].initialized = true;
                client->backend_init_data[i].next_update_time = next_platform_time();
                client->backend_init_data[i].backend_token = packet->backend_token;

                next_printf( NEXT_LOG_LEVEL_INFO, "initialized with client backend %d", i );

                break;
            }
        }
        else if ( packet_type == NEXT_CLIENT_BACKEND_PACKET_PONG && packet_bytes == sizeof(next_client_backend_pong_packet_t) )
        {
            const next_client_backend_pong_packet_t * packet = (const next_client_backend_pong_packet_t*) packet_data;

            // todo: endian fixup

            for ( int i = 0; i < NEXT_MAX_CONNECT_TOKEN_BACKENDS; i++ )
            {
                if ( client->connect_token.backend_addresses[i] != from_ipv4 || client->connect_token.backend_ports[i] != from_port )
                    continue;

                if ( !client->backend_init_data[i].initialized )
                    break;

                if ( client->backend_init_data[i].request_id != packet->request_id )
                    break;

                if ( packet->ping_sequence < client->backend_init_data[i].pong_sequence )
                    break;

                next_printf( NEXT_LOG_LEVEL_INFO, "received pong from client backend %d", i );

                client->backend_init_data[i].pong_sequence = packet->ping_sequence + 1;
                client->backend_init_data[i].num_pongs_received++;

                if ( client->backend_init_data[i].num_pongs_received++ > client->connect_token.pongs_before_select )
                {
                    client->state = NEXT_CLIENT_CONNECTED;
                    client->client_backend_address = *from;
                    client->backend_token = client->backend_init_data[i].backend_token;

                    next_printf( NEXT_LOG_LEVEL_INFO, "selected client backend %d", i );
                }

                break;
            }
        }
    }
}

void next_client_update_receive_packets( next_client_t * client )
{
    while ( true )
    {
        uint8_t packet_data[NEXT_MAX_PACKET_BYTES];
        next_address_t from;
        int packet_bytes = next_platform_socket_receive_packet( client->socket, &from, packet_data, sizeof(packet_data) );
        if ( packet_bytes == 0 )
            return;

        next_client_process_packet( client, &from, packet_data, packet_bytes );
    }
}

void next_client_update_refresh_backend_token( next_client_t * client )
{
    if ( client->state <= NEXT_CLIENT_INITIALIZING )
        return;

    const uint64_t current_time = next_platform_time();

    if ( client->last_refresh_backend_token_time + client->connect_token.backend_token_refresh_seconds > current_time )
        return;

    if ( client->last_request_backend_token_refresh_time + 1.0 > current_time )
        return;

    next_printf( NEXT_LOG_LEVEL_INFO, "request refresh backend token" );

    next_client_backend_refresh_token_request_packet_t packet;
    packet.type = NEXT_CLIENT_BACKEND_PACKET_REFRESH_TOKEN_REQUEST;
    packet.sdk_version_major = NEXT_VERSION_MAJOR_INT;
    packet.sdk_version_major = NEXT_VERSION_MINOR_INT;
    packet.sdk_version_major = NEXT_VERSION_PATCH_INT;
    packet.request_id = client->refresh_backend_token_request_id;
    packet.backend_token = client->backend_token;
    // todo: endian fixup
    next_client_send_packet_internal( client, &client->client_backend_address, (uint8_t*) &packet, sizeof(next_client_backend_refresh_token_request_packet_t) );

    client->last_request_backend_token_refresh_time = current_time;
}

void next_client_update( next_client_t * client )
{
    next_assert( client );

    next_client_update_initialize( client );

    next_client_update_refresh_backend_token( client );

    next_client_update_receive_packets( client );

    // todo
    (void) client;
    next_platform_sleep( 1.0 / 100.0 );
}

void next_client_send_packet( next_client_t * client, const uint8_t * packet_data, int packet_bytes )
{
    next_assert( client );

    if ( client->state != NEXT_CLIENT_CONNECTED )
        return;

    // todo: send payload packet
    (void) client;
    (void) packet_data;
    (void) packet_bytes;
}

void next_client_disconnect( next_client_t * client )
{
    next_assert( client );
    client->state = NEXT_CLIENT_DISCONNECTED;
}

int next_client_state( next_client_t * client )
{
    next_assert( client );
    return client->state;
}

uint64_t next_client_session_id( next_client_t * client )
{
    next_assert( client );
    return client->session_id;
}

uint64_t next_client_server_id( next_client_t * client )
{
    next_assert( client );
    return client->server_id;
}
