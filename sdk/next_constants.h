/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#pragma once

#ifndef NEXT_CONSTANTS_H
#define NEXT_CONSTANTS_H

#include "next.h"

#define NEXT_FRAME_SIZE                                              2048

#define NEXT_SEND_PACKETS_PER_CLIENT                                   64

#define NEXT_RECEIVE_PACKETS_PER_CLIENT                                16

#if NEXT_XDP

#define NEXT_XDP_NUM_FRAMES                                         65536
#define NEXT_XDP_FRAME_SIZE                                          4096
#define NEXT_XDP_SEND_QUEUE_SIZE                             ( 4096 * 4 )
#define NEXT_XDP_RECV_QUEUE_SIZE                             ( 4096 * 4 )
#define NEXT_XDP_FILL_QUEUE_SIZE                                     2048
#define NEXT_XDP_SEND_BATCH_SIZE                                       32

#else // #if NEXT_XDP

#define NEXT_SERVER_SOCKET_MAX_SEND_PACKETS              ( NEXT_SEND_PACKETS_PER_CLIENT * NEXT_MAX_CLIENTS )

#define NEXT_SERVER_SOCKET_MAX_RECEIVE_PACKETS        ( NEXT_RECEIVE_PACKETS_PER_CLIENT * NEXT_MAX_CLIENTS )

#endif // #if NEXT_XDP

#define NEXT_SERVER_SOCKET_MAX_PROCESS_PACKETS        ( NEXT_RECEIVE_PACKETS_PER_CLIENT * NEXT_MAX_CLIENTS )

#define NEXT_NUM_CLIENT_PACKETS                                      1024

#define NEXT_DIRECT_TIMEOUT                                          30.0

#define NEXT_REPLAY_PROTECTION_BUFFER_SIZE                           1024

#define NEXT_PACKET_LOSS_TRACKER_HISTORY                             1024
#define NEXT_PACKET_LOSS_TRACKER_SAFETY                                30
#define NEXT_SECONDS_BETWEEN_PACKET_LOSS_UPDATES                      0.1

#define NEXT_IPV4_HEADER_BYTES                                         20
#define NEXT_UDP_HEADER_BYTES                                           8
#define NEXT_HEADER_BYTES                                              18

#define NEXT_SOCKET_SEND_BUFFER_SIZE                              1000000
#define NEXT_SOCKET_RECEIVE_BUFFER_SIZE                           1000000

#define NEXT_VALUE_TRACKER_HISTORY                                   1024

#endif // #ifndef NEXT_CONSTANTS_H
