/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 2.0
*/

#pragma once

#ifndef NEXT_CONSTANTS_H
#define NEXT_CONSTANTS_H

#include "next.h"

#define NEXT_SERVER_FRAME_SIZE                                       2048

#define NEXT_NUM_SERVER_FRAMES                  ( 10 * NEXT_MAX_CLIENTS )
#define NEXT_NUM_CLIENT_FRAMES                                   ( 1024 )

#define NEXT_XDP_QUEUE_SIZE                                 ( 64 * 1024 )

#define NEXT_XDP_MAX_SEND_PACKETS                                    2048

#define NEXT_DIRECT_TIMEOUT                                           5.0

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
