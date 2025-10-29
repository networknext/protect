/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.  
    Licensed under the Network Next Source Available License 1.0
*/

#ifndef CLIENT_BACKEND_BPF_H
#define CLIENT_BACKEND_BPF_H

#include "relay.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

struct bpf_t
{
    int interface_index;
    struct xdp_program * program;
    bool attached_native;
    bool attached_skb;
    /*
    int config_fd;
    int state_fd;
    int stats_fd;
    int relay_map_fd;
    int session_map_fd;
    int whitelist_map_fd;
    */
};

int bpf_init( struct bpf_t * bpf, uint32_t public_address );

void bpf_shutdown( struct bpf_t * bpf );

#endif // #ifndef CLIENT_BACKEND_BPF_H
