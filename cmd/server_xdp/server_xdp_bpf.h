/*
    Network Next. Copyright 2017 - 2025 Network Next, Inc.
    Licensed under the Network Next Source Available License 2.0
*/

#ifndef CLIENT_BACKEND_BPF_H
#define CLIENT_BACKEND_BPF_H

#include "client_backend.h"

#ifdef __linux__
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#endif // #ifdef __linux__

struct bpf_t
{
#ifdef __linux__
    int interface_index;
    struct xdp_program * program;
    bool attached_native;
    bool attached_skb;
    int config_fd;
    int state_fd;
    int buyer_fd;
#endif // #ifdef __linux__
};

bool bpf_init( struct bpf_t * bpf, uint32_t public_address );

void bpf_shutdown( struct bpf_t * bpf );

#endif // #ifndef CLIENT_BACKEND_BPF_H
