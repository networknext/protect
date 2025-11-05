/*
    Network Next Linux kernel module

    This module supports Ubuntu 24.04 LTS
*/

#pragma once

#include <linux/types.h>

#define NEXT_SIGN_PUBLIC_KEY_BYTES  32

#define NEXT_SIGN_PRIVATE_KEY_BYTES 64

#define NEXT_SECRETBOX_KEY_BYTES    32

struct next_sign_create_args
{
    __u8 private_key[NEXT_SIGN_PRIVATE_KEY_BYTES];
};

struct next_sign_verify_args
{
    __u8 public_key[NEXT_SIGN_PUBLIC_KEY_BYTES];
};

extern int bpf_next_sha256( void * data, int data__sz, void * output, int output__sz );

extern int bpf_next_sign_create( void * data, int data__sz, void * signature, int signature__sz, struct next_sign_create_args * args );

extern int bpf_next_sign_verify( void * data, int data__sz, void * signature, int signature__sz, struct next_sign_verify_args * args );

extern int bpf_next_secretbox_encrypt( void * data, int data__sz, void * key, int key__sz );

extern int bpf_next_secretbox_decrypt( void * data, int data__sz, void * key, int key__sz );
