/*
    Network Next Linux kernel module

    This module supports Ubuntu 24.04 LTS

    USAGE:

        sudo insmod next_module.ko
        lsmod
        sudo dmesg --follow
        sudo rmmod next_module

    BTF debugging:

        sudo bpftool btf show
        sudo bpftool btf dump id <id>
*/

#include "next_module.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <crypto/hash.h>
#include <crypto/kpp.h>
#include "hydrogen.h"

// ----------------------------------------------------------------------------------------------------------------------

struct crypto_shash * sha256;

__bpf_kfunc int bpf_next_sha256( void * data, int data__sz, void * output, int output__sz )
{
    SHASH_DESC_ON_STACK( shash, tfm );
    shash->tfm = sha256;
    crypto_shash_digest( shash, data, data__sz, output );
    return 0;
}

// ----------------------------------------------------------------------------------------------------------------------

__bpf_kfunc int bpf_next_sign_create( void * data, int data__sz, void * signature, int signature__sz, struct next_sign_create_args * args )
{
    kernel_fpu_begin();
    char context[hydro_sign_CONTEXTBYTES];
    memset( context, 0, sizeof(context) );
    int result = hydro_sign_create( signature, data, data__sz, context, args->private_key );
    kernel_fpu_end();
    return result;
}

// ----------------------------------------------------------------------------------------------------------------------

__bpf_kfunc int bpf_next_sign_verify( void * data, int data__sz, void * signature, int signature__sz, struct next_sign_verify_args * args )
{
    kernel_fpu_begin();
    char context[hydro_sign_CONTEXTBYTES];
    memset( context, 0, sizeof(context) );
    int result = hydro_sign_verify( signature, data, data__sz, context, args->public_key );
    kernel_fpu_end();
    return result;
}

// ----------------------------------------------------------------------------------------------------------------------

int bpf_next_secretbox_encrypt( void * data, int data__sz, void * key, int key__sz )
{
    kernel_fpu_begin();
    char context[hydro_sign_CONTEXTBYTES];
    memset( context, 0, sizeof(context) );
    // ...
    kernel_fpu_end();
    return 0;
}

// ----------------------------------------------------------------------------------------------------------------------

int bpf_next_secretbox_decrypt( void * data, int data__sz, void * key, int key__sz )
{
    kernel_fpu_begin();
    char context[hydro_sign_CONTEXTBYTES];
    memset( context, 0, sizeof(context) );
    // ...
    kernel_fpu_end();
    return 0;
}

// ----------------------------------------------------------------------------------------------------------------------

BTF_SET8_START( bpf_task_set )
BTF_ID_FLAGS( func, bpf_next_sha256 )
BTF_ID_FLAGS( func, bpf_next_sign_verify )
BTF_ID_FLAGS( func, bpf_next_secretbox_encrypt )
BTF_ID_FLAGS( func, bpf_next_secretbox_decrypt )
BTF_SET8_END( bpf_task_set )

static const struct btf_kfunc_id_set bpf_task_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &bpf_task_set,
};

// ----------------------------------------------------------------------------------------------------------------------

static int __init next_init( void ) 
{
    pr_info( "Network Next kernel module initializing...\n" );

    sha256 = crypto_alloc_shash( "sha256", 0, 0 );
    if ( IS_ERR( sha256 ) )
    {
        pr_err( "can't create sha256 crypto hash algorithm\n" );
        return PTR_ERR( sha256 );
    }

    int result = register_btf_kfunc_id_set( BPF_PROG_TYPE_XDP, &bpf_task_kfunc_set );
    if ( result != 0 )
    {
        pr_err( "failed to register network next kernel module kfuncs\n" );
        return -1;
    }

    pr_info( "Network Next kernel module initialized successfully\n" );

    return result;
}

static void __exit next_exit( void ) 
{
    pr_info( "Network Next kernel module shutting down...\n" );

    if ( !IS_ERR( sha256 ) )
    {
        crypto_free_shash( sha256 );
    }

    pr_info( "Network Next kernel module shut down successfully\n" );
}

module_init( next_init );
module_exit( next_exit );

#include "hydrogen.c"

MODULE_VERSION( "1.0.0" );
MODULE_LICENSE( "GPL" ); 
MODULE_AUTHOR( "Glenn Fiedler" ); 
MODULE_DESCRIPTION( "Network Next kernel module" );
