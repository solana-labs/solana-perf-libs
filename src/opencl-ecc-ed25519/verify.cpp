#include "cl_common.h"

#include "sha512.h"
#include <algorithm>
#include <stdio.h>
#include "ge.cu"
#include "sc.cu"
#include "fe.cu"
#include "seed.cu"
#include "keypair.cu"
#include "sha512.cu"

#include "ed25519.h"
#include <pthread.h>

#include "gpu_common.h"
#include "gpu_ctx.h"

#define USE_CLOCK_GETTIME
#include "perftime.h"

static int consttime_equal(const unsigned char *x, const unsigned char *y) {
    unsigned char r = 0;

    r = x[0] ^ y[0];
    #define F(i) r |= x[i] ^ y[i]
    F(1);
    F(2);
    F(3);
    F(4);
    F(5);
    F(6);
    F(7);
    F(8);
    F(9);
    F(10);
    F(11);
    F(12);
    F(13);
    F(14);
    F(15);
    F(16);
    F(17);
    F(18);
    F(19);
    F(20);
    F(21);
    F(22);
    F(23);
    F(24);
    F(25);
    F(26);
    F(27);
    F(28);
    F(29);
    F(30);
    F(31);
    #undef F

    return !r;
}

static int ed25519_verify_device(const unsigned char *signature,
                      const unsigned char *message,
                      uint32_t message_len,
                      const unsigned char *public_key) {
    unsigned char h[64];
    unsigned char checker[32];
    sha512_context hash;
    ge_p3 A;
    ge_p2 R;

    if (signature[63] & 224) {
        return 0;
    }

    if (ge_frombytes_negate_vartime(&A, public_key) != 0) {
        return 0;
    }
    sha512_init(&hash);
    sha512_update(&hash, signature, 32);
    sha512_update(&hash, public_key, 32);
    sha512_update(&hash, message, message_len);
    sha512_final(&hash, h);
    
    sc_reduce(h);
    ge_double_scalarmult_vartime(&R, h, &A, signature + 32);
    ge_tobytes(checker, &R);

    if (!consttime_equal(checker, signature)) {
        return 0;
    }

    return 1;
}

int ed25519_verify(const unsigned char *signature,
               const unsigned char *message,
               uint32_t message_len,
               const unsigned char *public_key) {
    return ed25519_verify_device(signature, message, message_len, public_key);
}

bool g_verbose = true;

void ed25519_set_verbose(bool val) {
    g_verbose = val;
}

void ed25519_verify_many(const gpu_Elems* elems,
                         uint32_t num_elems,
                         uint32_t message_size,
                         uint32_t total_packets,
                         uint32_t total_signatures,
                         const uint32_t* message_lens,
                         const uint32_t* public_key_offsets,
                         const uint32_t* signature_offsets,
                         const uint32_t* message_start_offsets,
                         uint8_t* out,
                         uint8_t use_non_default_stream)
{
    DIE(cl_check_init() == false, "OpenCL could not be init");
    
    cl_int ret;
    
    LOG("Starting verify_many: num_elems: %d total_signatures: %d total_packets: %d message_size: %d\n",
        num_elems, total_signatures, total_packets, message_size);

    size_t out_size = total_signatures * sizeof(uint8_t);

    uint32_t total_packets_size = total_packets * message_size;

    if (0 == total_packets) {
        return;
    }
	
	// Device allocate

    gpu_ctx_t* gpu_ctx = get_gpu_ctx();

    verify_ctx_t* cur_ctx = &gpu_ctx->verify_ctx;

    setup_gpu_ctx(cur_ctx,
                  elems,
                  num_elems,
                  message_size,
                  total_packets,
                  total_packets_size,
                  total_signatures,
                  message_lens,
                  public_key_offsets,
                  signature_offsets,
                  message_start_offsets,
                  out_size
                 );

    size_t num_threads_per_block = 64;
    size_t num_blocks = ROUND_UP_DIV(total_signatures, num_threads_per_block) * num_threads_per_block;
    LOG("num_blocks: %zu threads_per_block: %zu keys: %d out: %p\n",
           num_blocks, num_threads_per_block, (int)total_packets, out);                     
                             
    CL_ERR( clSetKernelArg(ed25519_verify_kernel, 0, sizeof(cl_mem), (void *)&cur_ctx->packets) );
    CL_ERR( clSetKernelArg(ed25519_verify_kernel, 1, sizeof(cl_uint), (void *)&message_size) );
    CL_ERR( clSetKernelArg(ed25519_verify_kernel, 2, sizeof(cl_mem), (void *)&cur_ctx->message_lens) );
    CL_ERR( clSetKernelArg(ed25519_verify_kernel, 3, sizeof(cl_mem), (void *)&cur_ctx->public_key_offsets) );
    CL_ERR( clSetKernelArg(ed25519_verify_kernel, 4, sizeof(cl_mem), (void *)&cur_ctx->signature_offsets) );
    CL_ERR( clSetKernelArg(ed25519_verify_kernel, 5, sizeof(cl_mem), (void *)&cur_ctx->message_start_offsets) );
    CL_ERR( clSetKernelArg(ed25519_verify_kernel, 6, sizeof(cl_uint), (void *)&cur_ctx->offsets_len) );
    CL_ERR( clSetKernelArg(ed25519_verify_kernel, 7, sizeof(cl_mem), (void *)&cur_ctx->out) );

	perftime_t start, end;
    get_time(&start);

    size_t globalSize[2] = {num_blocks * num_threads_per_block, 0};
    size_t localSize[2] = {num_threads_per_block, 0};    
    ret = clEnqueueNDRangeKernel(cmd_queue, ed25519_verify_kernel, 1, NULL,
        globalSize, localSize, 0, NULL, NULL);
        CL_ERR( ret );
        
    CL_ERR( clEnqueueReadBuffer(cmd_queue, cur_ctx->out, CL_TRUE, 0, out_size, out, 0, NULL, NULL));
	
	release_gpu_ctx(gpu_ctx);

    get_time(&end);
    LOG("time diff: %f\n", get_diff(&start, &end));
}

// Ensure copyright and license notice is embedded in the binary
const char* ed25519_license() {
   return "Copyright (c) 2018 Solana Labs, Inc. "
          "Licensed under the Apache License, Version 2.0 "
          "<http://www.apache.org/licenses/LICENSE-2.0>";
}

// Supported by the cuda lib, so stub them here.
int cuda_host_register(void* ptr, size_t size, unsigned int flags)
{
    return 0;
}

int cuda_host_unregister(void* ptr)
{
    return 0;
}
