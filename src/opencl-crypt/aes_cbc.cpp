/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include "common.h"

#include <algorithm>
#include "aes.h"
#include "modes.h"
#include "perftime.h"
#include "modes_lcl.h"
#include "aes_core.cpp"
#include "cl_common.h"

#if !defined(STRICT_ALIGNMENT) && !defined(PEDANTIC)
# define STRICT_ALIGNMENT 0
#endif

void AES_cbc_encrypt(
        const unsigned char *in, 
        unsigned char *out,
        size_t length,
        const AES_KEY *keys,
        unsigned char *ivec,
        const int enc)
{
    DIE(cl_check_init() == false, "OpenCL could not be init");
    
    cl_int ret;

    cl_mem in_device;
    cl_mem output_device;
    cl_mem keys_device;
    cl_mem ivec_device;

    cl_uint num_keys = 1;
    cl_uint sample_len = 0;
    cl_mem samples_device;

    in_device = clCreateBuffer(context, CL_MEM_READ_WRITE, BLOCK_SIZE, NULL, &ret);
    CL_ERR( ret );

    size_t ctx_size = sizeof(AES_KEY) * num_keys;
    keys_device = clCreateBuffer(context, CL_MEM_READ_WRITE, ctx_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, keys_device, CL_TRUE, 0, ctx_size, keys, 0, NULL, NULL));

    size_t ivec_size = AES_BLOCK_SIZE * num_keys;
    ivec_device = clCreateBuffer(context, CL_MEM_READ_WRITE, ivec_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, ivec_device, CL_TRUE, 0, ivec_size, ivec, 0, NULL, NULL));

    size_t output_size = (size_t)num_keys * (size_t)BLOCK_SIZE;
    output_device = clCreateBuffer(context, CL_MEM_READ_WRITE, output_size, NULL, &ret);
    CL_ERR( ret );

    size_t num_threads_per_block = 256;
    size_t num_blocks = (num_keys + num_threads_per_block - 1) / num_threads_per_block;

    perftime_t start, end;

    get_time(&start);

    ssize_t slength = length;

    for (uint32_t i = 0;; i++) {

        size_t size = std::min(slength, (ssize_t)BLOCK_SIZE);
        CL_ERR( clEnqueueWriteBuffer(cmd_queue, in_device, CL_TRUE, 0, size, in, 0, NULL, NULL));

        /* set OpenCL kernel argument */
        cl_uint block_i = i * BLOCK_SIZE;


        /*
        __kernel void AES_cbc_encrypt_kernel(
            __global unsigned char *in,
            __global unsigned char *out,
            uint32_t len,
            __global AES_KEY *key,
            __global unsigned char *ivec,
            const int enc)
        */
        CL_ERR( clSetKernelArg(AES_cbc_encrypt_kernel, 0, sizeof(cl_mem), (void *)&in_device) );
        CL_ERR( clSetKernelArg(AES_cbc_encrypt_kernel, 1, sizeof(cl_mem), (void *)&output_device) );
        CL_ERR( clSetKernelArg(AES_cbc_encrypt_kernel, 2, sizeof(cl_uint), (void *)&size) );
        CL_ERR( clSetKernelArg(AES_cbc_encrypt_kernel, 3, sizeof(cl_mem), (void *)&keys_device) );
        CL_ERR( clSetKernelArg(AES_cbc_encrypt_kernel, 4, sizeof(cl_mem), (void *)&ivec_device) );
        CL_ERR( clSetKernelArg(AES_cbc_encrypt_kernel, 5, sizeof(cl_uint), (void *)&enc) );

        size_t globalSize[2] = {num_blocks * num_threads_per_block, 0};
        size_t localSize[2] = {num_threads_per_block, 0};    
        ret = clEnqueueNDRangeKernel(cmd_queue, AES_cbc_encrypt_kernel, 1, NULL,
            globalSize, localSize, 0, NULL, NULL);
            CL_ERR( ret );

        slength -= BLOCK_SIZE;
        in += BLOCK_SIZE;
        out += BLOCK_SIZE;
        if (slength <= 0) {
            break;
        }
    }

    CL_ERR( clEnqueueReadBuffer(cmd_queue, ivec_device, CL_TRUE, 0, ivec_size, ivec, 0, NULL, NULL));
}

void AES_cbc_encrypt_many(const unsigned char *in, unsigned char *out,
                          size_t length, const AES_KEY *keys,
                          unsigned char *ivec,
                          uint32_t num_keys,
                          float* time_us)
{
    if (length < BLOCK_SIZE) {
        printf("ERROR! block size(%d) > length(%zu)\n", BLOCK_SIZE, length);
        return;
    }

    DIE(cl_check_init() == false, "OpenCL could not be init");
    
    cl_int ret;

    cl_mem in_device;
    cl_mem keys_device;
    cl_mem output_device;
    cl_mem ivec_device;

    cl_mem sha_state_device;

    cl_uint sample_len = 0;
    cl_mem samples_device;

    in_device = clCreateBuffer(context, CL_MEM_READ_WRITE, BLOCK_SIZE, NULL, &ret);
    CL_ERR( ret );

    size_t ctx_size = sizeof(AES_KEY) * num_keys;
    keys_device = clCreateBuffer(context, CL_MEM_READ_WRITE, ctx_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, keys_device, CL_TRUE, 0, ctx_size, keys, 0, NULL, NULL));

    size_t ivec_size = AES_BLOCK_SIZE * num_keys;
    ivec_device = clCreateBuffer(context, CL_MEM_READ_WRITE, ivec_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, ivec_device, CL_TRUE, 0, ivec_size, ivec, 0, NULL, NULL));

    size_t output_size = (size_t)num_keys * (size_t)BLOCK_SIZE;
    output_device = clCreateBuffer(context, CL_MEM_READ_WRITE, output_size, NULL, &ret);
    CL_ERR( ret );

    size_t num_threads_per_block = 256;
    size_t num_blocks = (num_keys + num_threads_per_block - 1) / num_threads_per_block;

    perftime_t start, end;

    get_time(&start);

    ssize_t slength = length;

    for (uint32_t i = 0;; i++) {

        size_t size = std::min(slength, (ssize_t)BLOCK_SIZE);
        CL_ERR( clEnqueueWriteBuffer(cmd_queue, in_device, CL_TRUE, 0, size, in, 0, NULL, NULL));

        /* set OpenCL kernel argument */
        cl_uint block_i = i * BLOCK_SIZE;


        /* __kernel void CRYPTO_cbc128_encrypt_kernel(__global unsigned char* input, 
                                            __global unsigned char* output,
                                            uint32_t length,
                                            __global AES_KEY* keys,
                                            __global unsigned char* ivec,
                                            uint32_t num_keys,
                                            __global unsigned char* sha_state,
                                            __global uint32_t* sample_idx,
                                            uint32_t sample_len,
                                            uint32_t block_offset)
        */
        CL_ERR( clSetKernelArg(CRYPTO_cbc128_encrypt_kernel, 0, sizeof(cl_mem), (void *)&in_device) );
        CL_ERR( clSetKernelArg(CRYPTO_cbc128_encrypt_kernel, 1, sizeof(cl_mem), (void *)&output_device) );
        CL_ERR( clSetKernelArg(CRYPTO_cbc128_encrypt_kernel, 2, sizeof(cl_uint), (void *)&size) );
        CL_ERR( clSetKernelArg(CRYPTO_cbc128_encrypt_kernel, 3, sizeof(cl_mem), (void *)&keys_device) );
        CL_ERR( clSetKernelArg(CRYPTO_cbc128_encrypt_kernel, 4, sizeof(cl_mem), (void *)&ivec_device) );
        CL_ERR( clSetKernelArg(CRYPTO_cbc128_encrypt_kernel, 5, sizeof(cl_uint), (void *)&num_keys) );
        CL_ERR( clSetKernelArg(CRYPTO_cbc128_encrypt_kernel, 6, sizeof(cl_mem), (void *)&sha_state_device) );
        CL_ERR( clSetKernelArg(CRYPTO_cbc128_encrypt_kernel, 7, sizeof(cl_mem), (void *)&samples_device) );
        CL_ERR( clSetKernelArg(CRYPTO_cbc128_encrypt_kernel, 8, sizeof(cl_uint), (void *)&sample_len) );
        CL_ERR( clSetKernelArg(CRYPTO_cbc128_encrypt_kernel, 9, sizeof(cl_uint), (void *)&block_i ) );

        size_t globalSize[2] = {num_blocks * num_threads_per_block, 0};
        size_t localSize[2] = {num_threads_per_block, 0};    
        ret = clEnqueueNDRangeKernel(cmd_queue, CRYPTO_cbc128_encrypt_kernel, 1, NULL,
            globalSize, localSize, 0, NULL, NULL);
            CL_ERR( ret );

        slength -= BLOCK_SIZE;
        in += BLOCK_SIZE;
        if (slength <= 0) {
            break;
        }
    }

    CL_ERR( clEnqueueReadBuffer(cmd_queue, ivec_device, CL_TRUE, 0, ivec_size, ivec, 0, NULL, NULL));

    get_time(&end);
    *time_us = get_diff(&start, &end);

    printf("gpu time: %f us\n", get_diff(&start, &end));
}


