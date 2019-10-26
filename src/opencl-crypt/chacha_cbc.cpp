#include "common.h"
#include "chacha.h"
#include "modes_lcl.h"
#include "perftime.h"
#include <algorithm>
#include <cstring>
#include <assert.h>

using namespace std;

#if !defined(STRICT_ALIGNMENT) && !defined(PEDANTIC)
# define STRICT_ALIGNMENT 0
#endif

#include <sha256.cu>
#include "cl_common.h"

void chacha20_ctr_encrypt(
            const uint8_t *in, 
            uint8_t *out, 
            size_t in_len,
            const uint8_t key[CHACHA_KEY_SIZE], 
            const uint8_t nonce[CHACHA_NONCE_SIZE],
            uint32_t counter)
{
    DIE(cl_check_init() == false, "OpenCL could not be init");
    
    cl_int ret;

    cl_mem in_device;
    cl_mem out_device;
    cl_mem key_device;
    cl_mem nonce_device;
    
    in_device = clCreateBuffer(context, CL_MEM_READ_WRITE, in_len, NULL, &ret);
    CL_ERR( ret );
    
    out_device = clCreateBuffer(context, CL_MEM_READ_WRITE, in_len, NULL, &ret);
    CL_ERR( ret );
    
    key_device = clCreateBuffer(context, CL_MEM_READ_WRITE, CHACHA_KEY_SIZE, NULL, &ret);
    CL_ERR( ret );

    nonce_device = clCreateBuffer(context, CL_MEM_READ_WRITE, CHACHA_NONCE_SIZE, NULL, &ret);
    CL_ERR( ret );
    
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, in_device, CL_TRUE, 0, in_len, in, 0, NULL, NULL));
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, key_device, CL_TRUE, 0, CHACHA_KEY_SIZE, key, 0, NULL, NULL));
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, nonce_device, CL_TRUE, 0, CHACHA_NONCE_SIZE, nonce, 0, NULL, NULL));
    /*
    __kernel void chacha20_ctr_encrypt_kernel(
                __global const uint8_t *in, 
                __global uint8_t *out, 
                uint32_t in_len,
                __global const uint8_t key[CHACHA_KEY_SIZE],
                __global const uint8_t nonce[CHACHA_NONCE_SIZE],
                uint32_t counter)
    */
    CL_ERR( clSetKernelArg(chacha20_ctr_encrypt_kernel, 0, sizeof(cl_mem), (void *)&in_device) );
    CL_ERR( clSetKernelArg(chacha20_ctr_encrypt_kernel, 1, sizeof(cl_mem), (void *)&out_device) );
    CL_ERR( clSetKernelArg(chacha20_ctr_encrypt_kernel, 2, sizeof(cl_uint), (void *)&in_len) );
    CL_ERR( clSetKernelArg(chacha20_ctr_encrypt_kernel, 3, sizeof(cl_mem), (void *)&key_device) );
    CL_ERR( clSetKernelArg(chacha20_ctr_encrypt_kernel, 4, sizeof(cl_mem), (void *)&nonce_device) );
    CL_ERR( clSetKernelArg(chacha20_ctr_encrypt_kernel, 5, sizeof(cl_uint), (void *)&counter) );
    
    size_t num_threads_per_block = 64;
    size_t num_blocks = ROUND_UP_DIV(1, num_threads_per_block);
    
    size_t globalSize[2] = {num_blocks * num_threads_per_block, 0};
    size_t localSize[2] = {num_threads_per_block, 0};    
    ret = clEnqueueNDRangeKernel(cmd_queue, chacha20_ctr_encrypt_kernel, 1, NULL,
        globalSize, localSize, 0, NULL, NULL);
        CL_ERR( ret );

    CL_ERR( clEnqueueReadBuffer(cmd_queue, out_device, CL_TRUE, 0, in_len, out, 0, NULL, NULL));
}


void chacha20_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                          const uint8_t key[CHACHA_KEY_SIZE], uint8_t* ivec)
{
    DIE(cl_check_init() == false, "OpenCL could not be init");
    
    cl_int ret;

    cl_mem in_device;
    cl_mem keys_device;
    cl_mem out_device;
    cl_mem ivec_device;

    in_device = clCreateBuffer(context, CL_MEM_READ_WRITE, BLOCK_SIZE, NULL, &ret);
    CL_ERR( ret );

    size_t keys_size = CHACHA_KEY_SIZE;
    keys_device = clCreateBuffer(context, CL_MEM_READ_WRITE, keys_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, keys_device, CL_TRUE, 0, keys_size, key, 0, NULL, NULL));

    size_t ivec_size = CHACHA_BLOCK_SIZE;
    ivec_device = clCreateBuffer(context, CL_MEM_READ_WRITE, ivec_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, ivec_device, CL_TRUE, 0, ivec_size, ivec, 0, NULL, NULL));

    size_t out_size = (size_t)BLOCK_SIZE;
    out_device = clCreateBuffer(context, CL_MEM_READ_WRITE, out_size, NULL, &ret);
    CL_ERR( ret );

    size_t num_threads_per_block = 64;
    size_t num_blocks = ROUND_UP_DIV(1, num_threads_per_block);
    
    uint32_t num_keys = 1;

    perftime_t start, end;

    get_time(&start);

    ssize_t slength = length;

    for (uint32_t i = 0;; i++) {
        
        size_t size = std::min(slength, (ssize_t)BLOCK_SIZE);
        CL_ERR( clEnqueueWriteBuffer(cmd_queue, in_device, CL_TRUE, 0, size, in, 0, NULL, NULL));

        /* set OpenCL kernel argument */
        cl_int block_i = i * BLOCK_SIZE;
        
        /*
        __kernel void chacha20_cbc128_encrypt_kernel(
                    __global const unsigned char* input, 
                    __global unsigned char* output,
                    uint32_t length,
                    __global const uint8_t* keys,
                    __global unsigned char* ivec,
                    uint32_t num_keys)
        */
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_kernel, 0, sizeof(cl_mem), (void *)&in_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_kernel, 1, sizeof(cl_mem), (void *)&out_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_kernel, 2, sizeof(cl_uint), (void *)&size) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_kernel, 3, sizeof(cl_mem), (void *)&keys_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_kernel, 4, sizeof(cl_mem), (void *)&ivec_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_kernel, 5, sizeof(cl_uint), (void *)&num_keys) );
        
        size_t globalSize[2] = {num_blocks * num_threads_per_block, 0};
        size_t localSize[2] = {num_threads_per_block, 0};    
        ret = clEnqueueNDRangeKernel(cmd_queue, chacha20_cbc128_encrypt_kernel, 1, NULL,
            globalSize, localSize, 0, NULL, NULL);
            CL_ERR( ret );

        CL_ERR( clEnqueueReadBuffer(cmd_queue, out_device, CL_TRUE, 0, size, out, 0, NULL, NULL));

        slength -= BLOCK_SIZE;
        in += BLOCK_SIZE;
        out += BLOCK_SIZE;

        if (slength <= 0) {
            break;
        }
    }

    CL_ERR( clEnqueueReadBuffer(cmd_queue, ivec_device, CL_TRUE, 0, ivec_size, ivec, 0, NULL, NULL));
}

void chacha_cbc_encrypt_many(const unsigned char *in, unsigned char *out,
                             size_t length, const uint8_t *keys,
                             uint8_t* ivec,
                             uint32_t num_keys,
                             float* time_us)
{
    DIE(cl_check_init() == false, "OpenCL could not be init");
    
    cl_int ret;

    if (length < BLOCK_SIZE) {
        printf("ERROR! block size(%d) > length(%zu)\n", BLOCK_SIZE, length);
        return;
    }
    cl_mem in_device;
    cl_mem keys_device;
    cl_mem out_device;
    cl_mem ivec_device;

    in_device = clCreateBuffer(context, CL_MEM_READ_WRITE, BLOCK_SIZE, NULL, &ret);
    CL_ERR( ret );

    size_t keys_size = CHACHA_KEY_SIZE * num_keys;
    keys_device = clCreateBuffer(context, CL_MEM_READ_WRITE, keys_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, keys_device, CL_TRUE, 0, keys_size, keys, 0, NULL, NULL));

    size_t ivec_size = CHACHA_BLOCK_SIZE * num_keys;
    ivec_device = clCreateBuffer(context, CL_MEM_READ_WRITE, ivec_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, ivec_device, CL_TRUE, 0, ivec_size, ivec, 0, NULL, NULL));

    size_t output_size = (size_t)num_keys * (size_t)BLOCK_SIZE;
    out_device = clCreateBuffer(context, CL_MEM_READ_WRITE, output_size, NULL, &ret);
    CL_ERR( ret );

    size_t num_threads_per_block = 64;
    size_t num_blocks = ROUND_UP_DIV(num_keys, num_threads_per_block);

    perftime_t start, end;

    get_time(&start);

    ssize_t slength = length;

    for (uint32_t i = 0;; i++) {
        
        size_t size = std::min(slength, (ssize_t)BLOCK_SIZE);
        CL_ERR( clEnqueueWriteBuffer(cmd_queue, in_device, CL_TRUE, 0, size, in, 0, NULL, NULL));

        /* set OpenCL kernel argument */
        cl_int block_i = i * BLOCK_SIZE;
        
        /*
        __kernel void chacha20_cbc128_encrypt_kernel(
                    __global const unsigned char* input, 
                    __global unsigned char* output,
                    uint32_t length,
                    __global const uint8_t* keys,
                    __global unsigned char* ivec,
                    uint32_t num_keys)
        */
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_kernel, 0, sizeof(cl_mem), (void *)&in_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_kernel, 1, sizeof(cl_mem), (void *)&out_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_kernel, 2, sizeof(cl_uint), (void *)&size) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_kernel, 3, sizeof(cl_mem), (void *)&keys_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_kernel, 4, sizeof(cl_mem), (void *)&ivec_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_kernel, 5, sizeof(cl_uint), (void *)&num_keys) );
        
        size_t globalSize[2] = {num_blocks * num_threads_per_block, 0};
        size_t localSize[2] = {num_threads_per_block, 0};    
        ret = clEnqueueNDRangeKernel(cmd_queue, chacha20_cbc128_encrypt_kernel, 1, NULL,
            globalSize, localSize, 0, NULL, NULL);
            CL_ERR( ret );

        CL_ERR( clEnqueueReadBuffer(cmd_queue, out_device, CL_TRUE, 0, size, out, 0, NULL, NULL));

        slength -= BLOCK_SIZE;
        in += BLOCK_SIZE;
        out += BLOCK_SIZE;
        
        if (slength <= 0) {
            break;
        }
    }

    CL_ERR( clEnqueueReadBuffer(cmd_queue, ivec_device, CL_TRUE, 0, ivec_size, ivec, 0, NULL, NULL));

    get_time(&end);
    *time_us = get_diff(&start, &end);

    //printf("gpu time: %f us\n", get_diff(&start, &end));
}

void chacha_init_sha_state(void* sha_state_arg, uint32_t num_keys)
{
    DIE(cl_check_init() == false, "OpenCL could not be init");
    
    int ret;
    
    LOG("sizeof(hash_state) %zu\n", sizeof(hash_state));
    hash_state* sha_state = (hash_state*)sha_state_arg;
    cl_mem sha_state_device = NULL;
    
    size_t sha_state_size = num_keys * sizeof(hash_state);
    sha_state_device = clCreateBuffer(context, CL_MEM_READ_WRITE, sha_state_size, NULL, &ret);
    CL_ERR( ret );

    size_t num_threads_per_block = 64;
    size_t num_blocks = ROUND_UP_DIV(num_keys, num_threads_per_block);
    
    /*
    __kernel void init_sha256_state_kernel(
            __global hash_state* sha_state, 
            uint32_t num_keys)
    */
    CL_ERR( clSetKernelArg(init_sha256_state_kernel, 0, sizeof(cl_mem), (void *)&sha_state_device) );
    CL_ERR( clSetKernelArg(init_sha256_state_kernel, 1, sizeof(cl_uint), (void *)&num_keys) );
    
    size_t globalSize[2] = {num_blocks * num_threads_per_block, 0};
    size_t localSize[2] = {num_threads_per_block, 0};    
    ret = clEnqueueNDRangeKernel(cmd_queue, init_sha256_state_kernel, 1, NULL,
        globalSize, localSize, 0, NULL, NULL);
        CL_ERR( ret );

    CL_ERR( clEnqueueReadBuffer(cmd_queue, sha_state_device, CL_TRUE, 0, sha_state_size, sha_state, 0, NULL, NULL));

    CL_ERR(clReleaseMemObject(sha_state_device));

}

void chacha_end_sha_state(const void* sha_state_arg, uint8_t* out, uint32_t num_keys)
{
    DIE(cl_check_init() == false, "OpenCL could not be init");
    
    int ret;
    
    const hash_state* sha_state = (const hash_state*)sha_state_arg;
    cl_mem out_device;
    cl_mem sha_state_device;
    size_t sha_state_size = num_keys * sizeof(hash_state);
    
    sha_state_device = clCreateBuffer(context, CL_MEM_READ_WRITE, sha_state_size, NULL, &ret);
    CL_ERR( ret );

    size_t out_size = SHA256_BLOCK_SIZE * num_keys;
    out_device = clCreateBuffer(context, CL_MEM_READ_WRITE, sha_state_size, NULL, &ret);
    CL_ERR( ret );
    
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, sha_state_device, CL_TRUE, 0, sha_state_size, sha_state, 0, NULL, NULL));

    size_t num_threads_per_block = 64;
    size_t num_blocks = ROUND_UP_DIV(num_keys, num_threads_per_block);
    
    /*
    __kernel void end_sha256_state_kernel(
            __global hash_state* sha_state,
            __global uint8_t* out_state, 
            uint32_t num_keys) 
    */
    CL_ERR( clSetKernelArg(end_sha256_state_kernel, 0, sizeof(cl_mem), (void *)&sha_state_device) );
    CL_ERR( clSetKernelArg(end_sha256_state_kernel, 1, sizeof(cl_mem), (void *)&out_device) );
    CL_ERR( clSetKernelArg(end_sha256_state_kernel, 2, sizeof(cl_uint), (void *)&num_keys) );
    
    size_t globalSize[2] = {num_blocks * num_threads_per_block, 0};
    size_t localSize[2] = {num_threads_per_block, 0};    
    ret = clEnqueueNDRangeKernel(cmd_queue, end_sha256_state_kernel, 1, NULL,
        globalSize, localSize, 0, NULL, NULL);
        CL_ERR( ret );

    CL_ERR( clEnqueueReadBuffer(cmd_queue, out_device, CL_TRUE, 0, out_size, out, 0, NULL, NULL));

    CL_ERR(clReleaseMemObject(sha_state_device));
    CL_ERR(clReleaseMemObject(out_device));
}

void chacha_cbc_encrypt_many_sample(const uint8_t* in,
                                    void* sha_state_arg,
                                    size_t length,
                                    const uint8_t* keys,
                                    uint8_t* ivecs,
                                    uint32_t num_keys,
                                    const uint64_t* samples,
                                    uint32_t num_samples,
                                    uint64_t starting_block_offset,
                                    float* time_us)
{
    DIE(cl_check_init() == false, "OpenCL could not be init");
    
    cl_int ret;

    hash_state* sha_state = (hash_state*)sha_state_arg;
    LOG("encrypt_many_sample in: %p len: %zu\n", in, length);
    LOG("    ivecs: %p num_keys: %d\n", ivecs, num_keys);

    cl_mem in_device;
    cl_mem keys_device;
    cl_mem out_device;
    cl_mem ivec_device;

    cl_mem sha_state_device;
    cl_mem samples_device;

    LOG("samples:");
    for (uint32_t i = 0; i < num_samples; i++) {
        LOG("%ld ", samples[i]);
    }
    LOG("\n");

    size_t samples_size = sizeof(uint64_t) * num_samples;
    samples_device = clCreateBuffer(context, CL_MEM_READ_WRITE, samples_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, samples_device, CL_TRUE, 0, samples_size, samples, 0, NULL, NULL));

    in_device = clCreateBuffer(context, CL_MEM_READ_WRITE, BLOCK_SIZE, NULL, &ret);
    CL_ERR( ret );

    size_t keys_size = CHACHA_KEY_SIZE * num_keys;
    keys_device = clCreateBuffer(context, CL_MEM_READ_WRITE, keys_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, keys_device, CL_TRUE, 0, keys_size, keys, 0, NULL, NULL));

    size_t ivec_size = CHACHA_BLOCK_SIZE * num_keys;
    ivec_device = clCreateBuffer(context, CL_MEM_READ_WRITE, ivec_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, ivec_device, CL_TRUE, 0, ivec_size, ivecs, 0, NULL, NULL));

    size_t output_size = (size_t)num_keys * (size_t)BLOCK_SIZE;
    out_device = clCreateBuffer(context, CL_MEM_READ_WRITE, output_size, NULL, &ret);
    CL_ERR( ret );

    size_t sha_state_size = num_keys * sizeof(hash_state);
    sha_state_device = clCreateBuffer(context, CL_MEM_READ_WRITE, sha_state_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, sha_state_device, CL_TRUE, 0, sha_state_size, sha_state, 0, NULL, NULL));

    size_t num_threads_per_block = 64;
    size_t num_blocks = ROUND_UP_DIV(num_keys, num_threads_per_block);

    perftime_t start, end;

    get_time(&start);

    ssize_t slength = length;
    size_t num_data_blocks = std::max(1ul, (length + BLOCK_SIZE - 1) / (BLOCK_SIZE));

    LOG("ivecs:\n");
    for (size_t nkey = 0; nkey < num_keys; nkey++) {
        LOG("ivec: %zu:\n", nkey);
        for (size_t i = 0; i < CHACHA_BLOCK_SIZE; i++) {
            LOG("%d ", ivecs[nkey * CHACHA_BLOCK_SIZE + i]);
        }
        LOG("\n");
    }
    LOG("\n");

    for (uint32_t i = 0;; i++) {

        size_t size = std::min(slength, (ssize_t)BLOCK_SIZE);
        LOG("copying to in_device: %p in: %p size: %zu num_data_blocks: %zu\n", in_device, in, size, num_data_blocks);
        
        CL_ERR( clEnqueueWriteBuffer(cmd_queue, in_device, CL_TRUE, 0, size, in, 0, NULL, NULL));

        LOG("done copying to in_device\n");

        /* set OpenCL kernel argument */
        cl_int block_i = i * BLOCK_SIZE + starting_block_offset;

        /*
        __kernel void chacha20_cbc128_encrypt_sample_kernel(
                    __global const uint8_t* input,
                    __global uint8_t* output,
                    uint32_t length,
                    __global const uint8_t* keys,
                    __global uint8_t* ivec,
                    uint32_t num_keys,
                    __global hash_state* sha_state,
                    __global uint64_t* sample_idx,
                    uint32_t sample_len,
                    uint64_t block_offset)
        */
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_sample_kernel, 0, sizeof(cl_mem), (void *)&in_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_sample_kernel, 1, sizeof(cl_mem), (void *)&out_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_sample_kernel, 2, sizeof(cl_uint), (void *)&size) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_sample_kernel, 3, sizeof(cl_mem), (void *)&keys_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_sample_kernel, 4, sizeof(cl_mem), (void *)&ivec_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_sample_kernel, 5, sizeof(cl_uint), (void *)&num_keys) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_sample_kernel, 6, sizeof(cl_mem), (void *)&sha_state_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_sample_kernel, 7, sizeof(cl_mem), (void *)&samples_device) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_sample_kernel, 8, sizeof(cl_uint), (void *)&num_samples) );
        CL_ERR( clSetKernelArg(chacha20_cbc128_encrypt_sample_kernel, 9, sizeof(cl_ulong), (void *)&block_i ) );

        size_t globalSize[2] = {num_blocks * num_threads_per_block, 0};
        size_t localSize[2] = {num_threads_per_block, 0};    
        ret = clEnqueueNDRangeKernel(cmd_queue, chacha20_cbc128_encrypt_sample_kernel, 1, NULL,
            globalSize, localSize, 0, NULL, NULL);
            CL_ERR( ret );

        slength -= BLOCK_SIZE;
        in += BLOCK_SIZE;
        if (slength <= 0) {
            break;
        }
    }

    CL_ERR( clEnqueueReadBuffer(cmd_queue, ivec_device, CL_TRUE, 0, ivec_size, ivecs, 0, NULL, NULL));
    CL_ERR( clEnqueueReadBuffer(cmd_queue, sha_state_device, CL_TRUE, 0, sha_state_size, sha_state, 0, NULL, NULL));

    get_time(&end);
    *time_us = get_diff(&start, &end);

    //LOG("gpu time: %f us\n", get_diff(&start, &end));

    CL_ERR(clReleaseMemObject(samples_device));
    CL_ERR(clReleaseMemObject(in_device));
    CL_ERR(clReleaseMemObject(keys_device));
    CL_ERR(clReleaseMemObject(ivec_device));
    CL_ERR(clReleaseMemObject(out_device));
    CL_ERR(clReleaseMemObject(sha_state_device));
}



void chacha_ctr_encrypt_many(const unsigned char *in, unsigned char *out,
                             size_t length,
                             const uint8_t *keys,
                             const uint8_t* nonces,
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
    cl_mem out_device;
    cl_mem ivec_device;

    cl_mem nonces_device;
    cl_mem sha_state_device;

    uint32_t sample_len = 0;
    uint32_t* samples_device = NULL;

    in_device = clCreateBuffer(context, CL_MEM_READ_WRITE, BLOCK_SIZE, NULL, &ret);
    CL_ERR( ret );
    size_t keys_size = CHACHA_KEY_SIZE * num_keys;

    keys_device = clCreateBuffer(context, CL_MEM_READ_WRITE, keys_size, NULL, &ret);
    CL_ERR( ret );
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, keys_device, CL_TRUE, 0, keys_size, keys, 0, NULL, NULL));

    size_t nonces_size = CHACHA_NONCE_SIZE * num_keys;
    nonces_device = clCreateBuffer(context, CL_MEM_READ_WRITE, nonces_size, NULL, &ret);
    CL_ERR( ret );

    CL_ERR( clEnqueueWriteBuffer(cmd_queue, nonces_device, CL_TRUE, 0, nonces_size, nonces, 0, NULL, NULL));

    size_t output_size = (size_t)num_keys * (size_t)BLOCK_SIZE;
    out_device = clCreateBuffer(context, CL_MEM_READ_WRITE, output_size, NULL, &ret);
    CL_ERR( ret );

    size_t num_threads_per_block = 64;
    size_t num_blocks = ROUND_UP_DIV(num_keys, num_threads_per_block);

    perftime_t start, end;

    get_time(&start);

    ssize_t slength = length;
    size_t num_data_blocks = (length + BLOCK_SIZE - 1) / (BLOCK_SIZE);

    for (uint32_t i = 0;; i++) {

        size_t size = std::min(slength, (ssize_t)BLOCK_SIZE);

        CL_ERR( clEnqueueWriteBuffer(cmd_queue, in_device, CL_TRUE, 0, size, in, 0, NULL, NULL));

        cl_int block_i = i * BLOCK_SIZE;

        /*
        __kernel void chacha_ctr_encrypt_kernel(
                        __global const unsigned char* input,
                        __global unsigned char* output,
                        uint32_t length, 
                        __global const uint8_t* keys,
                        __global unsigned char* nonces, uint32_t num_keys,
                        __global unsigned char* sha_state,
                        __global uint32_t* sample_idx,
                        uint32_t sample_len,
                        uint32_t block_offset)
        */
        CL_ERR( clSetKernelArg(chacha_ctr_encrypt_kernel, 0, sizeof(cl_mem), (void *)&in_device) );
        CL_ERR( clSetKernelArg(chacha_ctr_encrypt_kernel, 1, sizeof(cl_mem), (void *)&out_device) );
        CL_ERR( clSetKernelArg(chacha_ctr_encrypt_kernel, 2, sizeof(cl_uint), (void *)&size) );
        CL_ERR( clSetKernelArg(chacha_ctr_encrypt_kernel, 3, sizeof(cl_mem), (void *)&keys_device) );
        CL_ERR( clSetKernelArg(chacha_ctr_encrypt_kernel, 4, sizeof(cl_mem), (void *)&nonces_device) );
        CL_ERR( clSetKernelArg(chacha_ctr_encrypt_kernel, 5, sizeof(cl_uint), (void *)&num_keys) );
        CL_ERR( clSetKernelArg(chacha_ctr_encrypt_kernel, 6, sizeof(cl_mem), (void *)&sha_state_device) );
        CL_ERR( clSetKernelArg(chacha_ctr_encrypt_kernel, 7, sizeof(cl_mem), (void *)&samples_device) );
        CL_ERR( clSetKernelArg(chacha_ctr_encrypt_kernel, 8, sizeof(cl_uint), (void *)&sample_len) );
        CL_ERR( clSetKernelArg(chacha_ctr_encrypt_kernel, 9, sizeof(cl_ulong), (void *)&block_i ) );

        size_t globalSize[2] = {num_blocks * num_threads_per_block, 0};
        size_t localSize[2] = {num_threads_per_block, 0};    
        ret = clEnqueueNDRangeKernel(cmd_queue, chacha_ctr_encrypt_kernel, 1, NULL,
            globalSize, localSize, 0, NULL, NULL);
            CL_ERR( ret );

        slength -= BLOCK_SIZE;
        in += BLOCK_SIZE;
        if (slength <= 0) {
            break;
        }
    }

    get_time(&end);
    *time_us = get_diff(&start, &end);

    //LOG("gpu time: %f us\n", get_diff(&start, &end));
}

