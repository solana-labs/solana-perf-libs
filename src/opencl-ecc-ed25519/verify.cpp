#include "sha512.h"
#include <algorithm>
#include <stdio.h>
#include "ge.cu"
#include "sc.cu"
#include "fe.cu"
#include "seed.cu"
#include "keypair.cu"
#include "sign.cu"
#include "sha512.cu"

#include "ed25519.h"
#include <pthread.h>

#include "gpu_common.h"

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

typedef struct {
    cl_mem packets;
    cl_mem out;
    cl_mem public_key_offsets;
    cl_mem message_start_offsets;
    cl_mem signature_offsets;
    cl_mem message_lens;

    size_t num;
    size_t num_signatures;
    uint32_t total_packets_len;
    pthread_mutex_t mutex;

    //cudaStream_t stream;
} gpu_ctx;

static pthread_mutex_t g_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

#define MAX_NUM_GPUS 8
#define MAX_QUEUE_SIZE 8

static gpu_ctx g_gpu_ctx[MAX_NUM_GPUS][MAX_QUEUE_SIZE] = {0};
static uint32_t g_cur_gpu = 0;
static uint32_t g_cur_queue[MAX_NUM_GPUS] = {0};
static int32_t g_total_gpus = -1;
bool g_verbose = false;

void ed25519_set_verbose(bool val) {
    g_verbose = val;
}

static bool ed25519_init_locked() {
	
	/*
    if (g_total_gpus == -1) {
        cudaGetDeviceCount(&g_total_gpus);
        g_total_gpus = min(MAX_NUM_GPUS, g_total_gpus);
        LOG("total_gpus: %d\n", g_total_gpus);
        for (int gpu = 0; gpu < g_total_gpus; gpu++) {
            CUDA_CHK(cudaSetDevice(gpu));
            for (int queue = 0; queue < MAX_QUEUE_SIZE; queue++) {
                int err = pthread_mutex_init(&g_gpu_ctx[gpu][queue].mutex, NULL);
                if (err != 0) {
                    fprintf(stderr, "pthread_mutex_init error %d gpu: %d queue: %d\n",
                            err, gpu, queue);
                    g_total_gpus = 0;
                    return false;
                }
                CUDA_CHK(cudaStreamCreate(&g_gpu_ctx[gpu][queue].stream));
            }
        }
    } */
	
	// TODO hardcoded OpenCL current support
	g_total_gpus = 1;
	
    return g_total_gpus > 0;
}

bool ed25519_init() {
    //cudaFree(0);
    pthread_mutex_lock(&g_ctx_mutex);
    bool success = ed25519_init_locked();
    pthread_mutex_unlock(&g_ctx_mutex);
    return success;
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
    size_t offsets_size = total_signatures * sizeof(uint32_t);

    uint32_t total_packets_len = total_packets * message_size;

    if (0 == total_packets) {
        return;
    }

    int32_t cur_gpu, cur_queue;

    LOG("device allocate. packets: %d out: %d offsets_size: %zu\n",
        total_packets_len, (int)out_size, offsets_size);
    // Device allocate

    pthread_mutex_lock(&g_ctx_mutex);
    if (!ed25519_init_locked()) {
        pthread_mutex_unlock(&g_ctx_mutex);
        LOG("No GPUs, exiting...\n");
        return;
    }
    cur_gpu = g_cur_gpu;
    g_cur_gpu++;
    g_cur_gpu %= g_total_gpus;
    cur_queue = g_cur_queue[cur_gpu];
    g_cur_queue[cur_gpu]++;
    g_cur_queue[cur_gpu] %= MAX_QUEUE_SIZE;
    pthread_mutex_unlock(&g_ctx_mutex);

    gpu_ctx* cur_ctx = &g_gpu_ctx[cur_gpu][cur_queue];
    pthread_mutex_lock(&cur_ctx->mutex);

    //CUDA_CHK(cudaSetDevice(cur_gpu));

    LOG("cur gpu: %d cur queue: %d\n", cur_gpu, cur_queue);

    if (total_packets_len > cur_ctx->total_packets_len) {
		// TODO OpenCL fix memory leak
		//CL_ERR(clReleaseMemObject(cur_ctx->packets));
		cur_ctx->packets = clCreateBuffer(context, CL_MEM_READ_WRITE, total_packets_len, NULL, &ret);
		CL_ERR( ret );

        cur_ctx->total_packets_len = total_packets_len;
    }

    if (cur_ctx->num < total_signatures) {
		// TODO OpenCL fix memory leak
		//CL_ERR(clReleaseMemObject(cur_ctx->out));
		cur_ctx->out = clCreateBuffer(context, CL_MEM_READ_WRITE, out_size, NULL, &ret);
		CL_ERR( ret );

        cur_ctx->num = total_signatures;
    }

    if (cur_ctx->num_signatures < total_signatures) {
		// TODO OpenCL fix memory leaks
		//CL_ERR(clReleaseMemObject(cur_ctx->public_key_offsets));
		cur_ctx->public_key_offsets = clCreateBuffer(context, CL_MEM_READ_WRITE, offsets_size, NULL, &ret);
		CL_ERR( ret );
		
		//CL_ERR(clReleaseMemObject(cur_ctx->signature_offsets));
		cur_ctx->signature_offsets = clCreateBuffer(context, CL_MEM_READ_WRITE, offsets_size, NULL, &ret);
		CL_ERR( ret );
		
		//CL_ERR(clReleaseMemObject(cur_ctx->message_start_offsets));
		cur_ctx->message_start_offsets = clCreateBuffer(context, CL_MEM_READ_WRITE, offsets_size, NULL, &ret);
		CL_ERR( ret );
		
		//CL_ERR(clReleaseMemObject(cur_ctx->message_lens));
		cur_ctx->message_lens = clCreateBuffer(context, CL_MEM_READ_WRITE, offsets_size, NULL, &ret);
		CL_ERR( ret );

        cur_ctx->num_signatures = total_signatures;
    }

    //cudaStream_t stream = 0;
    //if (0 != use_non_default_stream) {
    //    stream = cur_ctx->stream;
    //}
	
	CL_ERR( clEnqueueWriteBuffer(cmd_queue, cur_ctx->public_key_offsets, CL_TRUE, 0, offsets_size, public_key_offsets, 0, NULL, NULL));
	CL_ERR( clEnqueueWriteBuffer(cmd_queue, cur_ctx->signature_offsets, CL_TRUE, 0, offsets_size, signature_offsets, 0, NULL, NULL));
	CL_ERR( clEnqueueWriteBuffer(cmd_queue, cur_ctx->message_start_offsets, CL_TRUE, 0, offsets_size, message_start_offsets, 0, NULL, NULL));
	CL_ERR( clEnqueueWriteBuffer(cmd_queue, cur_ctx->message_lens, CL_TRUE, 0, offsets_size, message_lens, 0, NULL, NULL));

    size_t cur = 0;
    for (size_t i = 0; i < num_elems; i++) {
        LOG("i: %zu size: %d\n", i, elems[i].num * message_size);
        CL_ERR( clEnqueueReadBuffer(cmd_queue, cur_ctx->packets, CL_TRUE, cur * message_size, elems[i].num * message_size, elems[i].elems, 0, NULL, NULL));
		cur += elems[i].num;
    }

    size_t num_threads_per_block = 64;
    size_t num_blocks = ROUND_UP_DIV(total_signatures, num_threads_per_block) * num_threads_per_block;
    LOG("num_blocks: %d threads_per_block: %d keys: %d out: %p\n",
           num_blocks, num_threads_per_block, (int)total_packets, out);

    perftime_t start, end;
    get_time(&start);							 
							 
	CL_ERR( clSetKernelArg(ed25519_verify_kernel, 0, sizeof(cl_mem), (void *)&cur_ctx->packets) );
	CL_ERR( clSetKernelArg(ed25519_verify_kernel, 1, sizeof(cl_uint), (void *)&message_size) );
	CL_ERR( clSetKernelArg(ed25519_verify_kernel, 2, sizeof(cl_mem), (void *)&cur_ctx->message_lens) );
	CL_ERR( clSetKernelArg(ed25519_verify_kernel, 3, sizeof(cl_mem), (void *)&cur_ctx->public_key_offsets) );
	CL_ERR( clSetKernelArg(ed25519_verify_kernel, 4, sizeof(cl_mem), (void *)&cur_ctx->signature_offsets) );
	CL_ERR( clSetKernelArg(ed25519_verify_kernel, 5, sizeof(cl_mem), (void *)&cur_ctx->message_start_offsets) );
	CL_ERR( clSetKernelArg(ed25519_verify_kernel, 6, sizeof(cl_uint), (void *)&cur_ctx->num_signatures) );
	CL_ERR( clSetKernelArg(ed25519_verify_kernel, 7, sizeof(cl_mem), (void *)&cur_ctx->out) );

	size_t globalSize[2] = {num_blocks, 0};
	size_t localSize[2] = {num_threads_per_block, 0};	
	ret = clEnqueueNDRangeKernel(cmd_queue, ed25519_verify_kernel, 1, NULL,
		globalSize, localSize, 0, NULL, NULL);
		CL_ERR( ret );
    //CUDA_CHK(cudaPeekAtLastError());

	CL_ERR( clEnqueueReadBuffer(cmd_queue, cur_ctx->out, CL_TRUE, 0, out_size, out, 0, NULL, NULL));
		
	//if (err != cudaSuccess)  {
    //    fprintf(stderr, "cudaMemcpy(out) error: out = %p cur_ctx->out = %p size = %zu num: %d elems = %p\n",
    //                    out, cur_ctx->out, out_size, num_elems, elems);
    //}
    //CUDA_CHK(err);

    //CUDA_CHK(cudaStreamSynchronize(stream));

    pthread_mutex_unlock(&cur_ctx->mutex);

    get_time(&end);
    LOG("time diff: %f\n", get_diff(&start, &end));
}

void ed25519_free_gpu_mem() {
	
	gpu_ctx* cur_ctx = &g_gpu_ctx[0][0];
	
	CL_ERR(clReleaseMemObject(cur_ctx->packets));
	CL_ERR(clReleaseMemObject(cur_ctx->out));
	CL_ERR(clReleaseMemObject(cur_ctx->message_lens));
	CL_ERR(clReleaseMemObject(cur_ctx->public_key_offsets));
	CL_ERR(clReleaseMemObject(cur_ctx->signature_offsets));
	CL_ERR(clReleaseMemObject(cur_ctx->message_start_offsets));
}

// Ensure copyright and license notice is embedded in the binary
const char* ed25519_license() {
   return "Copyright (c) 2018 Solana Labs, Inc. "
          "Licensed under the Apache License, Version 2.0 "
          "<http://www.apache.org/licenses/LICENSE-2.0>";
}

int cuda_host_register(void* ptr, size_t size, unsigned int flags) {
	//return cudaHostRegister(ptr, size, flags);
	return -1;
}

int cuda_host_unregister(void* ptr) {
	//return cudaHostUnregister(ptr);
	return -1;
}
