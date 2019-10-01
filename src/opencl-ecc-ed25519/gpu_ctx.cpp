#include "ed25519.h"
#include "gpu_ctx.h"
#include <pthread.h>
#include "gpu_common.h"

static pthread_mutex_t g_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

#define MAX_NUM_GPUS 	1
#define MAX_QUEUE_SIZE 	1

static gpu_ctx_t g_gpu_ctx[MAX_NUM_GPUS][MAX_QUEUE_SIZE] = {0};
static uint32_t g_cur_gpu = 0;
static uint32_t g_cur_queue[MAX_NUM_GPUS] = {0};
static int32_t g_total_gpus = -1;

static bool cl_crypt_init_locked() {
    if (g_total_gpus == -1) {
        g_total_gpus = MAX_NUM_GPUS;
        LOG("total_gpus: %d\n", g_total_gpus);
        for (int gpu = 0; gpu < g_total_gpus; gpu++) {
            for (int queue = 0; queue < MAX_QUEUE_SIZE; queue++) {
                int err = pthread_mutex_init(&g_gpu_ctx[gpu][queue].mutex, NULL);
                if (err != 0) {
                    fprintf(stderr, "pthread_mutex_init error %d gpu: %d queue: %d\n",
                            err, gpu, queue);
                    g_total_gpus = 0;
                    return false;
                }
            }
        }
    }
    return g_total_gpus > 0;
}

bool ed25519_init() {
    pthread_mutex_lock(&g_ctx_mutex);
    bool success = cl_crypt_init_locked();
    pthread_mutex_unlock(&g_ctx_mutex);
    return success;
}

gpu_ctx_t* get_gpu_ctx() {
    int32_t cur_gpu, cur_queue;

    LOG("locking global mutex\n");
    pthread_mutex_lock(&g_ctx_mutex);
    if (!cl_crypt_init_locked()) {
        pthread_mutex_unlock(&g_ctx_mutex);
        LOG("No GPUs, exiting...\n");
        return NULL;
    }
    cur_gpu = g_cur_gpu;
    g_cur_gpu++;
    g_cur_gpu %= g_total_gpus;
    cur_queue = g_cur_queue[cur_gpu];
    g_cur_queue[cur_gpu]++;
    g_cur_queue[cur_gpu] %= MAX_QUEUE_SIZE;
    pthread_mutex_unlock(&g_ctx_mutex);

    gpu_ctx_t* cur_ctx = &g_gpu_ctx[cur_gpu][cur_queue];
    LOG("locking contex mutex queue: %d gpu: %d\n", cur_queue, cur_gpu);
    pthread_mutex_lock(&cur_ctx->mutex);

    LOG("selecting gpu: %d queue: %d\n", cur_gpu, cur_queue);

    return cur_ctx;
}

void setup_gpu_ctx(verify_ctx_t* cur_ctx,
                   const gpu_Elems* elems,
                   uint32_t num_elems,
                   uint32_t message_size,
                   uint32_t total_packets,
                   uint32_t total_packets_size,
                   uint32_t total_signatures,
                   const uint32_t* message_lens,
                   const uint32_t* public_key_offsets,
                   const uint32_t* signature_offsets,
                   const uint32_t* message_start_offsets,
                   size_t out_size
                   ) {
	int ret;
    size_t offsets_size = total_signatures * sizeof(uint32_t);

    LOG("device allocate. packets: %d out: %d offsets_size: %zu\n",
        total_packets_size, (int)out_size, offsets_size);

    if (cur_ctx->packets == NULL ||
        total_packets_size > cur_ctx->packets_size_bytes) {
        clReleaseMemObject(cur_ctx->packets);
        cur_ctx->packets = clCreateBuffer(context, CL_MEM_READ_WRITE, total_packets_size, NULL, &ret);
        CL_ERR( ret );

        cur_ctx->packets_size_bytes = total_packets_size;
    }
	
	if (cur_ctx->out == NULL || cur_ctx->out_size_bytes < out_size) {
        clReleaseMemObject(cur_ctx->out);
        cur_ctx->out = clCreateBuffer(context, CL_MEM_READ_WRITE, out_size, NULL, &ret);
        CL_ERR( ret );

        cur_ctx->out_size_bytes = total_signatures;
    }
	
	if (cur_ctx->public_key_offsets == NULL || cur_ctx->offsets_len < total_signatures) {
        
        clReleaseMemObject(cur_ctx->public_key_offsets);
        cur_ctx->public_key_offsets = clCreateBuffer(context, CL_MEM_READ_WRITE, offsets_size, NULL, &ret);
        CL_ERR( ret );
        
        clReleaseMemObject(cur_ctx->signature_offsets);
        cur_ctx->signature_offsets = clCreateBuffer(context, CL_MEM_READ_WRITE, offsets_size, NULL, &ret);
        CL_ERR( ret );
        
        clReleaseMemObject(cur_ctx->message_start_offsets);
        cur_ctx->message_start_offsets = clCreateBuffer(context, CL_MEM_READ_WRITE, offsets_size, NULL, &ret);
        CL_ERR( ret );
        
        clReleaseMemObject(cur_ctx->message_lens);
        cur_ctx->message_lens = clCreateBuffer(context, CL_MEM_READ_WRITE, offsets_size, NULL, &ret);
        CL_ERR( ret );

        cur_ctx->offsets_len = total_signatures;
    }

    CL_ERR( clEnqueueWriteBuffer(cmd_queue, cur_ctx->public_key_offsets, CL_TRUE, 0, offsets_size, public_key_offsets, 0, NULL, NULL));
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, cur_ctx->signature_offsets, CL_TRUE, 0, offsets_size, signature_offsets, 0, NULL, NULL));
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, cur_ctx->message_start_offsets, CL_TRUE, 0, offsets_size, message_start_offsets, 0, NULL, NULL));
    CL_ERR( clEnqueueWriteBuffer(cmd_queue, cur_ctx->message_lens, CL_TRUE, 0, offsets_size, message_lens, 0, NULL, NULL));

    size_t cur = 0;
    for (size_t i = 0; i < num_elems; i++) {
        LOG("i: %zu size: %d\n", i, elems[i].num * message_size);
        CL_ERR( clEnqueueWriteBuffer(cmd_queue, cur_ctx->packets, CL_TRUE, cur * message_size, elems[i].num * message_size, elems[i].elems, 0, NULL, NULL));
        cur += elems[i].num;
    }
}


void release_gpu_ctx(gpu_ctx_t* cur_ctx) {
    pthread_mutex_unlock(&cur_ctx->mutex);
}

void ed25519_free_gpu_mem() {
	for (size_t gpu = 0; gpu < MAX_NUM_GPUS; gpu++) {
        for (size_t queue = 0; queue < MAX_QUEUE_SIZE; queue++) {
            verify_ctx_t* verify_ctx = &g_gpu_ctx[gpu][queue].verify_ctx;
			
			CL_ERR(clReleaseMemObject(verify_ctx->packets));
			CL_ERR(clReleaseMemObject(verify_ctx->out));
			CL_ERR(clReleaseMemObject(verify_ctx->message_lens));
			CL_ERR(clReleaseMemObject(verify_ctx->public_key_offsets));
			CL_ERR(clReleaseMemObject(verify_ctx->signature_offsets));
			CL_ERR(clReleaseMemObject(verify_ctx->message_start_offsets));
        }
    }
}
