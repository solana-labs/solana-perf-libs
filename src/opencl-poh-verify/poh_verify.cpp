#include <stddef.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include "cl_common.h"
#include "sha256.cu"

// TODO OpenCL uses only 1 GPU and 1 context/cmd queue
#define OPENCL_MAX_NUM_GPUS 1
#define OPENCL_MAX_QUEUE_SIZE 1
#define OPENCL_LOCAL_WORK_SIZE 64

typedef struct {
    cl_mem hashes;
    cl_mem num_hashes_arr;
    size_t num_elems_alloc;
    pthread_mutex_t mutex;
} gpu_ctx;

static pthread_mutex_t g_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

static gpu_ctx g_gpu_ctx[OPENCL_MAX_NUM_GPUS][OPENCL_MAX_QUEUE_SIZE] = {0};
static uint32_t g_cur_gpu = 0;
static uint32_t g_cur_queue[OPENCL_MAX_NUM_GPUS] = {0};
static int32_t g_total_gpus = -1;

static bool poh_init_locked() {

    if (g_total_gpus == -1) {
        g_total_gpus = OPENCL_MAX_NUM_GPUS;
        LOG("total_gpus: %d\n", g_total_gpus);
        for (int gpu = 0; gpu < g_total_gpus; gpu++) {
            
            for (int queue = 0; queue < OPENCL_MAX_QUEUE_SIZE; queue++) {
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

bool poh_init() {
    pthread_mutex_lock(&g_ctx_mutex);
    bool success = poh_init_locked();
    pthread_mutex_unlock(&g_ctx_mutex);
    return success;
}

extern "C" {
int poh_verify_many(uint8_t* hashes,
                    const uint64_t* num_hashes_arr,
                    size_t num_elems,
                    uint8_t use_non_default_stream)
{
	DIE(cl_check_init() == false, "OpenCL could not be init");
    
    int ret;
	
    LOG("Starting poh_verify_many: num_elems: %zu\n", num_elems);

    if (num_elems == 0) return 0;

    int32_t cur_gpu, cur_queue;

    pthread_mutex_lock(&g_ctx_mutex);
    if (!poh_init_locked()) {
        pthread_mutex_unlock(&g_ctx_mutex);
        LOG("No GPUs, exiting...\n");
        return 1;
    }
    cur_gpu = g_cur_gpu;
    g_cur_gpu++;
    g_cur_gpu %= g_total_gpus;
    cur_queue = g_cur_queue[cur_gpu];
    g_cur_queue[cur_gpu]++;
    g_cur_queue[cur_gpu] %= OPENCL_MAX_QUEUE_SIZE;
    pthread_mutex_unlock(&g_ctx_mutex);

    gpu_ctx* cur_ctx = &g_gpu_ctx[cur_gpu][cur_queue];
    pthread_mutex_lock(&cur_ctx->mutex);

    LOG("cur gpu: %d cur queue: %d\n", cur_gpu, cur_queue);

    size_t hashes_size = num_elems * SHA256_BLOCK_SIZE * sizeof(uint8_t);
    size_t num_hashes_size = num_elems * sizeof(uint64_t);

    // Ensure there is enough memory allocated
    if (cur_ctx->hashes == NULL || cur_ctx->num_elems_alloc < num_elems) {
		
		CL_ERR(clReleaseMemObject(cur_ctx->hashes));
		cur_ctx->hashes = clCreateBuffer(context, CL_MEM_READ_WRITE, hashes_size, NULL, &ret);
		CL_ERR( ret );
		
		CL_ERR(clReleaseMemObject(cur_ctx->num_hashes_arr));
		cur_ctx->num_hashes_arr = clCreateBuffer(context, CL_MEM_READ_WRITE, num_hashes_size, NULL, &ret);
		CL_ERR( ret );

        cur_ctx->num_elems_alloc = num_elems;
    }

	CL_ERR( clEnqueueWriteBuffer(cmd_queue, cur_ctx->hashes, CL_TRUE, 0, hashes_size, hashes, 0, NULL, NULL));
	CL_ERR( clEnqueueWriteBuffer(cmd_queue, cur_ctx->num_hashes_arr, CL_TRUE, 0, num_hashes_size, num_hashes_arr, 0, NULL, NULL));
	
    size_t num_blocks = ROUND_UP_DIV(num_elems, OPENCL_LOCAL_WORK_SIZE);
	size_t num_threads_block = OPENCL_LOCAL_WORK_SIZE;
	
	CL_ERR( clSetKernelArg(poh_verify_kernel, 0, sizeof(cl_mem), (void *)&cur_ctx->hashes) );
	CL_ERR( clSetKernelArg(poh_verify_kernel, 1, sizeof(cl_mem), (void *)&cur_ctx->num_hashes_arr) );
	CL_ERR( clSetKernelArg(poh_verify_kernel, 2, sizeof(size_t), (void *)&num_elems) );

	size_t global_size[2] = {num_blocks * num_threads_block, 0};
	size_t local_size[2] = {num_threads_block, 0};	
	ret = clEnqueueNDRangeKernel(cmd_queue, poh_verify_kernel, 1, NULL,
		global_size, local_size, 0, NULL, NULL);
		CL_ERR( ret );
	
	CL_ERR( clEnqueueReadBuffer(cmd_queue, cur_ctx->hashes, CL_TRUE, 0, hashes_size, hashes, 0, NULL, NULL));

    pthread_mutex_unlock(&cur_ctx->mutex);

    return 0;
}
}
