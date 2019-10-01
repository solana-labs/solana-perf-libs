#include "cl_common.h"

#include "ed25519.h"
#include "sha512.h"
#include "ge.h"
#include "sc.h"
#include "gpu_common.h"
#include "gpu_ctx.h"

static void
ed25519_sign_device(unsigned char *signature,
                   const unsigned char *message,
                   size_t message_len,
                   const unsigned char *public_key,
                   const unsigned char *private_key) {
    sha512_context hash;
    unsigned char hram[64];
    unsigned char r[64];
    ge_p3 R;


    sha512_init(&hash);
    sha512_update(&hash, private_key + 32, 32);
    sha512_update(&hash, message, message_len);
    sha512_final(&hash, r);

    sc_reduce(r);
    ge_scalarmult_base(&R, r);
    ge_p3_tobytes(signature, &R);

    sha512_init(&hash);
    sha512_update(&hash, signature, 32);
    sha512_update(&hash, public_key, 32);
    sha512_update(&hash, message, message_len);
    sha512_final(&hash, hram);

    sc_reduce(hram);
    sc_muladd(signature + 32, hram, private_key, r);
}

void ed25519_sign(unsigned char *signature,
                   const unsigned char *message,
                   size_t message_len,
                   const unsigned char *public_key,
                   const unsigned char *private_key) {
    ed25519_sign_device(signature, message, message_len, public_key, private_key);
}

void ed25519_sign_many(const gpu_Elems* elems,
                       uint32_t num_elems,
                       uint32_t message_size,
                       uint32_t total_packets,
                       uint32_t total_signatures,
                       const uint32_t* message_lens,
                       const uint32_t* public_key_offsets,
                       const uint32_t* private_key_offsets,
                       const uint32_t* message_start_offsets,
                       uint8_t* signatures_out,
                       uint8_t use_non_default_stream
                       ) {
    DIE(cl_check_init() == false, "OpenCL could not be init");
    
    cl_int ret;
    
    size_t sig_out_size = SIG_SIZE * total_signatures;

    if (0 == total_packets) {
        return;
    }
	
    uint32_t total_packets_size = total_packets * message_size;
	
	LOG("signing %d packets sig_size: %zu message_size: %d\n",
        total_packets, sig_out_size, message_size);

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
                  private_key_offsets,
                  message_start_offsets,
                  sig_out_size
                 );

    size_t num_threads_per_block = 64;
    size_t num_blocks = ROUND_UP_DIV(total_signatures, num_threads_per_block) * num_threads_per_block;
    LOG("signing blocks: %d threads_per_block: %d\n", num_blocks, num_threads_per_block);
	
    /*
	__kernel void ed25519_sign_kernel(__global unsigned char* packets,
										uint32_t message_size,
										__global uint32_t* public_key_offsets,
										__global uint32_t* private_key_offsets,
										__global uint32_t* message_start_offsets,
										__global uint32_t* message_lens,
										uint32_t num_transactions,
										__global uint8_t* out)
	*/				 
    CL_ERR( clSetKernelArg(ed25519_sign_kernel, 0, sizeof(cl_mem), (void *)&cur_ctx->packets) );
    CL_ERR( clSetKernelArg(ed25519_sign_kernel, 1, sizeof(cl_uint), (void *)&message_size) );
    CL_ERR( clSetKernelArg(ed25519_sign_kernel, 2, sizeof(cl_mem), (void *)&cur_ctx->public_key_offsets) );
    CL_ERR( clSetKernelArg(ed25519_sign_kernel, 3, sizeof(cl_mem), (void *)&cur_ctx->signature_offsets) );
    CL_ERR( clSetKernelArg(ed25519_sign_kernel, 4, sizeof(cl_mem), (void *)&cur_ctx->message_start_offsets) );
    CL_ERR( clSetKernelArg(ed25519_sign_kernel, 5, sizeof(cl_mem), (void *)&cur_ctx->message_lens) );
    CL_ERR( clSetKernelArg(ed25519_sign_kernel, 6, sizeof(cl_uint), (void *)&total_signatures) );
    CL_ERR( clSetKernelArg(ed25519_sign_kernel, 7, sizeof(cl_mem), (void *)&cur_ctx->out) );

    size_t globalSize[2] = {num_blocks * num_threads_per_block, 0};
    size_t localSize[2] = {num_threads_per_block, 0};    
    
    ret = clEnqueueNDRangeKernel(cmd_queue, ed25519_sign_kernel, 1, NULL,
        globalSize, localSize, 0, NULL, NULL);
        CL_ERR( ret );
        
    CL_ERR( clEnqueueReadBuffer(cmd_queue, cur_ctx->out, CL_TRUE, 0, sig_out_size, signatures_out, 0, NULL, NULL));

    release_gpu_ctx(gpu_ctx);
}
