#include "common.h"
#include "chacha.h"

#if !defined(STRICT_ALIGNMENT) && !defined(PEDANTIC)
# define STRICT_ALIGNMENT 0
#endif

#include "gpu_common.h"

// common code CPU(HOST) and GPU(DEVICE)
#include "chacha20_core.cl"

void cuda_chacha20_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t in_len,
                               const uint8_t key[CHACHA_KEY_SIZE], uint8_t* ivec)
{
    cuda_chacha20_cbc128_encrypt(in, out, in_len, key, ivec);
}

void chacha20_cbc128_encrypt_kernel(const unsigned char* input, unsigned char* output,
                                               size_t length, const uint8_t* keys,
                                               unsigned char* ivec, uint32_t num_keys)
{
    size_t i = (size_t)(blockIdx.x * blockDim.x + threadIdx.x);

    if (i < num_keys) {
        cuda_chacha20_cbc128_encrypt(input, &output[i * length], length, &keys[i], &ivec[i * CHACHA_BLOCK_SIZE]);
    }
}

#include "sha256.cu"

void init_sha256_state_kernel(hash_state* sha_state, uint32_t num_keys)
{
    size_t i = (size_t)(blockIdx.x * blockDim.x + threadIdx.x);
    if (i < num_keys) {
        sha256_init(&sha_state[i]);
    }
}

void end_sha256_state_kernel(hash_state* sha_state, uint8_t* out_state, uint32_t num_keys) {
    size_t i = (size_t)(blockIdx.x * blockDim.x + threadIdx.x);
    if (i < num_keys) {
        sha256_done(&sha_state[i], &out_state[i * SHA256_BLOCK_SIZE]);
    }
}

void chacha20_cbc128_encrypt_sample_kernel(const uint8_t* input,
                                                      uint8_t* output,
                                                      size_t length,
                                                      const uint8_t* keys,
                                                      uint8_t* ivec,
                                                      uint32_t num_keys,
                                                      hash_state* sha_state,
                                                      uint64_t* sample_idx,
                                                      uint32_t sample_len,
                                                      uint64_t block_offset)
{
    size_t i = (size_t)(blockIdx.x * blockDim.x + threadIdx.x);

    if (i < num_keys) {
        uint8_t* t_output = &output[i * BLOCK_SIZE];
        cuda_chacha20_cbc128_encrypt(input, t_output, length, &keys[i * CHACHA_KEY_SIZE], &ivec[i * CHACHA_BLOCK_SIZE]);

        for (uint32_t j = 0; j < sample_len; j++) {
            uint64_t cur_sample = sample_idx[j] * SAMPLE_SIZE;
            if (cur_sample >= block_offset && cur_sample < (block_offset + length)) {
                sha256_process(&sha_state[i], &t_output[cur_sample - block_offset], SAMPLE_SIZE);
            }
        }
    }
}


void chacha_ctr_encrypt_kernel(const unsigned char* input, unsigned char* output,
                                          size_t length, const uint8_t* keys,
                                          unsigned char* nonces, uint32_t num_keys,
                                          unsigned char* sha_state,
                                          uint32_t* sample_idx,
                                          uint32_t sample_len,
                                          uint32_t block_offset)
{
    size_t i = (size_t)(blockIdx.x * blockDim.x + threadIdx.x);

    if (i < num_keys) {
        chacha20_ctr_encrypt(input, &output[i * length], length, &keys[i * CHACHA_KEY_SIZE], &nonces[i * CHACHA_NONCE_SIZE], 0);
    }
}