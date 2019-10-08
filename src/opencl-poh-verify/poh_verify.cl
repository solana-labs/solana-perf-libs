
#include "gpu_common.h"
#include "sha256.cu"

__global__ void poh_verify_kernel(uint8_t* hashes, uint64_t* num_hashes_arr, size_t num_elems) {
    size_t idx = (size_t)(blockIdx.x * blockDim.x + threadIdx.x);
    if (idx >= num_elems) return;

    uint8_t hash[SHA256_BLOCK_SIZE];

    memcpy(hash, &hashes[idx * SHA256_BLOCK_SIZE], SHA256_BLOCK_SIZE);

    for (size_t i = 0; i < num_hashes_arr[idx]; i++) {
        hash_state sha_state;
        sha256_init(&sha_state);
        sha256_process(&sha_state, hash, SHA256_BLOCK_SIZE);
        sha256_done(&sha_state, hash);
    }

    memcpy(&hashes[idx * SHA256_BLOCK_SIZE], hash, SHA256_BLOCK_SIZE);
}