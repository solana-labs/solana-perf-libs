#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "chacha.h"

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
    fprintf(stderr, "chacha_cbc_encrypt_many_sample not implemented\n");
    exit(1);
}

void chacha_end_sha_state(const void* sha_state, uint8_t* out, uint32_t num_keys)
{
    fprintf(stderr, "chacha_end_sha_state not implemented\n");
    exit(1);
}

void chacha_init_sha_state(void* sha_state, uint32_t num_keys)
{
    fprintf(stderr, "chacha_init_sha_state not implemented\n");
    exit(1);
}


