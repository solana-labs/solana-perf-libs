#ifndef HEADER_CHACHA_H
# define HEADER_CHACHA_H

#include <inttypes.h>
# include <stddef.h>
# ifdef  __cplusplus
extern "C" {
# endif

#define CHACHA_KEY_SIZE_BYTES 32
#define CHACHA_KEY_SIZE_U32 8
#define CHACHA_NONCE_SIZE 12
#define CHACHA_BLOCK_SIZE 64
#define CHACHA_ROUNDS 500
#define SAMPLE_SIZE 32
#define CHACHA_IV_SIZE 16

void cuda_chacha20_cbc_encrypt(
                const uint8_t *in,
                uint8_t *out,
                size_t in_len,
                const uint32_t key[CHACHA_KEY_SIZE_U32],
                uint8_t ivec[CHACHA_IV_SIZE]);

void chacha_cbc_encrypt_many(const uint8_t* in,
                             uint8_t* out,
                             size_t length,
                             const uint8_t *keys,
                             uint8_t* ivec,
                             uint32_t num_keys,
                             float* time_us);

void chacha_cbc_encrypt_many_sample(const uint8_t* in,
                                    void* out,
                                    size_t length,
                                    const uint8_t* keys,
                                    uint8_t* ivecs,
                                    uint32_t num_keys,
                                    const uint64_t* samples,
                                    uint32_t num_samples,
                                    uint64_t starting_block_offset,
                                    float* time_us);

void chacha_end_sha_state(const void* sha_state, uint8_t* out, uint32_t num_keys);

void chacha_init_sha_state(void* sha_state, uint32_t num_keys);

# ifdef  __cplusplus
}
# endif

#endif
