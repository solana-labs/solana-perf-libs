
#ifdef _MSC_VER
#include <Windows.h>
#endif

#include "chacha.h"
#include <stdio.h>
#include <inttypes.h>
#include "perftime.h"
#include <algorithm>
#include "common.h"

typedef struct {
    size_t len;
    uint32_t num_keys;
    uint8_t* input;
    uint8_t* output;
    uint8_t* output_ref;

    uint8_t chacha_ivec[CHACHA_BLOCK_SIZE];
    uint8_t chacha_ivec_orig[CHACHA_BLOCK_SIZE];
    uint8_t chacha_ivec_ref[CHACHA_BLOCK_SIZE];
} ctx_t;

void free_ctx(ctx_t* ctx)
{
    free(ctx->input);
    free(ctx->output);
    free(ctx->output_ref);
}

void clear_ctx(ctx_t* ctx)
{
    memset(ctx->input, 0, ctx->len);
    memset(ctx->output, 0, ctx->len);
    memset(ctx->output_ref, 0, ctx->len);
}

int test_chacha_cbc_sample(ctx_t* gctx)
{
    printf("Starting gpu cbc chacha..\n");
    uint8_t key[CHACHA_KEY_SIZE] = {0};
    for (int i = 0; i < CHACHA_KEY_SIZE; i++) {
        key[i] = i;
    }

    cuda_chacha20_cbc_encrypt(gctx->input, gctx->output_ref, gctx->len, key, gctx->chacha_ivec);
    memcpy(gctx->chacha_ivec_ref, gctx->chacha_ivec, sizeof(gctx->chacha_ivec));

    printf("\n\n");
    print_bytes("output_ref", gctx->output_ref, gctx->len);

    int iterations = 1;
    perftime_t start, end;
    get_time(&start);
    for (int i = 0; i < iterations; i++) {
        cuda_chacha20_cbc_encrypt(gctx->input, gctx->output, gctx->len, key, gctx->chacha_ivec);
    }
    get_time(&end);

    print_bytes("output", gctx->output, gctx->len);

    float time_us = get_diff(&start, &end);
    float ns_per_byte = 1000.f * time_us / ((float)iterations * (float)gctx->len);
    printf("time: %f ns/byte time: %f us\n", ns_per_byte, time_us);

    uint8_t* outputs = (uint8_t*)calloc(gctx->len, gctx->num_keys);
    uint8_t* ivecs = (uint8_t*)calloc(CHACHA_BLOCK_SIZE, gctx->num_keys);
    uint8_t* keys = (uint8_t*)calloc(CHACHA_KEY_SIZE, gctx->num_keys);

    for (uint32_t i = 0; i < gctx->num_keys; i++) {
        memcpy(&keys[i * CHACHA_KEY_SIZE], key, CHACHA_KEY_SIZE);
        memcpy(&ivecs[i * CHACHA_BLOCK_SIZE], gctx->chacha_ivec_orig, CHACHA_BLOCK_SIZE);
    }

    uint64_t samples[1] = {0};

    chacha_cbc_encrypt_many_sample((uint8_t*)gctx->input, outputs, gctx->len, keys, ivecs, gctx->num_keys, samples, 1, 0, &time_us);

    ns_per_byte = 1000.f * time_us / ((float)gctx->len * (float)gctx->num_keys);
    printf("gpu time: %f ns/byte time: %f us\n", ns_per_byte, time_us);

    int output_errors = 0, ivec_errors = 0;
    for (uint32_t i = 0; i < gctx->num_keys; i++) {
        if (0 != verbose_memcmp(gctx->output_ref, &outputs[i * gctx->len], gctx->len)) {
            if (output_errors < 10) {
                printf("%d gpu output not matching! %x\n", i, outputs[0]);
            }
            output_errors++;
            break;
        }

        if (0 != verbose_memcmp(gctx->chacha_ivec_ref, &ivecs[i * CHACHA_BLOCK_SIZE], CHACHA_BLOCK_SIZE)) {
            if (ivec_errors < 1) {
                printf("%d ivecs output not matching! %x\n", i, ivecs[0]);
            }
            ivec_errors++;
        }
    }
    printf("total keys: %d output_errors: %d ivec_errors: %d\n", gctx->num_keys, output_errors, ivec_errors);

    print_bytes("gpu output", outputs, gctx->len);
    print_bytes("gpu ivec", ivecs, CHACHA_BLOCK_SIZE);

    free(outputs);
    free(ivecs);
    free(keys);

    return 0;
}



int test_chacha_cbc(ctx_t* gctx)
{
    printf("Starting gpu cbc chacha..\n");
    uint8_t key[CHACHA_KEY_SIZE] = {0};
    for (int i = 0; i < CHACHA_KEY_SIZE; i++) {
        key[i] = i;
    }

    cuda_chacha20_cbc_encrypt(gctx->input, gctx->output_ref, gctx->len, key, gctx->chacha_ivec);
    memcpy(gctx->chacha_ivec_ref, gctx->chacha_ivec, sizeof(gctx->chacha_ivec));

    printf("\n\n");
    print_bytes("output_ref", gctx->output_ref, gctx->len);

    int iterations = 1;
    perftime_t start, end;
    get_time(&start);
    for (int i = 0; i < iterations; i++) {
        cuda_chacha20_cbc_encrypt(gctx->input, gctx->output, gctx->len, key, gctx->chacha_ivec);
    }
    get_time(&end);

    print_bytes("output", gctx->output, gctx->len);

    float time_us = get_diff(&start, &end);
    float ns_per_byte = 1000.f * time_us / ((float)iterations * (float)gctx->len);
    printf("time: %f ns/byte time: %f us\n", ns_per_byte, time_us);

    uint8_t* outputs = (uint8_t*)calloc(gctx->len, gctx->num_keys);
    uint8_t* ivecs = (uint8_t*)calloc(CHACHA_BLOCK_SIZE, gctx->num_keys);
    uint8_t* keys = (uint8_t*)calloc(CHACHA_KEY_SIZE, gctx->num_keys);

    for (uint32_t i = 0; i < gctx->num_keys; i++) {
        memcpy(&keys[i * CHACHA_KEY_SIZE], key, CHACHA_KEY_SIZE);
        memcpy(&ivecs[i * CHACHA_BLOCK_SIZE], gctx->chacha_ivec_orig, CHACHA_BLOCK_SIZE);
    }

    chacha_cbc_encrypt_many((uint8_t*)gctx->input, outputs, gctx->len, keys, ivecs, gctx->num_keys, &time_us);

    ns_per_byte = 1000.f * time_us / ((float)gctx->len * (float)gctx->num_keys);
    printf("gpu time: %f ns/byte time: %f us\n", ns_per_byte, time_us);

    int output_errors = 0, ivec_errors = 0;
    for (uint32_t i = 0; i < gctx->num_keys; i++) {
        if (0 != verbose_memcmp(gctx->output_ref, &outputs[i * gctx->len], gctx->len)) {
            if (output_errors < 10) {
                printf("%d gpu output not matching! %x\n", i, outputs[0]);
            }
            output_errors++;
            break;
        }

        if (0 != verbose_memcmp(gctx->chacha_ivec_ref, &ivecs[i * CHACHA_BLOCK_SIZE], CHACHA_BLOCK_SIZE)) {
            if (ivec_errors < 1) {
                printf("%d ivecs output not matching! %x\n", i, ivecs[0]);
            }
            ivec_errors++;
        }
    }
    printf("total keys: %d output_errors: %d ivec_errors: %d\n", gctx->num_keys, output_errors, ivec_errors);

    print_bytes("gpu output", outputs, gctx->len);
    print_bytes("gpu ivec", ivecs, CHACHA_BLOCK_SIZE);

    free(outputs);
    free(ivecs);
    free(keys);

    return 0;
}


int test_chacha_ctr(ctx_t* gctx)
{
    printf("Starting gpu ctr chacha..\n");
    uint8_t key[CHACHA_KEY_SIZE] = {0};
    uint8_t nonce[CHACHA_NONCE_SIZE] = {0};
    for (int i = 0; i < CHACHA_KEY_SIZE; i++) {
        key[i] = i;
    }

    for (int i = 0; i < CHACHA_NONCE_SIZE; i++) {
        nonce[i] = i;
    }

    chacha20_ctr_encrypt(gctx->input, gctx->output_ref, gctx->len, key, nonce, 0);

    printf("\n\n");
    print_bytes("output_ref", gctx->output_ref, gctx->len);

    int iterations = 1;
    perftime_t start, end;
    get_time(&start);
    for (int i = 0; i < iterations; i++) {
        chacha20_ctr_encrypt(gctx->input, gctx->output, gctx->len, key, nonce, i);
    }
    get_time(&end);

    print_bytes("output", gctx->output, gctx->len);

    float time_us = get_diff(&start, &end);
    float ns_per_byte = 1000.f * time_us / ((float)iterations * (float)gctx->len);
    printf("time: %f ns/byte time: %f us\n", ns_per_byte, time_us);

    uint8_t* outputs = (uint8_t*)calloc(gctx->len, gctx->num_keys);
    uint8_t* nonces = (uint8_t*)calloc(CHACHA_NONCE_SIZE, gctx->num_keys);
    uint8_t* keys = (uint8_t*)calloc(CHACHA_KEY_SIZE, gctx->num_keys);

    for (uint32_t i = 0; i < gctx->num_keys; i++) {
        memcpy(&keys[i * CHACHA_KEY_SIZE], key, CHACHA_KEY_SIZE);
        memcpy(&nonces[i * CHACHA_NONCE_SIZE], nonce, CHACHA_NONCE_SIZE);
    }

    chacha_ctr_encrypt_many((uint8_t*)gctx->input, outputs, gctx->len, keys, nonces, gctx->num_keys, &time_us);

    ns_per_byte = 1000.f * time_us / ((float)gctx->len * (float)gctx->num_keys);
    printf("gpu time: %f ns/byte time: %f us\n", ns_per_byte, time_us);

    int output_errors = 0, ivec_errors = 0;
    for (uint32_t i = 0; i < gctx->num_keys; i++) {
        if (0 != verbose_memcmp(gctx->output_ref, &outputs[i * gctx->len], gctx->len)) {
            if (output_errors < 10) {
                printf("%d gpu output not matching! %x\n", i, outputs[0]);
            }
            output_errors++;
            break;
        }
    }
    printf("total keys: %d output_errors: %d ivec_errors: %d\n", gctx->num_keys, output_errors, ivec_errors);

    print_bytes("gpu output", outputs, gctx->len);

    free(outputs);
    free(nonces);
    free(keys);

    return 0;
}

int main(int argc, const char* argv[]) {
    printf("Starting gpu crypto..\n");
    ctx_t ctx = {0};
    ctx.len = 64;
    ctx.num_keys = 4;

    int arg = 1;
    if (arg < argc) {
        ctx.num_keys = strtol(argv[arg++], NULL, 10);
    }
    if (arg < argc) {
        ctx.len = strtol(argv[arg++], NULL, 10);
    }

    if (ctx.num_keys == 0) {
        printf("ERROR: num_keys == 0!\n");
        return 1;
    }

    printf("num_keys: %d len: %zu\n", ctx.num_keys, ctx.len);

    ctx.input = (uint8_t*)calloc(ctx.len, 1);
    ctx.output = (uint8_t*)calloc(ctx.len, 1);
    ctx.output_ref = (uint8_t*)calloc(ctx.len, 1);

    uint8_t chacha_ivec_orig[CHACHA_BLOCK_SIZE] = {0xde, 0xad, 0xbe, 0xef};
    memcpy(ctx.chacha_ivec_orig, chacha_ivec_orig, sizeof(ctx.chacha_ivec_orig));
    memcpy(ctx.chacha_ivec, chacha_ivec_orig, sizeof(ctx.chacha_ivec));

    clear_ctx(&ctx);

    //test_chacha_ctr(&ctx);
    //clear_ctx(&ctx);

    //test_chacha_cbc(&ctx);

    test_chacha_cbc_sample(&ctx);

    free_ctx(&ctx);

    return 0;
}
