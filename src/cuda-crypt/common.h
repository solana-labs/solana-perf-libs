#ifndef CRYPT_COMMON_H
#define CRYPT_COMMON_H

static void print_bytes(const char* name, const uint8_t* input, size_t len)
{
    printf("%s:\n", name);
    for (size_t i = 0; i < std::min(len, (size_t)64); i++) {
        printf("%x ", input[i]);
    }
    printf("\n");
}

static uint32_t verbose_memcmp(void* a, void* b, size_t size)
{
    uint8_t* a8 = (uint8_t*)a;
    uint8_t* b8 = (uint8_t*)b;
    uint32_t num_errors = 0;
    for (size_t j = 0; j < size; j++) {
        if (a8[j] != b8[j]) {
            if (num_errors < 1) {
                printf("mismatch @(j=%zu) ref: %d actual: %d\n", j, a8[j], b8[j]);
            }
            num_errors++;
        }
    }
    return num_errors;
}

#endif
