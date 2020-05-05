
#ifndef COMMON_CU
#define COMMON_CU

static uint64_t __host__ __device__ load_3(const unsigned char *in) {
    uint64_t result;

    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;

    return result;
}

static uint64_t __host__ __device__ load_4(const unsigned char *in) {
    uint64_t result;

    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;
    result |= ((uint64_t) in[3]) << 24;
    
    return result;
}

static uint64_t __host__ __device__ load_7(const unsigned char *in) {
    uint64_t result;

    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;
    result |= ((uint64_t) in[3]) << 24;
    result |= ((uint64_t) in[4]) << 32;
    result |= ((uint64_t) in[5]) << 40;
    result |= ((uint64_t) in[6]) << 48;

    return result;
}


#endif
