#ifndef COMMON_CL
#define COMMON_CL

static ulong load_3(const unsigned char *in) {
    ulong result;

    result = (ulong) in[0];
    result |= ((ulong) in[1]) << 8;
    result |= ((ulong) in[2]) << 16;

    return result;
}

static uint64_t load_4(const unsigned char *in) {
    ulong result;

    result = (ulong) in[0];
    result |= ((ulong) in[1]) << 8;
    result |= ((ulong) in[2]) << 16;
    result |= ((ulong) in[3]) << 24;
    
    return result;
}

#endif
