#ifndef INT128_H
#define INT128_H

struct uint128_t {
  uint64_t low;
  uint64_t high;
};

static __device__ __host__ uint128_t mul_128(uint64_t a, uint64_t b) {
  uint128_t result;
#ifdef __CUDA_ARCH__
  result.low = a * b;
  result.high = __mul64hi(a, b);
#elif __x86_64__
  asm( "mulq %3\n\t"
      : "=a" (result.low), "=d" (result.high)
      : "%0" (a), "rm" (b));
#endif
  return result;
}

static __device__ __host__ uint128_t add_128(uint128_t a, uint128_t b) {
  uint128_t result;
#ifdef __CUDA_ARCH__
  asm( "add.cc.u64    %0, %2, %4;\n\t"
       "addc.u64      %1, %3, %5;\n\t"
       : "=l" (result.low), "=l" (result.high)
       : "l" (a.low), "l" (a.high),
       "l" (b.low), "l" (b.high));
#else
  result.low = a.low + b.low;
  result.high = a.high + b.high + (result.low < a.low);
#endif
  return result;
}

#endif
