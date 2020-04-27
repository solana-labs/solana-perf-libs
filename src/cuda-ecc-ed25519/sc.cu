#include "fixedint.h"
#include "sc.h"
#include "common.cu"
#include "int128.h"

#ifdef __CUDA_ARCH__
#define CONSTANT __constant__
#else
#define CONSTANT const
#endif

/// R = R % L where R = 2^260
const __device__ uint64_t R_scalar_u52[] = {
    0x000f48bd6721e6ed,
    0x0003bab5ac67e45a,
    0x000fffffeb35e51b,
    0x000fffffffffffff,
    0x00000fffffffffff,
    };

CONSTANT uint64_t L_scalar_u52[] = {
    0x0002631a5cf5d3ed,
    0x000dea2f79cd6581,
    0x000000000014def9,
    0x0000000000000000,
    0x0000100000000000,
    };

const uint64_t L_FACTOR = 0x51da312547e1b;

// Unpacked 32-byte scalar with 5x 52-bit limbs
typedef uint64_t scalar32_u52_t[5];

// Packed 32-byte scalar
typedef uint8_t scalar32_t[32];

void __host__ __device__ scalar52_mul(uint128_t* out, const scalar32_u52_t a, const scalar32_u52_t b) {
    out[0] = mul_128(a[0], b[0]);

    out[1] = add_128(mul_128(a[0], b[1]), mul_128(a[1], b[0]));

    out[2] = add_128(mul_128(a[0], b[2]), mul_128(a[1], b[1]));
    out[2] = add_128(out[2], mul_128(a[2], b[0]));

    out[3] = add_128(mul_128(a[0], b[3]), mul_128(a[1], b[2]));
    out[3] = add_128(out[3], mul_128(a[2], b[1]));
    out[3] = add_128(out[3], mul_128(a[3], b[0]));

    out[4] = add_128(mul_128(a[0], b[4]), mul_128(a[1], b[3]));
    out[4] = add_128(out[4], mul_128(a[2], b[2]));
    out[4] = add_128(out[4], mul_128(a[3], b[1]));
    out[4] = add_128(out[4], mul_128(a[4], b[0]));

    out[5] = add_128(mul_128(a[1], b[4]), mul_128(a[2], b[3]));
    out[5] = add_128(out[5], mul_128(a[3], b[2]));
    out[5] = add_128(out[5], mul_128(a[4], b[1]));

    out[6] = add_128(mul_128(a[2], b[4]), mul_128(a[3], b[3]));
    out[6] = add_128(out[5], mul_128(a[4], b[2]));

    out[7] = add_128(mul_128(a[3], b[4]), mul_128(a[4], b[3]));

    out[8] = mul_128(a[4], b[4]);
}

#define MASK_52 ((UINT64_C(1) << 52) - 1)

void __host__ __device__ scalar32_unpack(scalar32_u52_t out, scalar32_t in) {
    out[0] = MASK_52 & load_7(in);             //   0-51
    out[1] = MASK_52 & (load_7(in + 6) >> 4);  //  52-103
    out[2] = MASK_52 & load_7(in + 13);        // 104-156
    out[3] = MASK_52 & (load_7(in + 19) >> 4); // 156-208
    out[4] = MASK_52 & load_7(in + 26);        // 208-256
}

void __host__ __device__ scalar32_pack(scalar32_t out, scalar32_u52_t in) {
    out[0] = (uint8_t)in[0];
    out[1] = (uint8_t)(in[0] >> 8);
    out[2] = (uint8_t)(in[0] >> 16);
    out[3] = (uint8_t)(in[0] >> 24);
    out[4] = (uint8_t)(in[0] >> 32);
    out[5] = (uint8_t)(in[0] >> 40);

    out[6] = (uint8_t)((in[0] >> 48) | (in[1] << 4));

    out[7]  = (uint8_t)(in[1] >>  4);
    out[8]  = (uint8_t)(in[1] >> 12);
    out[9]  = (uint8_t)(in[1] >> 20);
    out[10] = (uint8_t)(in[1] >> 28);
    out[11] = (uint8_t)(in[1] >> 36);
    out[12] = (uint8_t)(in[1] >> 44);

    out[13] = (uint8_t)(in[2] >>  0);
    out[14] = (uint8_t)(in[2] >>  8);
    out[15] = (uint8_t)(in[2] >> 16);
    out[16] = (uint8_t)(in[2] >> 24);
    out[17] = (uint8_t)(in[2] >> 32);
    out[18] = (uint8_t)(in[2] >> 40);

    out[19] = ((uint8_t)(in[2] >> 48) | (uint8_t)(in[ 3] << 4));

    out[20] = (uint8_t)(in[3] >>  4);
    out[21] = (uint8_t)(in[3] >> 12);
    out[22] = (uint8_t)(in[3] >> 20);
    out[23] = (uint8_t)(in[3] >> 28);
    out[24] = (uint8_t)(in[3] >> 36);
    out[25] = (uint8_t)(in[3] >> 44);

    out[26] = (uint8_t)(in[4] >>  0);
    out[27] = (uint8_t)(in[4] >>  8);
    out[28] = (uint8_t)(in[4] >> 16);
    out[29] = (uint8_t)(in[4] >> 24);
    out[30] = (uint8_t)(in[4] >> 32);
    out[31] = (uint8_t)(in[4] >> 40);
}

uint128_t __host__ __device__ rshift_128(uint128_t val, uint64_t n) {
    val.low >>= n;
    uint64_t high_to_low = (val.high & MASK_52) << (64 - n);
    val.low |= high_to_low;
    val.high >>= n;
    return val;
}

void __host__ __device__ part1(uint128_t sum, uint128_t* carry, uint64_t* adjust) {
    *adjust = (sum.low * L_FACTOR) & MASK_52;
    *carry = rshift_128(add_128(sum, mul_128(*adjust, L_scalar_u52[0])), 52);
}

void __host__ __device__ part2(uint128_t sum, uint128_t* carry, uint64_t* adjust) {
    *adjust = sum.low & MASK_52;
    *carry = rshift_128(sum, 52);
}

// r = a - b
void __host__ __device__ scalar_u52_sub(scalar32_u52_t r, scalar32_u52_t a, const scalar32_u52_t b) {
    for (int i = 0; i < 5; i++) {
        r[i] = 0;
    }

    // a - b
    uint64_t borrow = 0;
    for (int i = 0; i < 5; i++) {
        borrow = a[i] - (b[i] + (borrow >> 63));
        r[i] = borrow & MASK_52;
    }

    // conditionally add l if the difference is negative
    uint64_t underflow_mask = ((borrow >> 63) ^ 1) - 1;
    uint64_t carry = 0;
    for (int i = 0; i < 5; i++) {
        carry = (carry >> 52) + r[i] + (L_scalar_u52[i] & underflow_mask);
        r[i] = carry & MASK_52;
    }
}

void __host__ __device__ montgomery_reduce(scalar32_u52_t s, uint128_t r[9]) {
    uint128_t carry;
    uint64_t n0;
    part1(r[0], &carry, &n0);

    uint64_t n1;
    uint128_t sum1 = add_128(mul_128(n0, L_scalar_u52[1]), r[1]);
    sum1 = add_128(sum1, carry);
    part1(sum1, &carry, &n1);

    uint64_t n2;
    uint128_t sum2 = add_128(mul_128(n0, L_scalar_u52[2]), mul_128(n1, L_scalar_u52[1]));
    sum2 = add_128(sum2, r[2]);
    sum2 = add_128(sum2, carry);
    part1(sum2, &carry, &n2);

    uint64_t n3;
    uint128_t sum3 = add_128(mul_128(n1, L_scalar_u52[2]), mul_128(n2, L_scalar_u52[1]));
    sum3 = add_128(sum3, r[3]);
    sum3 = add_128(sum3, carry);
    part1(sum3, &carry, &n3);

    uint64_t n4;
    uint128_t sum4 = add_128(mul_128(n0, L_scalar_u52[4]), mul_128(n3, L_scalar_u52[1]));
    sum4 = add_128(sum4, mul_128(n2, L_scalar_u52[2]));
    sum4 = add_128(sum4, r[4]);
    sum4 = add_128(sum4, carry);
    part1(sum4, &carry, &n4);

    uint128_t sum0;
    scalar32_u52_t r_scalar;

    sum0 = add_128(carry, r[5]);
    sum0 = add_128(sum0, mul_128(n1, L_scalar_u52[4]));
    sum0 = add_128(sum0, mul_128(n3, L_scalar_u52[2]));
    sum0 = add_128(sum0, mul_128(n4, L_scalar_u52[1]));
    part2(sum0, &carry, &r_scalar[0]);

    sum0 = add_128(carry, r[6]);
    sum0 = add_128(sum0, mul_128(n2, L_scalar_u52[4]));
    sum0 = add_128(sum0, mul_128(n4, L_scalar_u52[2]));
    part2(sum0, &carry, &r_scalar[1]);

    sum0 = add_128(carry, r[7]);
    sum0 = add_128(sum0, mul_128(n3, L_scalar_u52[4]));
    part2(sum0, &carry, &r_scalar[2]);

    sum0 = add_128(carry, r[8]);
    sum0 = add_128(sum0, mul_128(n4, L_scalar_u52[4]));
    part2(sum0, &carry, &r_scalar[3]);

    r_scalar[4] = carry.low;

    scalar_u52_sub(s, r_scalar, L_scalar_u52);
}

void __host__ __device__ scalar32_reduce(unsigned char *s) {
    scalar32_u52_t s_u52;
    scalar32_unpack(s_u52, s);

    uint128_t s_R[9];
    scalar52_mul(s_R, s_u52, R_scalar_u52);

    scalar32_u52_t s_R_mod_l;
    montgomery_reduce(s_R_mod_l, s_R);

    scalar32_pack(s, s_R_mod_l);
}


/*
Input:
  s[0]+256*s[1]+...+256^63*s[63] = s

Output:
  s[0]+256*s[1]+...+256^31*s[31] = s mod l
  where l = 2^252 + 27742317777372353535851937790883648493.
  Overwrites s in place.
*/

// 23x 21-bit limbs
void __host__ __device__ sc_reduce(unsigned char *s) {
    int64_t s0 = 2097151 & load_3(s);
    int64_t s1 = 2097151 & (load_4(s + 2) >> 5);
    int64_t s2 = 2097151 & (load_3(s + 5) >> 2);
    int64_t s3 = 2097151 & (load_4(s + 7) >> 7);
    int64_t s4 = 2097151 & (load_4(s + 10) >> 4);
    int64_t s5 = 2097151 & (load_3(s + 13) >> 1);
    int64_t s6 = 2097151 & (load_4(s + 15) >> 6);
    int64_t s7 = 2097151 & (load_3(s + 18) >> 3);
    int64_t s8 = 2097151 & load_3(s + 21);
    int64_t s9 = 2097151 & (load_4(s + 23) >> 5);
    int64_t s10 = 2097151 & (load_3(s + 26) >> 2);
    int64_t s11 = 2097151 & (load_4(s + 28) >> 7);
    int64_t s12 = 2097151 & (load_4(s + 31) >> 4);
    int64_t s13 = 2097151 & (load_3(s + 34) >> 1);
    int64_t s14 = 2097151 & (load_4(s + 36) >> 6);
    int64_t s15 = 2097151 & (load_3(s + 39) >> 3);
    int64_t s16 = 2097151 & load_3(s + 42);
    int64_t s17 = 2097151 & (load_4(s + 44) >> 5);
    int64_t s18 = 2097151 & (load_3(s + 47) >> 2);
    int64_t s19 = 2097151 & (load_4(s + 49) >> 7);
    int64_t s20 = 2097151 & (load_4(s + 52) >> 4);
    int64_t s21 = 2097151 & (load_3(s + 55) >> 1);
    int64_t s22 = 2097151 & (load_4(s + 57) >> 6);
    int64_t s23 = (load_4(s + 60) >> 3);
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;
    int64_t carry10;
    int64_t carry11;
    int64_t carry12;
    int64_t carry13;
    int64_t carry14;
    int64_t carry15;
    int64_t carry16;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    s23 = 0;
    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    s22 = 0;
    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    s21 = 0;
    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    s20 = 0;
    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    s19 = 0;
    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    s18 = 0;
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 << 21;
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 << 21;
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 << 21;
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 << 21;
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 << 21;
    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    s17 = 0;
    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    s16 = 0;
    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    s15 = 0;
    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    s14 = 0;
    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    s13 = 0;
    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;
    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;
    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;
    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;

    s[0] = (unsigned char) (s0 >> 0);
    s[1] = (unsigned char) (s0 >> 8);
    s[2] = (unsigned char) ((s0 >> 16) | (s1 << 5));
    s[3] = (unsigned char) (s1 >> 3);
    s[4] = (unsigned char) (s1 >> 11);
    s[5] = (unsigned char) ((s1 >> 19) | (s2 << 2));
    s[6] = (unsigned char) (s2 >> 6);
    s[7] = (unsigned char) ((s2 >> 14) | (s3 << 7));
    s[8] = (unsigned char) (s3 >> 1);
    s[9] = (unsigned char) (s3 >> 9);
    s[10] = (unsigned char) ((s3 >> 17) | (s4 << 4));
    s[11] = (unsigned char) (s4 >> 4);
    s[12] = (unsigned char) (s4 >> 12);
    s[13] = (unsigned char) ((s4 >> 20) | (s5 << 1));
    s[14] = (unsigned char) (s5 >> 7);
    s[15] = (unsigned char) ((s5 >> 15) | (s6 << 6));
    s[16] = (unsigned char) (s6 >> 2);
    s[17] = (unsigned char) (s6 >> 10);
    s[18] = (unsigned char) ((s6 >> 18) | (s7 << 3));
    s[19] = (unsigned char) (s7 >> 5);
    s[20] = (unsigned char) (s7 >> 13);
    s[21] = (unsigned char) (s8 >> 0);
    s[22] = (unsigned char) (s8 >> 8);
    s[23] = (unsigned char) ((s8 >> 16) | (s9 << 5));
    s[24] = (unsigned char) (s9 >> 3);
    s[25] = (unsigned char) (s9 >> 11);
    s[26] = (unsigned char) ((s9 >> 19) | (s10 << 2));
    s[27] = (unsigned char) (s10 >> 6);
    s[28] = (unsigned char) ((s10 >> 14) | (s11 << 7));
    s[29] = (unsigned char) (s11 >> 1);
    s[30] = (unsigned char) (s11 >> 9);
    s[31] = (unsigned char) (s11 >> 17);
}



/*
Input:
  a[0]+256*a[1]+...+256^31*a[31] = a
  b[0]+256*b[1]+...+256^31*b[31] = b
  c[0]+256*c[1]+...+256^31*c[31] = c

Output:
  s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
  where l = 2^252 + 27742317777372353535851937790883648493.
*/

void __host__ __device__ sc_muladd(unsigned char *s, const unsigned char *a, const unsigned char *b, const unsigned char *c) {
    int64_t a0 = 2097151 & load_3(a);
    int64_t a1 = 2097151 & (load_4(a + 2) >> 5);
    int64_t a2 = 2097151 & (load_3(a + 5) >> 2);
    int64_t a3 = 2097151 & (load_4(a + 7) >> 7);
    int64_t a4 = 2097151 & (load_4(a + 10) >> 4);
    int64_t a5 = 2097151 & (load_3(a + 13) >> 1);
    int64_t a6 = 2097151 & (load_4(a + 15) >> 6);
    int64_t a7 = 2097151 & (load_3(a + 18) >> 3);
    int64_t a8 = 2097151 & load_3(a + 21);
    int64_t a9 = 2097151 & (load_4(a + 23) >> 5);
    int64_t a10 = 2097151 & (load_3(a + 26) >> 2);
    int64_t a11 = (load_4(a + 28) >> 7);
    int64_t b0 = 2097151 & load_3(b);
    int64_t b1 = 2097151 & (load_4(b + 2) >> 5);
    int64_t b2 = 2097151 & (load_3(b + 5) >> 2);
    int64_t b3 = 2097151 & (load_4(b + 7) >> 7);
    int64_t b4 = 2097151 & (load_4(b + 10) >> 4);
    int64_t b5 = 2097151 & (load_3(b + 13) >> 1);
    int64_t b6 = 2097151 & (load_4(b + 15) >> 6);
    int64_t b7 = 2097151 & (load_3(b + 18) >> 3);
    int64_t b8 = 2097151 & load_3(b + 21);
    int64_t b9 = 2097151 & (load_4(b + 23) >> 5);
    int64_t b10 = 2097151 & (load_3(b + 26) >> 2);
    int64_t b11 = (load_4(b + 28) >> 7);
    int64_t c0 = 2097151 & load_3(c);
    int64_t c1 = 2097151 & (load_4(c + 2) >> 5);
    int64_t c2 = 2097151 & (load_3(c + 5) >> 2);
    int64_t c3 = 2097151 & (load_4(c + 7) >> 7);
    int64_t c4 = 2097151 & (load_4(c + 10) >> 4);
    int64_t c5 = 2097151 & (load_3(c + 13) >> 1);
    int64_t c6 = 2097151 & (load_4(c + 15) >> 6);
    int64_t c7 = 2097151 & (load_3(c + 18) >> 3);
    int64_t c8 = 2097151 & load_3(c + 21);
    int64_t c9 = 2097151 & (load_4(c + 23) >> 5);
    int64_t c10 = 2097151 & (load_3(c + 26) >> 2);
    int64_t c11 = (load_4(c + 28) >> 7);
    int64_t s0;
    int64_t s1;
    int64_t s2;
    int64_t s3;
    int64_t s4;
    int64_t s5;
    int64_t s6;
    int64_t s7;
    int64_t s8;
    int64_t s9;
    int64_t s10;
    int64_t s11;
    int64_t s12;
    int64_t s13;
    int64_t s14;
    int64_t s15;
    int64_t s16;
    int64_t s17;
    int64_t s18;
    int64_t s19;
    int64_t s20;
    int64_t s21;
    int64_t s22;
    int64_t s23;
    int64_t carry0;
    int64_t carry1;
    int64_t carry2;
    int64_t carry3;
    int64_t carry4;
    int64_t carry5;
    int64_t carry6;
    int64_t carry7;
    int64_t carry8;
    int64_t carry9;
    int64_t carry10;
    int64_t carry11;
    int64_t carry12;
    int64_t carry13;
    int64_t carry14;
    int64_t carry15;
    int64_t carry16;
    int64_t carry17;
    int64_t carry18;
    int64_t carry19;
    int64_t carry20;
    int64_t carry21;
    int64_t carry22;

    s0 = c0 + a0 * b0;
    s1 = c1 + a0 * b1 + a1 * b0;
    s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0;
    s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0;
    s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1 + a10 * b0;
    s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0;
    s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 + a8 * b4 + a9 * b3 + a10 * b2 + a11 * b1;
    s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2;
    s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
    s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
    s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    s20 = a9 * b11 + a10 * b10 + a11 * b9;
    s21 = a10 * b11 + a11 * b10;
    s22 = a11 * b11;
    s23 = 0;
    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 << 21;
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 << 21;
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 << 21;
    carry18 = (s18 + (1 << 20)) >> 21;
    s19 += carry18;
    s18 -= carry18 << 21;
    carry20 = (s20 + (1 << 20)) >> 21;
    s21 += carry20;
    s20 -= carry20 << 21;
    carry22 = (s22 + (1 << 20)) >> 21;
    s23 += carry22;
    s22 -= carry22 << 21;
    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 << 21;
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 << 21;
    carry17 = (s17 + (1 << 20)) >> 21;
    s18 += carry17;
    s17 -= carry17 << 21;
    carry19 = (s19 + (1 << 20)) >> 21;
    s20 += carry19;
    s19 -= carry19 << 21;
    carry21 = (s21 + (1 << 20)) >> 21;
    s22 += carry21;
    s21 -= carry21 << 21;
    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    s23 = 0;
    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    s22 = 0;
    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    s21 = 0;
    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    s20 = 0;
    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    s19 = 0;
    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    s18 = 0;
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 << 21;
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 << 21;
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 << 21;
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 << 21;
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 << 21;
    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    s17 = 0;
    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    s16 = 0;
    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    s15 = 0;
    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    s14 = 0;
    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    s13 = 0;
    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;
    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;
    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;
    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    
    s[0] = (unsigned char) (s0 >> 0);
    s[1] = (unsigned char) (s0 >> 8);
    s[2] = (unsigned char) ((s0 >> 16) | (s1 << 5));
    s[3] = (unsigned char) (s1 >> 3);
    s[4] = (unsigned char) (s1 >> 11);
    s[5] = (unsigned char) ((s1 >> 19) | (s2 << 2));
    s[6] = (unsigned char) (s2 >> 6);
    s[7] = (unsigned char) ((s2 >> 14) | (s3 << 7));
    s[8] = (unsigned char) (s3 >> 1);
    s[9] = (unsigned char) (s3 >> 9);
    s[10] = (unsigned char) ((s3 >> 17) | (s4 << 4));
    s[11] = (unsigned char) (s4 >> 4);
    s[12] = (unsigned char) (s4 >> 12);
    s[13] = (unsigned char) ((s4 >> 20) | (s5 << 1));
    s[14] = (unsigned char) (s5 >> 7);
    s[15] = (unsigned char) ((s5 >> 15) | (s6 << 6));
    s[16] = (unsigned char) (s6 >> 2);
    s[17] = (unsigned char) (s6 >> 10);
    s[18] = (unsigned char) ((s6 >> 18) | (s7 << 3));
    s[19] = (unsigned char) (s7 >> 5);
    s[20] = (unsigned char) (s7 >> 13);
    s[21] = (unsigned char) (s8 >> 0);
    s[22] = (unsigned char) (s8 >> 8);
    s[23] = (unsigned char) ((s8 >> 16) | (s9 << 5));
    s[24] = (unsigned char) (s9 >> 3);
    s[25] = (unsigned char) (s9 >> 11);
    s[26] = (unsigned char) ((s9 >> 19) | (s10 << 2));
    s[27] = (unsigned char) (s10 >> 6);
    s[28] = (unsigned char) ((s10 >> 14) | (s11 << 7));
    s[29] = (unsigned char) (s11 >> 1);
    s[30] = (unsigned char) (s11 >> 9);
    s[31] = (unsigned char) (s11 >> 17);
}
