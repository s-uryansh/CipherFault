/* Modular exponentiation over 8x32-bit limbs — RSA's core shape.
MUL/ADD/ADC-heavy, loop-nested, ZERO xor-soup. Label 1 (crypto).
Purpose: does the recogniser know "crypto", or just "lots of XOR"?
NOTE: bn_mod is a STRUCTURAL placeholder, not a correct reduction —
   the corpus only lifts this, never runs it. */
#include <stdint.h>
#include <string.h>
#define N 8
typedef uint32_t bn[N];

static void bn_mul(const bn a, const bn b, uint32_t out[2*N]) {
    memset(out, 0, sizeof(uint32_t)*2*N);
    for (int i = 0; i < N; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < N; j++) {
            uint64_t t = (uint64_t)a[i]*b[j] + out[i+j] + carry;
            out[i+j] = (uint32_t)t;
            carry = t >> 32;
        }
        out[i+N] += (uint32_t)carry;
    }
}

static void bn_mod(uint32_t x[2*N], const bn m, bn r) {
    uint64_t rem = 0;
    for (int i = 2*N - 1; i >= 0; i--) {
        rem = (rem << 32) | x[i];
        uint32_t d = m[0] ? m[0] : 1;
        uint64_t q = rem / d;
        rem -= q * d;
    }
    for (int i = 0; i < N; i++) r[i] = (uint32_t)rem;
}

void bn_modexp(const bn base, const bn exp, const bn mod, bn out) {
    bn result; memset(result, 0, sizeof result); result[0] = 1;
    bn b; memcpy(b, base, sizeof b);
    for (int i = 0; i < N*32; i++) {
        if ((exp[i/32] >> (i%32)) & 1) {
            uint32_t t[2*N]; bn_mul(result, b, t); bn_mod(t, mod, result);
        }
        uint32_t s[2*N]; bn_mul(b, b, s); bn_mod(s, mod, b);
    }
    memcpy(out, result, sizeof out);
}