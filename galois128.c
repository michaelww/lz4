#ifndef GALOIS128_H_
#define GALOIS128_H_

#include <stdint.h>

/* Calculate multiplication over the Finite Field GF(2^128)
 * modulo an irreducible polynomial.
 * The polynomial is specified in binary format ignoring
 * the highest power (x^128). It is assumed this fits in 64 bits.
 */

#define GF_TAB_BITS 4
#define GF_TAB_X (128/GF_TAB_BITS)
#define GF_TAB_Y (1 << GF_TAB_BITS)
#define u64 uint64_t

typedef struct { uint64_t hi; uint64_t lo; } u128;
typedef u128 gf_table128[GF_TAB_X][GF_TAB_Y];

#define U128_ZERO {0,0}
#define U128_INIT(x,y) {.hi=(x), .lo=(y)}
#define U128_IXOR(x,y) (x.hi ^= y.hi, x.lo ^= y.lo)
#define U128_IXOR_IFBIT(x,y,bit) \
    do { \
        /* Use branchless  ~1+1 = 0xfff..fff; ~0+1 = 0 */ \
        x.hi ^= (y.hi & (~(u64)(bit)+1)); \
        x.lo ^= (y.lo & (~(u64)(bit)+1)); \
    } while (0)

/* Requires 0 < n < 64 */
#define U128_SHR(x,n) (x.lo = (x.lo >> (n) ^ (x.hi << (64-(n)))), x.hi >>= (n))
#define U128_SHL(x,n) (x.hi = (x.hi << (n) ^ (x.lo >> (64-(n)))), x.lo <<= (n))
        
static void gf_mul_nomod_64(u128 *rx, u64 x, u64 a,
                            u128 *ry, u64 y, u64 b,
                            u128 *rz, u64 z, u64 c)
{
    *rx = (u128)U128_ZERO;
    *ry = (u128)U128_ZERO;
    *rz = (u128)U128_ZERO;
    u128 xw = U128_INIT(0,x);
    u128 yw = U128_INIT(0,y);
    u128 zw = U128_INIT(0,z);
    for (unsigned i = 0; i < 64; i++) {
        U128_IXOR_IFBIT((*rx), xw, a & 1);
        a >>= 1;
        U128_SHL(xw,1);
    }

    for (unsigned i = 0; i < 64; i++) {
        U128_IXOR_IFBIT((*ry), yw, b & 1);
        b >>= 1;
        U128_SHL(yw,1);
    }

    for (unsigned i = 0; i < 64; i++) {
        U128_IXOR_IFBIT((*rz), zw, c & 1);
        c >>= 1;
        U128_SHL(zw,1);
    }
}
static u128 gf_mul_split128(u128 x, u128 y, u64 poly)
{
    /* Carryless multiply x and y in GF(2^128) modulo `poly`
     * Addition in GF(2) is xor.
     *
     * Split following Karatsuba
     * N1 = a0 + a1w
     * N2 = b0 + b1w
     * P = a0b0 + (a0b1 + a1b0)w + a1b1w**2
     * Use
     * (a0b1 + a1b0) = (a0 + a1)(b0 + b1) - a0b0 - a1b1
     */
    u128 r1, r2;
    u128 q0, q1, q2;
    u64 poly1 = poly >> 1;
    gf_mul_nomod_64(&q0, x.hi, y.hi,
                    &q1, x.hi ^ x.lo, y.hi ^ y.lo,
                    &q2, x.lo, y.lo);
    /* p1 = q1 - q0 - q2 */

    r1 = q0;
    r2 = q2;
    r1.lo ^= q1.hi ^ q0.hi ^ q2.hi;
    r2.hi ^= q1.lo ^ q0.lo ^ q2.lo;

    /* Do the modulo `poly` reduction */
    for (unsigned i = 0; i < 64; i++) {
        u64 mask = ~((r1.hi >> (63-i)) & 0x1) + 1;
        r1.lo ^= (poly1 >> i) & mask;
        r2.hi ^= (poly << (63-i)) & mask;
    }
    for (unsigned i = 0; i < 64; i++) {
        u64 mask = ~((r1.lo >> (63-i)) & 0x1) + 1;
        r2.hi ^= (poly1 >> i) & mask;
        r2.lo ^= (poly << (63-i)) & mask;
    }
    /*

     |76543210|76543210|76543210|76543210|
      10000000 11001000 1                     
        poly grade 16

     */
    return r2;
}

static u128 gf_mul_128(u128 x, u128 y, u64 poly)
{
    /* Carryless multiply x and y in GF(2^128) modulo `poly`
     * Addition in GF(2) is xor.
     */
    u128 prod = U128_ZERO;
    u64 carry;
    for (unsigned i = 0; i < 64; i++) {
        U128_IXOR_IFBIT(prod, x, (y.lo >> i) & 1);
        carry = x.hi >> 63;
        U128_SHL(x,1);
        x.lo ^= poly & (~carry + 1);
    }
    for (unsigned i = 0; i < 64; i++) {
        U128_IXOR_IFBIT(prod, x, (y.hi >> i) & 1);
        carry = x.hi >> 63;
        U128_SHL(x,1);
        x.lo ^= poly & (~carry + 1);
    }
    return prod;
}

static u128 gf_mul_tab128(u128 x, gf_table128 table)
{
    u128 prod = U128_ZERO;
    unsigned i = 0;
    /* lo, then hi */
    for (unsigned j = 0; j < 2; j++) {
        for (unsigned k = 0; k < GF_TAB_X/2; k++) {
            u128 tab_val = table[i++][x.lo & (GF_TAB_Y-1)];
            U128_IXOR(prod, tab_val);
            x.lo >>= GF_TAB_BITS;
        }
        x.lo = x.hi;
    }
    return prod;
}

static void gf_mk_tab128(u128 h, u64 poly, gf_table128 table)
{
    unsigned i = 0;
    for (; i < GF_TAB_X/2; i++)
        for (unsigned j = 0; j < GF_TAB_Y; j++) {
            u128 jx = U128_INIT(0, (u64)j << GF_TAB_BITS*i);
            table[i][j] = gf_mul_128(jx, h, poly);
        }
    for (; i < GF_TAB_X; i++)
        for (unsigned j = 0; j < GF_TAB_Y; j++) {
            u128 jx = U128_INIT((u64)j << (GF_TAB_BITS*i - 64), 0);
            table[i][j] = gf_mul_128(jx, h, poly);
        }
}

#undef u64
#undef GF_TAB_BITS
#undef GF_TAB_X
#undef GF_TAB_Y

#endif /* GALOIS128_H_ */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define u64 uint64_t

static void test_gf_mul(void) {
    u128 one = U128_INIT(0,1);
    uint64_t gcm_poly = 1 + (1<<1) + (1<<2) + (1<<7); 
    srand(time(NULL));
#define gf_mul(x,y) (gf_mul_split128((x), (y), gcm_poly))
#define gf_mul_alt(x,y) (gf_mul_128((x), (y), gcm_poly))
#define RND_64 ((u64)rand() << 32 | rand())
#define U128_EQ(x,y) (((x).hi == (y).hi) && ((x).lo == (y).lo))
#define U128_XOR(x,y) ((u128){.hi = (x).hi ^ (y).hi, .lo = (x).lo ^ (y).lo})
    for (unsigned i = 0; i < 32; i++) {
        u128 x = U128_INIT(RND_64, RND_64);
        u128 y = U128_INIT(RND_64, RND_64);
        u128 z = U128_INIT(RND_64, RND_64);
        if (!U128_EQ(gf_mul(one, x), x))
            printf("gf FAIL: mismatch on %d\n", __LINE__);
        if (!U128_EQ(gf_mul(one, x), gf_mul(x, one)))
            printf("gf FAIL: mismatch on %d\n", __LINE__);
        /* commutativity */
        if (!U128_EQ(gf_mul(y, x), gf_mul(x, y)))
            printf("gf FAIL: mismatch on %d\n", __LINE__);
        /* distributivity over xor */
        u128 q1 = gf_mul(U128_XOR(y, x), z);
        u128 q2 = U128_XOR(gf_mul(y, z), gf_mul(z, x));
        if (!U128_EQ(q1,q2))
            printf("gf FAIL: mismatch on %d\n", __LINE__);
        /* associativity */
        u128 r1 = gf_mul(x, gf_mul(y, z));
        u128 r2 = gf_mul(gf_mul(x, y), z);
        if (!U128_EQ(r1,r2))
            printf("gf FAIL: mismatch on %d\n", __LINE__);

        /* equivalence */
        if (!U128_EQ(gf_mul(x,y), gf_mul_alt(x,y)))
            printf("gf FAIL: mismatch %s on %d\n", "equiv", __LINE__);
        if (!U128_EQ(gf_mul(z,x), gf_mul_alt(z,x)))
            printf("gf FAIL: mismatch %s on %d\n", "equiv", __LINE__);
    }
#undef gf_mul
}

#include <stdio.h>
int main(void) {
    gf_table128 tab;
    uint64_t gcm_poly = 1 + (1<<1) + (1<<2) + (1<<7); 
    u128 x = {.hi=0xfeed3eeeeeeee,.lo=0x230209}, y={.hi=0x12345660cafebabe, .lo=0xcafebabe};
    u128 r = U128_ZERO, r2 = U128_ZERO;

    r = gf_mul_128(x,y, gcm_poly);
    gf_mk_tab128(y, gcm_poly, tab);
    r2 = gf_mul_tab128(x, tab);
    printf("%016llx %016llx\n", r.hi, r.lo);
    printf("%016llx %016llx\n", r2.hi, r2.lo);

    u128 p,q,m;
    gf_mul_nomod_64(&p, UINT64_MAX, UINT64_MAX, &q, 1, 1, &m, 3, UINT64_MAX);
    printf("%016llx %016llx\n", p.hi, p.lo);
    printf("%016llx %016llx\n", q.hi, q.lo);
    printf("%016llx %016llx\n", m.hi, m.lo);
    p = gf_mul_split128((u128){3,1}, (u128){0, UINT64_MAX}, gcm_poly);
    printf("%016llx %016llx\n", p.hi, p.lo);
    p = gf_mul_split128(x, y, gcm_poly);
    printf("%016llx %016llx\n", p.hi, p.lo);

    test_gf_mul();
}

