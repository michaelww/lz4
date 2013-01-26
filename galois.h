#ifndef GALOIS_H_
#define GALOIS_H_

#define GF_TAB_BITS 4
#define GF_TAB_X (64/GF_TAB_BITS)
#define GF_TAB_Y (1 << GF_TAB_BITS)

#define u64 uint64_t
#define u32 uint32_t
typedef u64 gf_table[GF_TAB_X][GF_TAB_Y];

/* Galois Field GF(2^64) each element is a polynomial with coeffs in GF(2).
 * Addition and Subtraction is xor.
 * We implement multiplication modulo the irreducible polynomial.
 */

static u64 gf_mul_64(u64 x, u64 y, u64 poly)
{
    /* Use branchless  ~1+1 = 0xfff..fff; ~0+1 = 0 */
    u64 prod = 0;
    u32 y_hi = y >> 32;
    u32 y_lo = y;
    for (unsigned i = 0; i < 32; i++) {
        /* if bit `i` of y is set, add `x` to the product */
        prod ^= x & (~(u64)((y_lo >> i) & 0x1)+1);
        /* add `poly` if the carry bit is set */
        x = (x << 1) ^ (poly & (~(x >> 63)+1));
    }
    for (unsigned i = 0; i < 32; i++) {
        prod ^= x & (~(u64)((y_hi >> i) & 0x1)+1);
        x = (x << 1) ^ (poly & (~(x >> 63)+1));
    }
    return prod;
}

static u64 gf_tmul_64(u64 x, gf_table T)
{
    u64 prod = 0;
    u32 xl = x, xh = x >> 32;
    for (unsigned i = 0, k = GF_TAB_X/2; i < GF_TAB_X/2;) {
        prod ^= T[i++][xl & (GF_TAB_Y-1)]; xl >>= GF_TAB_BITS;
        prod ^= T[k++][xh & (GF_TAB_Y-1)]; xh >>= GF_TAB_BITS;
        prod ^= T[i++][xl & (GF_TAB_Y-1)]; xl >>= GF_TAB_BITS;
        prod ^= T[k++][xh & (GF_TAB_Y-1)]; xh >>= GF_TAB_BITS;
        prod ^= T[i++][xl & (GF_TAB_Y-1)]; xl >>= GF_TAB_BITS;
        prod ^= T[k++][xh & (GF_TAB_Y-1)]; xh >>= GF_TAB_BITS;
        prod ^= T[i++][xl & (GF_TAB_Y-1)]; xl >>= GF_TAB_BITS;
        prod ^= T[k++][xh & (GF_TAB_Y-1)]; xh >>= GF_TAB_BITS;
    }
    return prod;
}

static void gf_mk_tab(u64 h, u64 poly, gf_table T)
{
    for (unsigned i = 0; i < GF_TAB_X; i++)
        for (unsigned j = 0; j < GF_TAB_Y; j++)
            T[i][j] = gf_mul_64((u64)j << (GF_TAB_BITS*i), h, poly);
}

#undef u64
#undef u32
#undef GF_TAB_BITS
#undef GF_TAB_X
#undef GF_TAB_Y

#endif /* GALOIS_H_ */

