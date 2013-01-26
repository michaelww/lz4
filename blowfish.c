#include <string.h>

#include "blowfish.h"
#include "blowfish_init.h"

typedef uint32_t u32;

#define NR BLOWFISH_ROUNDS  /* Num rounds */
#define NP (NR+2) /* Num P subkeys */

static inline void swap32(u32 *x, u32 *y) {
    u32 tmp = *x; *x = *y; *y = tmp;
}

static inline u32 blowfish_feistel(const u32 S[], u32 x)
{
#define Subst(s,i,j) (s)[(i)*256+(j)]
    uint8_t a,b,c,d; /* Bytes of `x` with a most significant byte */
    a = (x >> 24) & 0xff;
    b = (x >> 16) & 0xff;
    c = (x >>  8) & 0xff;
    d = (x      ) & 0xff;
    return ((Subst(S,0,a) + Subst(S,1,b)) ^ Subst(S,2,c)) + Subst(S,3,d);
#undef Subst
}

void blowfish_encrypt(u32 x[2], const struct blowfish_key *bf_key)
{
    x[0] ^= bf_key->P[0];
    for (unsigned i = 1; i <= NR; ) {
        x[1] = blowfish_feistel(bf_key->S, x[0]) ^ x[1] ^ bf_key->P[i++];
        x[0] = blowfish_feistel(bf_key->S, x[1]) ^ x[0] ^ bf_key->P[i++];
    }
    x[1] ^= bf_key->P[NR+1];
    swap32(&x[0], &x[1]);
}

void blowfish_decrypt(u32 x[2], const struct blowfish_key *bf_key)
{
    x[0] ^= bf_key->P[NR+1];
    for (unsigned i = NR; i >= 2; ) {
        x[1] = blowfish_feistel(bf_key->S, x[0]) ^ x[1] ^ bf_key->P[i--];
        x[0] = blowfish_feistel(bf_key->S, x[1]) ^ x[0] ^ bf_key->P[i--];
    }
    x[1] ^= bf_key->P[0];
    swap32(&x[0], &x[1]);
}

/* At least 16 bytes of key is recommended. */
void blowfish_keyderiv(const unsigned char *key, unsigned key_len,
                       struct blowfish_key *bf_key) 
{
    /* Initialize subkey start values */
    memcpy(bf_key->P, bf_p_init, sizeof(bf_key->P));
    memcpy(bf_key->S, bf_sbox_init, sizeof(bf_key->S));
    /* Apply key */
    if (key_len <  1) key_len = 1;
    if (key_len > 56) key_len = 56;
    unsigned j = 0;
    for (unsigned i = 0; i < NP; i++) {
        u32 K = 0;
        K |= key[j++ % key_len]; K <<= 8;
        K |= key[j++ % key_len]; K <<= 8;
        K |= key[j++ % key_len]; K <<= 8;
        K |= key[j++ % key_len];
        bf_key->P[i] ^= K;
    }
    /* Subkey computation */
    u32 x[2] = {0,0};
    for (unsigned i = 0; i < NP; i += 2) {
        blowfish_encrypt(x, bf_key);
        bf_key->P[i]   = x[0];
        bf_key->P[i+1] = x[1];
    }
    for (unsigned i = 0; i < 4*256; i += 2) {
        blowfish_encrypt(x, bf_key);
        bf_key->S[i]   = x[0];
        bf_key->S[i+1] = x[1];
    }
}

#ifdef TEST
#include <stdio.h>

static int bf_test_enc(void *key, unsigned key_len, const u32 clear[2],
                       const u32 expect[2])
{
    struct blowfish_key bf_key;
    u32 input[2] = {clear[0], clear[1]};
    blowfish_keyderiv(key, key_len, &bf_key);
    blowfish_encrypt(input, &bf_key);
    if (input[0] != expect[0] || input[1] != expect[1]) {
        fprintf(stderr, "Encrypt FAIL: %08x%08x, Expected %08x%08x\n",
                input[0],input[1], expect[0],expect[1]);
        return 1;
    }
    blowfish_decrypt(input, &bf_key);
    if (clear[0] != input[0] || clear[1] != input[1]) {
        fprintf(stderr, "Decrypt FAIL: %08x%08x, Expected %08x%08x\n",
                input[0], input[1], clear[0], clear[1]);
    }
    return 0;
}


#include "bf_vectors.txt"
static int test_vectors(void)
{
    bf_test_enc((u32[]){0,0}, 8, (u32[]){0,0}, (u32[]){0x4EF99745,0x6198DD78});
    for (unsigned i = 0; i < NUM_VARIABLE_KEY_TESTS; i++) {
        bf_test_enc(variable_key[i], 8,
                    (u32[]){plaintext_l[i], plaintext_r[i]},
                    (u32[]){ciphertext_l[i],ciphertext_r[i]});
    }
    for (unsigned i = 0; i < NUM_SET_KEY_TESTS; i++) {
        unsigned j = i + NUM_VARIABLE_KEY_TESTS;
        bf_test_enc(set_key, i+1,
                    (u32[]){plaintext_l[j], plaintext_r[j]},
                    (u32[]){ciphertext_l[j],ciphertext_r[j]});
    }
    return 0;
}

int main(void)
{
    test_vectors();
}
#endif
