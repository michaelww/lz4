#define _XOPEN_SOURCE 700
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include "blowfish.h"

#include "galois.h"
#define GCM_GF2_64_POLY (0x1b) /* 1 + x + x^3 + x^4 + x^64 */

#define GCM_AUTH_TAG_LEN 8
#define GCM_NONCE_LEN    8
#define BF_BLOCK (BLOWFISH_BLOCK_BITS/8)
#define BF_BLOCK_MASK (BF_BLOCK-1)

typedef uint32_t u32;
typedef uint64_t u64;

static inline void write_be32(unsigned char *y, u32 x) {
    static const int _one = 1;
    if (*(unsigned char *)&_one == 0) { *(u32 *)y = x; return; }
    *y++ = (x >> 24) & 0xff;
    *y++ = (x >> 16) & 0xff;
    *y++ = (x >>  8) & 0xff;
    *y++ = (x      ) & 0xff;
}

static inline void write_be64(unsigned char *y, u64 x) {
    write_be32(y, x >> 32);
    write_be32(y+4, x & 0xffffffff);
}

#define W64(x,y) ((u64)(x) << 32 | (u64)(y))

static inline u32 read_be32(const unsigned char *x) {
    static const int _one = 1;
    if (*(unsigned char *)&_one == 0) return *(u32 *)x;
    return (((u32)x[3]      ) | ((u32)x[2] <<  8) |
            ((u32)x[1] << 16) | ((u32)x[0] << 24));
}
static inline u64 read_be64(const unsigned char *x) {
    return W64(read_be32(x), read_be32(x+4));
}


/* Require 2 elements in `out` */
static inline void blowfish_stream(u32 x[2], u64 nonce, u64 *ctr,
                                   const struct blowfish_key *bf_key)
{
    x[0] = (*ctr ^ nonce) >> 32;
    x[1] = (*ctr ^ nonce) & 0xffffffff;
    blowfish_encrypt(x, bf_key);
    (*ctr)++;
}

static void print_escaped(const unsigned char *s, unsigned len)
{
    while (len--) {
        printf("\\x%02x", *s);
        s++;
    }
    printf("\n");
}
static void print_hexvis(const unsigned char *s, unsigned len)
{
    while (len--) {
        if (*s > ' ' && *s <= 126)
            printf(" %c", *s);
        else
            printf("\033[00;35m%02x\033[m", *s);
        s++;
    }
    printf("\n");
}

static void get_zeropad(u32 plain[2], const unsigned char *buf, size_t len)
{
    plain[0] = plain[1] = 0;
    switch (len) {
        case 8: plain[1] |= (u32)buf[7];
        case 7: plain[1] |= (u32)buf[6] <<  8;
        case 6: plain[1] |= (u32)buf[5] << 16;
        case 5: plain[1] |= (u32)buf[4] << 24;
        case 4: plain[0] |= (u32)buf[3];
        case 3: plain[0] |= (u32)buf[2] <<  8;
        case 2: plain[0] |= (u32)buf[1] << 16;
        case 1: plain[0] |= (u32)buf[0] << 24;
    }
}

#define MUL_H(ctx, x) gf_tmul_64((x), (ctx)->h_table)

struct bf_gcm_ctx {
    gf_table h_table;
    u64 auth_tag;
    u64 nonce;
    u64 ctr;
    u64 total_len;
};

static void bf_gcm_init(struct bf_gcm_ctx *ctx, u64 nonce,
                        const struct blowfish_key *bf_key)
{
    u32 H[2] = {0,0};
    blowfish_encrypt(H, bf_key);
    gf_mk_tab(W64(H[0], H[1]), GCM_GF2_64_POLY, ctx->h_table);
    ctx->auth_tag = 0;
    ctx->ctr = 1;
    ctx->nonce = nonce;
    ctx->total_len = 0;
}

/* Calculate the final auth_tag and clear all other fields */
static void bf_gcm_finish(struct bf_gcm_ctx *ctx, u64 *auth_tag,
                          const struct blowfish_key *bf_key)
{
    u32 ciph_zero[2];
    u64 ctr_zero = 0;
    blowfish_stream(ciph_zero, ctx->nonce, &ctr_zero, bf_key);
    ctx->auth_tag = MUL_H(ctx, ctx->auth_tag ^ ctx->total_len);
    ctx->auth_tag ^= W64(ciph_zero[0], ciph_zero[1]);

    *auth_tag = ctx->auth_tag;
    memset(ctx, 0, sizeof(*ctx));
}

#define bf_gcm_encrypt_stream(ctx,...) bf_gcm_crypt_stream(ctx,0,__VA_ARGS__)
#define bf_gcm_decrypt_stream(ctx,...) bf_gcm_crypt_stream(ctx,1,__VA_ARGS__)
/* `cstream` is the variable that should be passed to
 * the auth tag, either `x` or `text`
 */
static void bf_gcm_crypt_stream(struct bf_gcm_ctx *ctx, int is_decrypt,
                                unsigned char *out, const unsigned char *src,
                                size_t len, const struct blowfish_key *bf_key)
{
    u32 x[2], text[2];
    size_t block_len = len - (len & BF_BLOCK_MASK);
    u32 *cstream = is_decrypt ? text : x;
    for (size_t j = 0; j < block_len; j += BF_BLOCK) {
        blowfish_stream(x, ctx->nonce, &ctx->ctr, bf_key);
        text[0] = read_be32(src+j);
        text[1] = read_be32(src+j+4);
        x[0] ^= text[0];
        x[1] ^= text[1];
        write_be32(out+j, x[0]);
        write_be32(out+j+4, x[1]);
        ctx->auth_tag = MUL_H(ctx, ctx->auth_tag ^ W64(cstream[0], cstream[1]));
    }
    if (len & BF_BLOCK_MASK) {
        u64 ciphertext = 0;
        blowfish_stream(x, ctx->nonce, &ctx->ctr, bf_key);
        get_zeropad(text, src + block_len, len & BF_BLOCK_MASK);

        if (is_decrypt) {
            /* Pad ciphertext past the message length */
            ciphertext |= W64(x[0], x[1]);
            ciphertext &= ((u64)1 << (BF_BLOCK - (len & BF_BLOCK_MASK))*8)-1;
        }

        x[0] ^= text[0];
        x[1] ^= text[1];
        write_be32(out+block_len, x[0]);
        write_be32(out+block_len+4, x[1]);
        ciphertext |= W64(cstream[0], cstream[1]);
        ctx->auth_tag = MUL_H(ctx, ctx->auth_tag ^ ciphertext);
    }
    ctx->total_len += len;
}

static size_t bf_gcm_enc(unsigned char *out, const unsigned char *src,
                         size_t len, u64 nonce, u64 *auth_tag,
                         const struct blowfish_key *bf_key)
{
    struct bf_gcm_ctx ctx;
    bf_gcm_init(&ctx, nonce, bf_key);
    bf_gcm_encrypt_stream(&ctx, out, src, len, bf_key);
    bf_gcm_finish(&ctx, auth_tag, bf_key);

    write_be64(out+len, *auth_tag);
    return len + GCM_AUTH_TAG_LEN;
}

enum bf_gcm_err { bf_gcm_continue = 0, bf_gcm_auth_ok = 1, bf_gcm_auth_fail = -1};

static enum bf_gcm_err bf_gcm_dec(unsigned char *out, const unsigned char *src,
                                  size_t len, u64 nonce, u64 *auth_tag,
                                  const struct blowfish_key *bf_key)
{
    struct bf_gcm_ctx ctx;
    bf_gcm_init(&ctx, nonce, bf_key);
    bf_gcm_decrypt_stream(&ctx, out, src, len, bf_key);
    bf_gcm_finish(&ctx, auth_tag, bf_key);

    u64 stream_auth_tag = read_be64(src+len);
    if (*auth_tag != stream_auth_tag) {
        printf("INVALID Stream tag: %016"PRIx64", Decrypt Tag: %016"PRIx64"\n",
               stream_auth_tag, *auth_tag);
        return bf_gcm_auth_fail;
    }
    return bf_gcm_auth_ok;
}


#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>

static int test_gcm_decrypt(const void *key, int key_len,
                            u64 nonce, const void *text, size_t len,
                            u64 exp_auth_tag)
{
    struct blowfish_key bf_key;
    blowfish_keyderiv(key, key_len, &bf_key);

    unsigned char buf[128] = {0};
    u64 auth_tag;

    len -= GCM_AUTH_TAG_LEN; /* remove auth tag length */
    int ret = bf_gcm_dec(buf, text, len, nonce, &auth_tag, &bf_key);
    if (ret != bf_gcm_auth_ok) {
        printf("Authenticated decryption failed!\n");
        print_hexvis(buf, len);
        return 0;
    }
    if (auth_tag != exp_auth_tag) {
        printf("Wrong Auth Tag, Got %016"PRIx64" Exp %016"PRIx64"\n",
               auth_tag, exp_auth_tag);
        return 0;
    }
    printf("Pass Decrypt with Auth Tag: %016"PRIx64"\n", auth_tag);
    return 1;
}

static int test_gcm_encrypt(const void *key, int key_len,
                            u64 nonce, const void *text, unsigned len,
                            const void *exp, unsigned exp_len)
{
    struct blowfish_key bf_key;
    blowfish_keyderiv(key, key_len, &bf_key);

    unsigned char buf[128] = {0};
    u64 auth_tag;

    bf_gcm_enc(buf, text, len, nonce, &auth_tag, &bf_key);
    if (exp_len != len + GCM_AUTH_TAG_LEN || !!memcmp(exp, buf, exp_len)) {
        printf("FAIL encryption, got: ");
        print_escaped(buf, len+GCM_AUTH_TAG_LEN);
        return 0;
    }
    printf("Pass Encrypt with Auth Tag: %016"PRIx64"\n", auth_tag);
    return 1;
}

static void test_vec_random(void)
{
    int verbose = 0;
    unsigned n_tests = 32;
    struct blowfish_key bf_key;
    unsigned char p[1024], q[1024], r[1024];
    unsigned char nonce_buf[GCM_NONCE_LEN];
    unsigned char k[56] = {0};
    u64 nonce;
    unsigned long r_seed = time(NULL);
    srand(r_seed);

    printf("Running randomized tests: ");

    /* Repeated random tests */
    for (unsigned j = 0; j < n_tests; j++) {
        for (unsigned i = 0; i < GCM_NONCE_LEN; i++)
            nonce_buf[i] = (rand() >> 8) & 0xff;
        memcpy(&nonce, nonce_buf, sizeof(nonce));

        unsigned input_length = 1 + 384*(1.0f*rand()/RAND_MAX);
        unsigned key_length = 1 + 55*(1.0f*rand()/RAND_MAX);
        for (unsigned i = 0; i < key_length; i++)
            k[i] = (rand() >> 8) & 0xff;
        blowfish_keyderiv(k, key_length, &bf_key);

        for (unsigned i = 0; i < input_length; i++)
            p[i] = (rand() >> 8) & 0xff;

        u64 auth_tag;
        enum bf_gcm_err retval;
        int test_ok = 1;
        //memset(p, 0, sizeof(p));
        memset(q, 0, sizeof(q));
        memset(r, 0, sizeof(r));
        bf_gcm_enc(q, p, input_length, nonce, &auth_tag, &bf_key);
        if (!!memcmp(q+input_length+GCM_AUTH_TAG_LEN, r,
                     sizeof(q)-input_length-GCM_AUTH_TAG_LEN))
            printf("FAIL: Wrote past bounds");
        retval = bf_gcm_dec(r, q, input_length, nonce, &auth_tag, &bf_key);
        if (retval != bf_gcm_auth_ok) {
            printf("Decryption Auth failed!\n");
            test_ok = 0;
        }
        if (!!memcmp(p, r, input_length)) {
            printf("Decryption Equiv failed!\n");
            test_ok = 0;
        }
        if (verbose || !test_ok) {
            printf("Test params j=%u, len=%u, keylen=%u, seed=%lu, "
                   "auth_tag=%016"PRIx64"\n",
                   j, input_length, key_length, r_seed, auth_tag);
        }
        if (!verbose) printf(".");
    }
    printf(" DONE\n");
}

static void test_vectors(void) {
    const unsigned char key[16] = {1,2,3};
    u64 auth_tag1 = 0x7f9b7b598912f87b;
    u64 nonce1 = 123;
    const unsigned char v1[] = "This is the plain text. Attack at noon.";
    const unsigned char v1_exp[] = {
        "\x23\xfc\xcd\x42\x73\x15\xe2\x8f\x7f\xf1\x09\x58\x56\xbf\x28\x83"
        "\x18\xb7\x88\xaa\x9e\x1d\xf0\xd5\x33\xda\xa5\xc5\x31\x9a\x38\x76"
        "\x0f\x0d\xad\x57\xd3\xf7\xf3\x7f\x9b\x7b\x59\x89\x12\xf8\x7b"};
    test_gcm_encrypt(key, 16, nonce1, v1, sizeof(v1)-1, v1_exp, sizeof(v1_exp)-1);
    test_gcm_decrypt(key, 16, nonce1, v1_exp, sizeof(v1_exp)-1, auth_tag1);
    const unsigned char v2[] = "blow me.";
    const unsigned char v2_exp[] = \
           "\x15\xf8\xcb\x46\x73\x11\xf4\x81\x28\xc5\x09\xca\x68\xa3\xfd\x44";
    u64 auth_tag2 = 0x28c509ca68a3fd44;
    test_gcm_encrypt(key, 16, nonce1, v2, sizeof(v2)-1, v2_exp, sizeof(v2_exp)-1);
    test_gcm_decrypt(key, 16, nonce1, v2_exp, sizeof(v2_exp)-1, auth_tag2);

    /* Length is block size + 1 */
    const unsigned char v3[] = "Eight + 1";
    const unsigned char v3_exp[] = \
       "\x32\xfd\xc3\x59\x27\x5c\xba\x8f\x3a\x6c\xd8\x64\x84\xc5\xb2\xc8\xdc";
    u64 auth_tag3 = 0x6cd86484c5b2c8dc;
    test_gcm_encrypt(key, 16, nonce1, v3, sizeof(v3)-1, v3_exp, sizeof(v3_exp)-1);
    test_gcm_decrypt(key, 16, nonce1, v3_exp, sizeof(v3_exp)-1, auth_tag3);
}

static void test_gf_mul(void) {
    u64 one = 1;
#define gf_mul(x,y) (gf_mul_64((x), (y), GCM_GF2_64_POLY))

    u64 a = 0x7f9b7b598912f87b;
    u64 b = 0x28c509ca68a3fd44;
    u64 exp_res = 0x7c1520de109266eb;
    if (gf_mul(a, b) != exp_res)
        printf("gf FAIL: mismatch, got %016"PRIx64"\n", gf_mul(a,b));

    for (unsigned i = 0; i < 32; i++) {
        u64 x = W64(rand(), rand());
        u64 y = W64(rand(), rand());
        u64 z = rand()*(u64)rand();
        if (gf_mul(one, x) != x)
            printf("gf FAIL: mismatch on %d\n", __LINE__);
        /* commutativity */
        if (gf_mul(x, z) != gf_mul(z, x))
            printf("gf FAIL: mismatch on %d\n", __LINE__);
        /* distributivity over addition */
        if (gf_mul(y ^ x, z) != (gf_mul(y, z) ^ gf_mul(z, x)))
            printf("gf FAIL: mismatch on %d\n", __LINE__);
        /* associativity */
        if (gf_mul(x, gf_mul(y, z)) != gf_mul(gf_mul(x, y), z))
            printf("gf FAIL: mismatch on %d\n", __LINE__);

        /* equivalence */
        gf_table tab;
        gf_mk_tab(x, GCM_GF2_64_POLY, tab);
        if (gf_tmul_64(y, tab) != gf_mul(y, x))
            printf("gf FAIL: mismatch on %d\n", __LINE__);
        if (gf_tmul_64(z, tab) != gf_mul(z, x))
            printf("gf FAIL: mismatch on %d\n", __LINE__);
    }
#undef gf_mul
}


/* Retry on EINTR */
static int xread(int fd, void *buf, int bytes) {
    int rd = 0;
    while (rd != bytes) {
        int ret = read(fd, (char *)buf+rd, bytes - rd);
        if (ret < 0 && errno != EINTR)
            return -1;
        if (ret > 0)
            rd += ret;
    }
    return bytes;
}

#define ERR(...) (fprintf(stderr, "Error: "  __VA_ARGS__), 0)

static int portable_getpass(FILE *f, char *buf, size_t len)
{
    struct termios oflags, nflags;
    int fd = fileno(f);
    char *newline;

    tcgetattr(fd, &oflags);
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |=  ECHONL;

    if (tcsetattr(fd, TCSANOW, &nflags) < 0 && errno != EINVAL)
        return -1 + ERR("tcsetattr, %s\n", strerror(errno));
    fgets(buf, len, f);
    if ((newline = strchr(buf, '\n')))
        *newline = 0;
    if (tcsetattr(fd, TCSANOW, &oflags) < 0 && errno != EINVAL)
        return -1 + ERR("tcsetattr, %s\n", strerror(errno));
    return 1;
}

#define RANDFILE "/dev/urandom"
#define FMODE(x,y,z) ((x) << 6 | (y) << 3 | (z))
int main(int gom, char *ba[])
{
    test_vectors();
    test_vec_random();
    test_gf_mul();
    int fd_in, fd_out;
    void *in_addr, *out_addr;
    unsigned char *out, *src;
    int encrypt = 1;
    if (gom > 1 && !strcmp(ba[1], "-d"))
        gom--, ba++, encrypt = 0;
    if (gom < 3)
        return 0;
    if ((fd_in = open(ba[1], O_RDONLY)) < 0)
        return !ERR("'%s', %s\n", ba[1], strerror(errno));
    if ((fd_out = open(ba[2], O_CREAT | O_EXCL | O_RDWR, FMODE(6,0,0))) < 0)
        return !ERR("'%s', %s\n", ba[2], strerror(errno));

    lseek(fd_in, 0, SEEK_END);
    off_t file_len = lseek(fd_in, 0, SEEK_CUR);
    off_t out_len = file_len;
    if (encrypt)
        out_len += GCM_NONCE_LEN + GCM_AUTH_TAG_LEN;
    else {
        out_len -= GCM_NONCE_LEN + GCM_AUTH_TAG_LEN;
        if (file_len <= GCM_NONCE_LEN + GCM_AUTH_TAG_LEN)
            return !ERR("Invalid input file\n");
    }
    /* Write to last byte of output file */
    lseek(fd_out, out_len -1, SEEK_SET);
    if (write(fd_out, "\0", 1) < 0)
        return !ERR("write: %s\n", strerror(errno));

    src = in_addr = mmap(0, file_len, PROT_READ, MAP_SHARED, fd_in, 0);
    out = out_addr = mmap(0, out_len,
                          PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
    if (in_addr == (void *)-1 || out_addr == (void *)-1)
        return !ERR("mmap failed\n");

    unsigned char crypt_key[64];
    unsigned crypt_key_len;
    printf("Password> ");
    portable_getpass(stdin, (void *)crypt_key, sizeof(crypt_key));
    crypt_key_len = strlen((void *)crypt_key);

    struct blowfish_key bf_key;
    blowfish_keyderiv(crypt_key, crypt_key_len, &bf_key);

    u64 nonce;

    if (encrypt) {
        int fd_rand;
        unsigned char nonce_buf[GCM_NONCE_LEN] = {0};
        if ((fd_rand = open(RANDFILE, O_RDONLY)) < 0)
            return !ERR("'%s', %s\n",RANDFILE, strerror(errno));
        if (xread(fd_rand, nonce_buf, sizeof(nonce_buf)) < 0)
            return !ERR("'%s', %s\n", "while reading " RANDFILE, strerror(errno));
        close(fd_rand);
        memcpy(&nonce, nonce_buf, sizeof(nonce));
        printf("Got nonce %016"PRIx64"\n", nonce);
        write_be64(out, nonce);
        out += sizeof(nonce);
        printf("Encrypting...\n");
    } else {
        nonce = read_be64(src);
        src += sizeof(nonce);
        printf("Read nonce %016"PRIx64"\n", nonce);
        printf("Decrypting...\n");
    }

    u64 auth_tag;
    if (encrypt) {
        bf_gcm_enc(out, in_addr, file_len, nonce, &auth_tag, &bf_key);
    } else {
        enum bf_gcm_err ret;
        ret = bf_gcm_dec(out, src, out_len, nonce, &auth_tag, &bf_key);
        if (ret != bf_gcm_auth_ok)
            printf("Authenticated Decryption Failed\n");
        else {
            printf("Authenticated Decryption Successful");
            printf(": '%s' -> '%s'\n", ba[1], ba[2]);
        }
    }
    munmap(in_addr, file_len);
    munmap(out_addr, out_len);
    close(fd_in);
    close(fd_out);
}
