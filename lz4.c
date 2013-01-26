/* Simple lz4 implementation GPL-3+, (c) ulrik 2012 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_LOG 12
#define HASHTABLESIZE (1 << HASH_LOG)
#define HASH_FUNCTION(x) (((x) * UINT32_C(0x9e3779b1)) >> (32-HASH_LOG))

#ifdef __GNUC__
#define likely(X) (__builtin_expect(!!(X),1))
#define unlikely(X) (__builtin_expect(!!(X),0))
#else
#define likely(X) (X)
#define unlikely(X) (X)
#endif

typedef unsigned char uchar;
#define WORDSZ   ((int)sizeof(unsigned long))

#define COPY(DST,SRC) memcpy((DST),(SRC),WORDSZ)
#define DO_WRITE_LENGTH(N,OUT)  /* increases OUT */\
    do { \
        unsigned _ii = (N)/255; \
        while (_ii--) *(OUT)++ = 0xff; \
        *(OUT)++ = (N) % 255; \
    } while (0)
#define FASTCOPY(DST,SRC,N)     /* does not increase DST */\
    do { \
        for (unsigned _ic = 0; _ic < (N); _ic += WORDSZ) \
            COPY((DST) + _ic, (SRC) + _ic); \
    } while (0)

static inline uint32_t VAL32(const uchar *y) {
    uint32_t x; memcpy(&x, y, sizeof(x));
    return x;
}
static inline unsigned long AWORD(const uchar *y) {
    unsigned long x; memcpy(&x, y, sizeof(x));
    return x;
}

static inline unsigned long read_le32(const uchar *src) {
    unsigned long x;
    x  = (unsigned long)src[0];         x |= (unsigned long)src[1] <<  8;
    x |= (unsigned long)src[2] << 16;   x |= (unsigned long)src[3] << 24;
    return x;
}
static inline void write_le32(uchar *dest, unsigned long x) {
    dest[0] = (x      ) & 0xff; dest[1] = (x >>  8) & 0xff;
    dest[2] = (x >> 16) & 0xff; dest[3] = (x >> 24) & 0xff;
}
/* write_lit_last: encode the last literal hunk, without the match part */
static inline unsigned write_lit_last(uchar *dest, const uchar *src, unsigned lit_len)
{
    uchar *out = dest;
    *out++ = (lit_len < 15 ? lit_len : 15) << 4;
    if (lit_len >= 15)
        DO_WRITE_LENGTH(lit_len - 15, out);
    memcpy(out, src, lit_len);
    out += lit_len;
    return (out - dest);
}
/* write_lit_match: Encode a full literal/match hunk */
static inline unsigned write_lit_match(uchar *const dest, const uchar *src,
                                       unsigned lit_len, unsigned match_off,
                                       unsigned match_len)
{
    uchar *out = dest;
    if likely(lit_len < 15) {
        *out++ = lit_len << 4; /* Fastpath, lit length < 15 */
    } else {
        *out++ = 15 << 4;
        DO_WRITE_LENGTH(lit_len - 15, out);
    }
    FASTCOPY(out, src, lit_len);
    out += lit_len;

    /* Match offset (LE 16-bit) */
    *out++ = match_off & 0xff;
    *out++ = (match_off >> 8) & 0xff;
    /* Match length */
    if unlikely(!(match_len < 15)) {
        *dest |= 0xf;
        DO_WRITE_LENGTH(match_len - 15, out);
    }
    *dest |= (match_len & 0xf);
    return out - dest;
}

static inline int ctlz_bytes(unsigned long x) {
#ifdef __GNUC__
    if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) return __builtin_ctzl(x)/8;
    else return __builtin_clzl(x)/8;
#endif
    unsigned r = 0; const int _one = 1;
    for (; r < sizeof(x); r++)
        if (0 == *(uchar *)&_one) { /* big endian */
            if (x & (0xff << (sizeof(x)-r-1)*8)) break;
        } else if (x & (0xff << r*8)) break;
    return r;
}

static inline unsigned runlength(const uchar *a, const uchar *b, unsigned max)
{
    unsigned cnt = 0;
    while (cnt + WORDSZ <= max) {
        unsigned long xval = AWORD(a+cnt) ^ AWORD(b+cnt);
        if (xval) return ctlz_bytes(xval) + cnt;
        cnt += WORDSZ;
    }
    return cnt;
}

/* lz4_compress: return output size. no error conditions. */
static int lz4_compress(uchar *dst, const uchar *const src, unsigned isize)
{
    unsigned mark = 0;
    const uchar *const odst = dst;
    unsigned last_word = (isize < 25 ? 0 : isize - 12 - WORDSZ - 3);
    unsigned HashTable[HASHTABLESIZE] = {0};
    unsigned i = 0;
    unsigned skip = 4;
_next_match:
    for (; i < last_word;) {
        unsigned ij = i;
        unsigned hs[4] = {
            HASH_FUNCTION(VAL32(&src[i+0])),
            HASH_FUNCTION(VAL32(&src[i+1])),
            HASH_FUNCTION(VAL32(&src[i+2])),
            HASH_FUNCTION(VAL32(&src[i+3])),
        };
        for (unsigned j = 0; j < 4; j++) {
            unsigned ref = HashTable[hs[j]];
            unsigned off = ++ij - ref;
            HashTable[hs[j]] = ij;
            if (ref && off < 0x10000 && VAL32(&src[ref]) == VAL32(&src[ij])) {
                unsigned runl = 0;
                unsigned maxrun = last_word + 7 - ij;
                /* Extend forward */
                runl = runlength(&src[ij-off+4], &src[ij+4], maxrun);
                /* Extend backward */
                while (ij - off && ij - mark && src[ij-off-1] == src[ij-1])
                    ij--, runl++;
                /* Code the literal until this point and the match reference */
                dst += write_lit_match(dst, &src[mark], ij - mark, off, runl);
                mark = i = ij + 4 + runl;
                goto _next_match;
            }
        }
        i += skip + ((i-mark) >> 6); /* Fast forward when incompressible */
    }
    dst += write_lit_last(dst, &src[mark], isize - mark);
    return dst - odst;
}

enum lz4_err { lz4_err_incomplete = 0, lz4_err_overflow, lz4_err_malformed };
static const char *lz4_errmsg[] = {
     "incomplete chunk", "output overflow", "malformed stream" };

/* lz4_decompress: return output size or a negative lz4_err value */
static int lz4_decompress(uchar *dst, const uchar *src, unsigned isize, unsigned max_osize)
{
    const uchar *const odst = dst;
    const uchar *const src_end = src + isize;
    max_osize -= 2*WORDSZ; /* Allow unrolling by word size */
    while (src+1 < src_end) {
        unsigned lit_len, match_off, match_len;
        /* Read token */
        match_len = *src++;
        lit_len = match_len >> 4;
        /* Read lit len */
        if unlikely(lit_len == 15) {
            do { lit_len += *src;
            } while (*src++ == 0xff && src < src_end);
            if (src >= src_end) break;
        }
        if unlikely(dst + lit_len > odst + max_osize)
            return -lz4_err_overflow;
        /* Copy literal */
        if unlikely(src + lit_len >= src_end) {
            if unlikely(src + lit_len > src_end)
                break;
            /* End of chunk */
            memcpy(dst, src, lit_len);
            dst += lit_len;
            return dst - odst;
        }
        FASTCOPY(dst, src, lit_len);
        dst += lit_len;
        src += lit_len;
        if unlikely(src >= src_end-2) break;
_decode_match:
        /* Read match off as LE 16-bit */
        match_off  =  *src++ & 0xff;
        match_off |= (*src++ & 0xff) << 8;
        if unlikely(match_off > (unsigned)(dst - odst))
            return -lz4_err_malformed;
        /* Read match len */
        match_len &= 15;
        if unlikely(match_len == 15) {
            do { match_len += *src;
            } while (*src++ == 0xff && src < src_end);
            if (src >= src_end) break;
        }
        match_len += 4;

        if unlikely(dst + match_len > odst + max_osize)
            return -lz4_err_overflow;
        /* Copy match */
        if likely(match_off >= WORDSZ) {
            unsigned j = 0;
            do {
                COPY(dst + j, dst + j - match_off);
                COPY(dst + j + WORDSZ, dst + j + WORDSZ - match_off);
                j += 2* WORDSZ;
            } while unlikely(j < match_len);
        } else
            for (unsigned j = 0; j < match_len; j++)
                dst[j] = *(dst - match_off + j);
        dst += match_len;
        if (!((match_len = *src) & 0xf0) && likely(src < src_end - 4)) {
            src++;
            goto _decode_match;
        }
    }
    return -lz4_err_incomplete;
}

#define ARCHIVE_MAGICNUMBER 0x184C2102
#define CHUNKSIZ (8 << 20)
#define READSIZ (512 << 10)
#define ERR(...) (fprintf(stderr, "lz4: Error: "  __VA_ARGS__), 0)
int main(int zztop, char *sup[])
{
    FILE *fin;
    uchar *txt_buf, *lz_buf;
    int alloc_siz = CHUNKSIZ + CHUNKSIZ/128;
    int decompress = 0;
    if (zztop > 1 && !strcmp(sup[1], "-d"))
        decompress = 1, zztop--, sup++;
    else if (zztop > 1 && !strcmp(sup[1], "-h"))
        return (fprintf(stderr, "Usage: lz4 [-d] [FILE]\n"), 0);
    if (zztop < 2 || !strcmp(sup[1], "-"))
        fin = stdin;
    else if (!(fin = fopen(sup[1], "r")))
        return !ERR("'%s', %s\n", sup[1], strerror(errno));
    txt_buf = malloc(CHUNKSIZ + 16);
    lz_buf = malloc(alloc_siz);
    if (!txt_buf || !lz_buf)
        return !ERR("%s\n", strerror(errno));
    if (!decompress) {
        unsigned insz = 0, osz= 4;
        /* Compression */
        write_le32(lz_buf, ARCHIVE_MAGICNUMBER);
        fwrite(lz_buf, 4, 1, stdout);
        while (1) {
            size_t read_len = fread(txt_buf, 1, READSIZ, fin);
            if (!read_len)
                break;
            int olen = lz4_compress(lz_buf+4, txt_buf, read_len);
            write_le32(lz_buf, olen);
            fwrite(lz_buf, 1, olen+4, stdout);
            insz += read_len; osz += olen+4;
        }
        fprintf(stderr, "Compressed to %g%%\n", (osz*100.0)/insz);
    } else {
        /* Decompression */
        int read = fread(lz_buf, 4, 1, fin);
        if (!read || read_le32(lz_buf) != ARCHIVE_MAGICNUMBER)
            return !ERR("not an lz4 archive\n");
        while (1) { /* handle each chunk */
            int in_len;
            read = fread(lz_buf, 4, 1, fin);
            if (!read) break; /* Archive end */
            in_len = read_le32(lz_buf);
            if (in_len > alloc_siz)
                return !ERR("chunk size too large\n");
            read = fread(lz_buf, 1, in_len, fin);
            if (read != in_len)
                return !ERR("%s\n", lz4_errmsg[-lz4_err_incomplete]);
            read = lz4_decompress(txt_buf, lz_buf, in_len, CHUNKSIZ+16);
            if (read <= 0)
                return !ERR("%s\n", lz4_errmsg[-read]);
            fwrite(txt_buf, 1, read, stdout);
        }
    }
    fclose(fin);
    free(txt_buf);
    free(lz_buf);
}
