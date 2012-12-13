/* Simple LZ4 implementation GPL-3, c michael 2012 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_LOG 12
#define HASHTABLESIZE (1 << HASH_LOG)
#define HASH_FUNCTION(x)	(((x) * 2654435761U) >> (32u-HASH_LOG))

#ifdef __GNUC__
#define likely(X) (__builtin_expect(!!(X),1))
#define unlikely(X) (__builtin_expect(!!(X),0))
#else
#define likely(X) (X)
#define unlikely(X) (X)
#endif

typedef uint32_t u32;
typedef uint64_t uArch;
#define VAL32(x) (*(uint32_t *)(x))
#define VAL16(x) (*(uint16_t *)(x))
#define WORDSZ   ((int)sizeof(uArch))
#define AWORD(x) (*(uArch *)(x))

#define DO_WRITE_LENGTH(N,OUT)  /* increases OUT */\
    do { \
        unsigned _ii = (N)/255; \
        while (_ii--) *(OUT)++ = 0xff; \
        *(OUT)++ = (N) % 255; \
    } while (0)
#define FASTCOPY(DST,SRC,N)     /* does not increase DST */\
    do { \
        for (unsigned _ic = 0; _ic < (N); _ic += WORDSZ) \
            AWORD((DST) + _ic) = AWORD((SRC) + _ic); \
    } while (0)

static inline uint16_t as_le16(uint16_t x) {
    const int _one = 1;
    if (*(unsigned char *)&_one == 1) return x;  /* identity func if LE */
    return ((x & 0xff00) >> 8) | ((x & 0x00ff) << 8);
}
static inline uint32_t as_le32(uint32_t x) {
    const int _one = 1;
    if (*(unsigned char *)&_one == 1) return x;
    return (x >> 24) | (x << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8);
}

/* Write the last Literal hunk that does not have the offset and match fields */
static inline u32 write_lit_last(unsigned char *const dest, const unsigned char *src,
                                 u32 lit_len)
{
    unsigned char *out = dest;
    *out++ = (lit_len < 15 ? lit_len : 15) << 4;
    if (lit_len >= 15)
        DO_WRITE_LENGTH(lit_len - 15, out);
    memcpy(out, src, lit_len);
    out += lit_len;
    return (out - dest);
}

/* Write Literal/Match hunk */
static inline u32 write_lit_match(unsigned char *const dest, const unsigned char *src,
                                  u32 lit_len, u32 match_off, u32 match_len)
{
    unsigned char *out = dest;
    if likely(lit_len < 15) {
        /* Fastpath, lit length < 15 */
        *out++ = lit_len << 4;
        FASTCOPY(out, src, 16);
    } else {
        *out++ = 15 << 4;
        DO_WRITE_LENGTH(lit_len - 15, out);
        FASTCOPY(out, src, lit_len);
    }
    out += lit_len;

    /* Match offset (LE 16-bit) */
    VAL16(out) = as_le16(match_off);
    out += 2;

    /* Match length */
    if unlikely(!(match_len < 15)) {
        *dest |= 0xf;
        DO_WRITE_LENGTH(match_len - 15, out);
    }
    *dest |= (match_len & 0xf);
    return out - dest;
}

static inline u32 runlength(const unsigned char *a, const unsigned char *b, int max)
{
    int cnt = 0;
    while (cnt + WORDSZ <= max) {
        uArch xval = AWORD(a+cnt) ^ AWORD(b+cnt);
        if (xval)
#ifdef __GNUC__
            return __builtin_ctzll(xval)/8 + cnt;
#else
            break;
#endif
        cnt += WORDSZ;
    }
    if (WORDSZ > 4)
        cnt += 4*(VAL32(a+cnt) == VAL32(b+cnt));
    cnt += (a[cnt] == b[cnt]);
    cnt += (a[cnt] == b[cnt]);
    cnt += (a[cnt] == b[cnt]);
    return cnt;
}

static int LZ4_compress(const unsigned char *const src,
                        unsigned char *dst, int isize)
{
    unsigned mark = 0;
    const unsigned char *const odst = dst;
    u32 last_word = (isize < 25 ? 0 : isize - 12 - WORDSZ - 3);
    u32 HashTable[HASHTABLESIZE] = {0};
    unsigned i = 0;
    unsigned skip = 4;
_next_match:
    for (; i < last_word;) {
        u32 hs[4] = {
            HASH_FUNCTION(VAL32(&src[i+0])),
            HASH_FUNCTION(VAL32(&src[i+1])),
            HASH_FUNCTION(VAL32(&src[i+2])),
            HASH_FUNCTION(VAL32(&src[i+3])),
        };
        for (unsigned j = 0; j < 4; j++) {
            u32 ref = HashTable[hs[j]];
            u32 ij = i + j;
            u32 off = ij - ref;
            HashTable[hs[j]] = ij;
            if (ref && off < 0x10000 && VAL32(&src[ref]) == VAL32(&src[ij])) {
                u32 runl = 0;
                u32 maxrun = last_word + 7 - ij;
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

#define ERR(...) (fprintf(stderr, "lz4: Error: "  __VA_ARGS__), 0)

static int LZ4_decompress(const unsigned char *src, unsigned char *dst,
                          u32 isize, u32 max_osize)
{
    const unsigned char *const src_end = src + isize;
    const unsigned char *const odst = dst;
    max_osize -= 2*WORDSZ; /* Allow unrolling by word size */
    while (src < src_end - 5) {
        u32 lit_len;
        u32 match_off;
        u32 match_len = *src++;
        /* Read token */
        if ((lit_len = match_len >> 4)) {
            /* Read lit len */
            if unlikely(lit_len == 15) {
                do { lit_len += *src;
                } while (*src++ == 0xff && src < src_end);
                if (src >= src_end) return ERR("malformed stream\n");
            }
            if unlikely(dst + lit_len > odst + max_osize)
                return ERR("output overflow\n");
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
            if unlikely(src+2 >= src_end) break;
        }
        /* Read match off as LE 16-bit */
        match_len &= 15;
        match_off = as_le16(VAL16(src));
        src += 2;
        if unlikely(!match_off || match_off > (dst - odst))
            return ERR("illegal match offset %u\n", match_off);
        /* Read match len */
        if unlikely(match_len == 15) {
            do { match_len += *src;
            } while (*src++ == 0xff && src < src_end);
            if (src >= src_end) return ERR("malformed stream\n");
        }
        match_len += 4;

        if unlikely(dst + match_len > odst + max_osize)
            return ERR("output overflow\n");
        /* Copy match */
        if likely(match_off >= WORDSZ) {
            unsigned j = 0;
            do {
                AWORD(dst+j) = AWORD(dst+j - match_off);
                AWORD(dst+j+WORDSZ) = AWORD(dst+j+WORDSZ - match_off);
                j += 2 * WORDSZ;
            } while unlikely(j < match_len);
        } else
            for (unsigned j = 0; j < match_len; j++)
                dst[j] = *(dst - match_off + j);
        dst += match_len;
    }
    return ERR("incomplete lz4 chunk\n");
}

#define ARCHIVE_MAGICNUMBER 0x184C2102

/* Stub compression program */
int main(int zztop, char *sup[])
{
    FILE *fin;
    unsigned char *obuf;
    unsigned char *inbuf;
    u32 chunk_siz = 8 << 20;
    u32 alloc_siz = 9 << 20;
    int decompress = 0;
    if (zztop > 1 && !strcmp(sup[1], "-d"))
        decompress = 1, zztop--, sup++;
    else if (zztop > 1 && !strcmp(sup[1], "-h"))
        return (fprintf(stderr, "Usage: %s [-d] [FILE]\n", sup[0]),0);
    if (zztop < 2 || !strcmp(sup[1], "-"))
        fin = stdin;
    else {
        fin = fopen(sup[1], "r");
        if (!fin)
            return !ERR("'%s', %s\n", sup[1], strerror(errno));
    }
    obuf = malloc(alloc_siz);
    inbuf = malloc(alloc_siz);
    if (!obuf || !inbuf)
        return !ERR("%s\n", strerror(errno));
    if (!decompress) {
        /* Compression */
        VAL32(obuf) = as_le32(ARCHIVE_MAGICNUMBER);
        fwrite(obuf, sizeof(u32), 1, stdout);
        while (1) {
            size_t read_len = fread(inbuf, 1, chunk_siz, fin);
            if (!read_len)
                break;
            int olen = LZ4_compress(inbuf, obuf+4, read_len);
            VAL32(obuf) = as_le32((u32)olen);
            fwrite(obuf, 1, olen+4, stdout);
        }
    } else {
    /* Decompression */
        size_t read;
        read = fread(inbuf, sizeof(u32), 1, fin);
        if (!read || as_le32(VAL32(inbuf)) != ARCHIVE_MAGICNUMBER)
            return !ERR("not an lz4 archive\n");
        while (1) { /* handle each chunk */
            u32 in_len;
            read = fread(inbuf, sizeof(u32), 1, fin);
            if (!read) break; /* Archive end */
            in_len = as_le32(VAL32(inbuf));
            if (in_len > alloc_siz)
                return !ERR("chunk size too large\n");
            read = fread(inbuf, 1, in_len, fin);
            if (read != in_len)
                return !ERR("incomplete lz4 chunk\n");
            read = LZ4_decompress(inbuf, obuf, in_len, alloc_siz);
            if (!read)
                return 1;
            fwrite(obuf, 1, read, stdout);
        }
    }
    fclose(fin);
    free(obuf);
    free(inbuf);
}
