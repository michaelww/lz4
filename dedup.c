
#define _XOPEN_SOURCE 700

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/stat.h> /* mkdir */

#include "rollsum.h"
#include "blake2s.h"

#define HASH_LEN 16 /* Use short hash = 128 bits */
#define HASH_SALT ("..1.1.1.")

#define DEDUPSTORE "DEDUPSTORE"
#define DEDUPMODE 0770

#define NO_WRITE

#define ROLLW  (8*sizeof(roll_t))

typedef uint32_t u32;
typedef unsigned short ushort;
typedef unsigned char uchar;

struct roll_chunk {
    roll_t checksum;
    size_t offset;
    size_t length;
};

static char *mkhexdigest(char *buf, const uchar *digest, size_t len)
{
    char *digits = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        buf[2*i]   = digits[digest[i]  >> 4];
        buf[2*i+1] = digits[digest[i] & 0xf];
    }
    buf[2*len] = 0;
    return buf;
}

/* Returns < 0 on error */
/* Returns 0 if file exists, 1 if file written */
static int store_chunk(char *name, const uchar *src, size_t len)
{
    /* cut of a 2-letter prefix */
    char prefix[] = { DEDUPSTORE "/" "XX" };
    char filepath[128];
    FILE *fout;
    prefix[sizeof(prefix)-3] = *name++;
    prefix[sizeof(prefix)-2] = *name++;
    if (mkdir(prefix, DEDUPMODE) < 0 && errno != EEXIST) {
        fprintf(stderr, "%s: %s\n", prefix, strerror(errno));
        return -1;
    }
    snprintf(filepath, sizeof(filepath), "%s/%s", prefix, name);
    fout = fopen(filepath, "wbx");
    if (!fout) {
        if (errno == EEXIST)
            return 0;
        fprintf(stderr, "%s: %s\n", filepath, strerror(errno));
        return -1;
    }
#ifndef NO_WRITE
    fwrite(src, 1, len, fout);
#endif
    fclose(fout);
    return 1;
}

/* Return -1 on failure */
static int output_chunk(char *name)
{
    /* cut of a 2-letter prefix */
    char prefix[] = { DEDUPSTORE "/" "XX" };
    char filepath[128];
    uchar buf[4096];
    FILE *fout;
    prefix[sizeof(prefix)-3] = *name++;
    prefix[sizeof(prefix)-2] = *name++;
    snprintf(filepath, sizeof(filepath), "%s/%s", prefix, name);
    fout = fopen(filepath, "rb");
    if (!fout) {
        fprintf(stderr, "%s: %s\n", filepath, strerror(errno));
        return -1;
    }
    while (1) { 
        size_t read = fread(buf, 1, sizeof(buf), fout);
        if (!read)
            break;
        fwrite(buf, 1, read, stdout);
    }
    fclose(fout);
    return 1;
}

#define CHUNKID   (32-ROLLBITS)
#define CHUNKIDX(R) ((R) >> ((ROLLW-32) + ROLLBITS))


static int roll_stream(uchar *out, const uchar *src, size_t len, size_t limit)
{
    (void) out; (void) limit;
    uchar digest[HASH_LEN];
    char hexdigest[HASH_LEN*2+1];

    size_t nchunks = 0;
    size_t totchunklen = 0;
    size_t effectivesize = 0;
    size_t duplicates = 0;
    int store_ret = 0;
    size_t bytes_written = 0;
    struct blake2s_ctx hash_ctx;

    for (size_t j = 0; j < len;) {
        struct roll_chunk chunk;
        roll_next_chunk(&chunk.checksum, &chunk.length, &src[j], len - j);
        size_t chunklen = chunk.length;

        /* Hash chunk and store */
        blake2s_init_salted(&hash_ctx, HASH_SALT, HASH_LEN);
        blake2s_update(&hash_ctx, &src[j], chunklen);
        blake2s_final(&hash_ctx, digest);
        mkhexdigest(hexdigest, digest, HASH_LEN);

        store_ret = store_chunk(hexdigest, &src[j], chunklen);
        if (store_ret == 1)
            bytes_written += chunklen;
        if (store_ret < 0)
            return store_ret;
        /* Write manifest */
        printf("%s\n", hexdigest);

        j += chunklen;

        int eq = (store_ret == 0);
        if (eq) {
            duplicates++;
        } else {
            nchunks++;
            effectivesize += chunklen;
        }

        totchunklen += chunklen;
    }
    fprintf(stderr, "chunks=%zu, dup=%zu, mean length=%g\n",
            nchunks, duplicates, effectivesize/(float)nchunks);
    fprintf(stderr, "Wrote %zuKB (%.2f%%, %zu)\n", bytes_written/1024,
                    100.0*bytes_written/(float)totchunklen, bytes_written);
    return 0;
}


#define CHUNKSIZ (32 << 20)
#define READSIZ CHUNKSIZ
#define ERR(...) (fprintf(stderr, "Error: "  __VA_ARGS__), 0)
#define USAGE ""
enum dedup_mode_t { DSTORE, DGET };

int main(int zztop, char *sup[])
{
    FILE *fin;
    unsigned char *lz_buf;
    enum dedup_mode_t mode = DSTORE;

    if (zztop > 1 && !strcmp(sup[1], "-h"))
        return (fprintf(stderr, "Usage: " USAGE "\n"), 0);
    if (zztop > 1 && !strcmp(sup[1], "--get")) {
        mode = DGET; zztop--; sup++;
    }
    if (zztop < 2 || !strcmp(sup[1], "-"))
        fin = stdin;
    else if (!(fin = fopen(sup[1], "r")))
        return !ERR("'%s', %s\n", sup[1], strerror(errno));

    if (mkdir(DEDUPSTORE, DEDUPMODE) < 0 && errno != EEXIST) {
        return !ERR("%s: %s\n", DEDUPSTORE, strerror(errno));
    }


    lz_buf = malloc(CHUNKSIZ);
    if (!lz_buf)
        return !ERR("%s\n", strerror(errno));
    while (mode == DSTORE) { 
        size_t read = fread(lz_buf, 1, READSIZ, fin);
        if (!read)
            break;
        read = roll_stream(lz_buf, lz_buf, read, CHUNKSIZ);
        fwrite(lz_buf, 1, read, stdout);
    }
    while (mode == DGET) { 
        char *newline;
        if (fgets((char *)lz_buf, READSIZ, fin) == NULL)
            break;
        newline = strchr((char *)lz_buf, '\n');
        if (newline) *newline = 0;
        if (output_chunk((char *)lz_buf) != 1)
            break;
    }
    fclose(fin);
    free(lz_buf);
}
