#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rollsum.h"

#define ROLLW  (8*sizeof(roll_t))
typedef uint32_t u32;
typedef unsigned short ushort;
typedef unsigned char uchar;

struct roll_chunk {
    roll_t checksum;
    size_t offset;
    size_t length;
};

#define CHUNKID   (32-ROLLBITS)
#define CHUNKIDX(R) ((R) >> ((ROLLW-32) + ROLLBITS))


static int roll_stream(uchar *out, const uchar *src, size_t len, size_t limit)
{
    roll_t r = 0;
    size_t last_chunk = 0;
    unsigned *tab = malloc((1 << CHUNKID) * sizeof(*tab));
    (void) out; (void) limit;

    size_t nchunks = 0;
    size_t totchunklen = 0;
    size_t effectivesize = 0;
    size_t duplicates = 0;
    size_t memcmps = 0;

    memset(tab, 0, (1 << CHUNKID) * sizeof(*tab));

    for (size_t j = 0; j < len;) {
        struct roll_chunk chunk;
        roll_next_chunk(&chunk.checksum, &chunk.length, &src[j], len - j);
        r = chunk.checksum;
        size_t chunklen = chunk.length;
        j += chunklen;

        int eq = 0;
#if 0
        printf("j=%zu, char=%02x (%c) rollsum=%x chunklen=%u\n",
               j, src[j], (src[j] != '\n'?src[j] : 0), r,
               chunklen);
#endif
        if (tab[CHUNKIDX(r)]) {
            size_t old_chunk = tab[CHUNKIDX(r)];
            if (old_chunk >= chunklen) {
                /* `j` is the last byte and first byte is j-chunklen+1 */
                eq = !memcmp(&src[j-chunklen],
                             &src[old_chunk-chunklen], chunklen);
                memcmps++;
            }
        }
        if (eq) {
            duplicates++;
        } else {
            nchunks++;
            effectivesize += chunklen;
        }
        totchunklen += chunklen;

        last_chunk = j; /* mark the position after this */
        tab[CHUNKIDX(r)] = last_chunk;
    }
    printf("last chunk r=%08lx, len=%zu\n", r, len-last_chunk);
    printf("chunks=%zu, dup=%zu, memcmps=%zu, compress=%g, mean length=%g\n",
            nchunks, duplicates, memcmps,
            effectivesize/(float)totchunklen, effectivesize/(float)nchunks);
    free(tab);
    return 0;
}


#define CHUNKSIZ (80 << 20)
#define READSIZ CHUNKSIZ
//#define READSIZ (512 << 10)
//#define CHUNKSIZ READSIZ
#define ERR(...) (fprintf(stderr, "Error: "  __VA_ARGS__), 0)
#define USAGE ""
int main(int zztop, char *sup[])
{
    FILE *fin;
    unsigned char *lz_buf;
    if (zztop > 1 && !strcmp(sup[1], "-h"))
        return (fprintf(stderr, "Usage: " USAGE "\n"), 0);
    if (zztop < 2 || !strcmp(sup[1], "-"))
        fin = stdin;
    else if (!(fin = fopen(sup[1], "r")))
        return !ERR("'%s', %s\n", sup[1], strerror(errno));
    lz_buf = malloc(CHUNKSIZ);
    if (!lz_buf)
        return !ERR("%s\n", strerror(errno));
    while (1) { 
        size_t read = fread(lz_buf, 1, READSIZ, fin);
        if (!read)
            break;
        read = roll_stream(lz_buf, lz_buf, read, CHUNKSIZ+16);
        fwrite(lz_buf, 1, read, stdout);
    }
    fclose(fin);
    free(lz_buf);
}
