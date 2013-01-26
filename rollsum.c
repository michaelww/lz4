#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rollsum.h"

typedef unsigned char uchar;

#define ROLLW  (8*sizeof(roll_t))

/* Hashing by cyclic polynomial or 'Buzhash'
 * http://en.wikipedia.org/wiki/Rolling_hash
 *
 * Random bytes for the mapping h: [0,256) -> [0,2**32)
 * Going through g: [0,256) -> [0,16) to save cache/memory space
 * and it works just as well
 *
 * h = f o g
 * f = roll_map
 * g x = x ^ (x >> 4)
 */
static const roll_t roll_map[16] = 
{
    0x3580e62c, 0x86ccf74b, 0x5977b0c4, 0x4c08a111,
    0x140f76f7, 0x694cf240, 0x6c783195, 0x222e7b17,
    0xdd58b264, 0xa46ebf36, 0x6d320fe5, 0xe7d8087c,
    0xfff91cb7, 0x3029c4ed, 0x2d3dcb98, 0x71b7b892,
};
#define map(x) roll_map[15 & ((x) ^ ((x) >> 4))]

#define ROTL(x,l) (((x) << (l)) | ((x) >> (ROLLW-(l))))

static inline roll_t roll(roll_t cur, uchar next, uchar last, size_t last_off)
{
    /* NOTE: `rolm` must not be zero, so last_off should not be multip of 32 */
    size_t rolm = last_off & (ROLLW-1);
    return map(next) ^ ROTL(cur, 1) ^ ROTL(map(last), rolm);
}

static inline roll_t roll_init(roll_t cur, uchar next)
{
    return map(next) ^ ROTL(cur, 1);
}

#define ROLLPERIOD ((1 << (ROLLBITS-1)) + 1)
#define MINCHUNKLEN 512
#define IS_CHUNK_SUM(r) (!((r) & ((1 << ROLLBITS) -1)))
#define ROLL_START_VAL 0

void roll_next_chunk(roll_t *rsum, size_t *length, const uchar *src, size_t slen)
{
    roll_t r = ROLL_START_VAL;
    roll_t rhist = 0;
    uchar  window[ROLLPERIOD];

    /* try to detect cycles and break on them */
    size_t resetperiod = ROLLPERIOD + 3;
    size_t reset_inc = 1;
    size_t j;

    for (j = 0; j < slen; j++) {
        size_t chunklen = j+1;
        if (j < ROLLPERIOD) {
            r = roll_init(r, src[j]);
        } else {
            r = roll(r, src[j], window[j % ROLLPERIOD], ROLLPERIOD);

            /* check for cycles */
            rhist ^= r;
            if (chunklen == resetperiod) {
                rhist = 0;
                resetperiod += reset_inc++;
            } else if (!rhist) {
                break;
            }
        }
        /* `window` should be completely filled before we access it */
        window[j % ROLLPERIOD] = src[j];

        if (chunklen >= MINCHUNKLEN && IS_CHUNK_SUM(r))
            break;
    }
    j += (j < slen);
    *rsum = r;
    *length = j;
}
