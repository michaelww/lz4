#ifndef ROLLSUM_H_
#define ROLLSUM_H_

#include <stddef.h>

#define ROLLBITS 11 /* Chunk size will be approx 1 << ROLLBITS */

typedef unsigned long roll_t;

void roll_next_chunk(roll_t *rsum, size_t *length,
                     const unsigned char *src, size_t slen);

#endif /* ROLLSUM_H_ */

