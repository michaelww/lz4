#ifndef BLOWFISH_H_
#define BLOWFISH_H_

#include <stdint.h>

#define BLOWFISH_BLOCK_BITS 64
#define BLOWFISH_ROUNDS 16

struct blowfish_key {
    uint32_t P[BLOWFISH_ROUNDS+2];
    uint32_t S[4*256];
};

void blowfish_encrypt(uint32_t x[2], const struct blowfish_key *);
void blowfish_decrypt(uint32_t x[2], const struct blowfish_key *);
void blowfish_keyderiv(const unsigned char *key, unsigned key_len,
                       struct blowfish_key *);

#endif /* BLOWFISH_H_ */

