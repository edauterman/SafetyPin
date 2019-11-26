#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "crypto.h"
#include "ctap.h"

#define NUM_LEAVES 256
#define LEVELS 8 // log2(NUM_LEAVES)

static uint8_t msk[16];

void PuncEnc_Setup() {
    uint8_t leaves[NUM_LEAVES][16];
    uint8_t keys[LEVELS][NUM_LEAVES][16];
    uint8_t cts[LEVELS][NUM_LEAVES][32];
    uint8_t 
    fillLeaves(leaves);
    /* Leaves first. */
    for (int i = 0; i < NUM_LEAVES; i++) {
        /* Choose random key. */
        ctap_generate_rng(keys[0][i], 16);
        /* Encrypt leaf. */
        crypto_aes256_init(keys[0][i], leaves[i]);
        memset(cts[0][i], 0, 32);
        crypto_aes256_encrypt(cts[0][i], 16);
    }
    for (int i = 1; i < LEVELS; i++) {
        for (int j =  0; j < NUM_LEAVES/(LEVELS + 1); j++) {
            /* Choose random key. */
            ctap_generate_rng(keys[i][j], 16);
            /* Encrypt two children keys. */
            crypto_aes256_init(keys[i][j], keys[i-1][2*j]);
            crypto_aes256_encrypt(cts[i][j], 16);
            crypto_aes256_reset_iv(keys[i-1][2*j+1]);
            crypto_aes256_encrypt(cts[i][j] + 16, 16);
        }
    }
    /* Need to return cts and save keys[LEVELS-1][0]*/
}

void fillLeaves(uint8_t leaves[NUM_LEAVES][16]) {
    for (int i = 0; i < NUM_LEAVES; i++) {
        leaves[i][0] = i & 0xff;
        leaves[i][1] = (i >> 8) & 0xff;
        leaves[i][2] = (i >> 16) & 0xff;
        leaves[i][3] = (i >> 24) & 0xff;
        memset(leaves + 4, 0, 12);
    }
}
