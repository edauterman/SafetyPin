#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "crypto.h"
#include "ctap.h"
#include "device.h"
#include "ibe.h"
#include "bls12_381/bls12_381.h"

embedded_pairing_core_bigint_256_t msk;
embedded_pairing_bls12_381_g1_t mpk;

void IBE_Setup() {
    /* Choose msk in Z_q^* */
    embedded_pairing_bls12_381_zp_random(&msk, ctap_generate_rng);
    /* Set mpk */
    // TODO: this should probably be the generator
    embedded_pairing_bls12_381_g1_multiply(&mpk, embedded_pairing_bls12_381_g1_zero, &msk);

}

void hashToBaseField(uint16_t index, uint8_t buf[BASEFIELD_SZ]) {
    uint8_t input[sizeof(uint16_t ) + sizeof(uint8_t)];
    uint8_t tmp[32];
    uint8_t ctr = 1;
    
    memcpy(input + sizeof(uint8_t), &index, sizeof(uint16_t));
    memcpy(input, &ctr, sizeof(uint8_t));
    
    crypto_sha256_init();
    crypto_sha256_update(input, 3);
    crypto_sha256_final(tmp);
    memcpy(buf, tmp, 32);

    ctr += 1;
    memcpy(input, &ctr, sizeof(uint8_t));

    crypto_sha256_init();
    crypto_sha256_update(input, 3);
    crypto_sha256_final(tmp);
    memcpy(buf + 32, tmp, BASEFIELD_SZ - 32);

}

void IBE_Extract(uint16_t index, embedded_pairing_bls12_381_g1_t *sk) {
    embedded_pairing_bls12_381_g1_t pt;
    uint8_t indexHash[BASEFIELD_SZ];
    embedded_pairing_bls12_381_g1affine_t pt_affine;
    /* Map index to a point pt. */
    hashToBaseField(index, indexHash);
    embedded_pairing_bls12_381_g1affine_from_hash(&pt_affine, indexHash);
    /* Set sk = pt^msk. */
    embedded_pairing_bls12_381_g1_multiply_affine(sk, &pt_affine, &msk);
}

// TODO: decrypt
