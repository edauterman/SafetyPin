#ifndef _IBE_H
#define _IBE_H

#include "bls12_381/bls12_381.h"

#define BASEFIELD_SZ_G1 48
#define BASEFIELD_SZ_G2 96
#define SHA256_DIGEST_LEN 32
#define IBE_MSG_LEN 32
#define IBE_CT_LEN (2 * IBE_MSG_LEN + BASEFIELD_SZ_G2)

typedef struct {
    embedded_pairing_bls12_381_g2_t U;
    uint8_t V[IBE_MSG_LEN];
    uint8_t W[IBE_MSG_LEN];
} IBE_ciphertext;

void IBE_Setup();
void IBE_Extract(uint16_t index, embedded_pairing_bls12_381_g1_t *sk);
void IBE_Decrypt(embedded_pairing_bls12_381_g1_t *sk, IBE_ciphertext *c, uint8_t msg[IBE_MSG_LEN]);

void IBE_MarshalCt(IBE_ciphertext *c, uint8_t buf[IBE_CT_LEN]);
void IBE_UnmarshalCt(uint8_t buf[IBE_CT_LEN], IBE_ciphertext *c);
void IBE_MarshalMpk(uint8_t buf[BASEFIELD_SZ_G2]);

#endif
