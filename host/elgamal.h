#ifndef _ELGAMAL_H
#define _ELGAMAL_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include "params.h"

typedef struct {
    EC_POINT *R;
    uint8_t *C;
} ElGamal_ciphertext;

ElGamal_ciphertext *ElGamalCiphertext_new(Params *params);
void ElGamalCiphertext_free(ElGamal_ciphertext *c);

/* 65 bytes */
void ElGamal_Marshal(Params *params, uint8_t *bytes, ElGamal_ciphertext *c);
void ElGamal_Unmarshal(Params *params, uint8_t *bytes, ElGamal_ciphertext *c);

int ElGamal_Encrypt(Params *params, BIGNUM *msg, EC_POINT *pk, BIGNUM *r, EC_POINT *R, ElGamal_ciphertext *c);
int ElGamal_Decrypt(Params *params, BIGNUM *msg, BIGNUM *sk, ElGamal_ciphertext *c);

#endif
