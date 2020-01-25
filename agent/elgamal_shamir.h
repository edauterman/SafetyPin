#ifndef _ELGAMAL_SHAMIR_H
#define _ELGAMAL_SHAMIR_H

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "elgamal.h"
#include "params.h"

typedef struct {
    BIGNUM *x;
    ElGamal_ciphertext *ct;
} ElGamalCtShare;

typedef struct {
    BIGNUM *x;
    EC_POINT *msg;
} ElGamalMsgShare;

ElGamalCtShare *ElGamalCtShare_new(Params *params);
void ElGamalCtShare_free(ElGamalCtShare *share);

ElGamalMsgShare *ElGamalMsgShare_new(Params *params);
void ElGamalMsgShare_free(ElGamalMsgShare *share);

int ElGamalShamir_CreateShares(Params *params, int t, int n, BIGNUM *secret, EC_POINT **pks, ElGamalCtShare **shares);
int ElGamalShamir_ReconstructShares(Params *params, int t, int n, ElGamalMsgShare **shares, EC_POINT *secret);
int ElGamalShamir_ValidateShares(Params *params, int t, int n, ElGamalMsgShare **shares);

#endif
