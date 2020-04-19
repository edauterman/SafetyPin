#ifndef _ELGAMAL_SHAMIR_H
#define _ELGAMAL_SHAMIR_H

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "elgamal.h"
#include "hsm.h"
//#include "params.h"

typedef struct {
    BIGNUM *x;
    ElGamal_ciphertext *ct;
} ElGamalCtShare;

typedef struct {
    EC_POINT *R;
    ElGamalCtShare **shares;
    uint8_t aesCt[FIELD_ELEM_LEN];
} LocationHidingCt;

LocationHidingCt *LocationHidingCt_new(Params *params, int n);
void LocationHidingCt_free(LocationHidingCt *c, int n);

ElGamalCtShare *ElGamalCtShare_new(Params *params);
void ElGamalCtShare_free(ElGamalCtShare *share);

int ElGamalShamir_CreateShares(Params *params, int t, int n, uint8_t *msg, EC_POINT **pks, LocationHidingCt *ct, BIGNUM **opt_x);
int ElGamalShamir_ReconstructShares(Params *params, int t, int n, LocationHidingCt *ct, ShamirShare **shares, uint8_t *msg);
#endif
