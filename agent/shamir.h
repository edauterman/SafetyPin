#ifndef __SHAMIR_H_INCLUDED__
#define __SHAMIR_H_INCLUDED__

#include <stdint.h>
#include <openssl/bn.h>

typedef struct {
    BIGNUM *x;
    BIGNUM *y;
} ShamirShare;

int Shamir_CreateShares(int t, int n, BIGNUM *secret, BIGNUM *prime, ShamirShare *shares);
int Shamir_ReconstructShares(int t, int n, ShamirShare *shares, BIGNUM *prime, BIGNUM *secret);
#endif
