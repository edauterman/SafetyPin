#ifndef __SHAMIR_H_INCLUDED__
#define __SHAMIR_H_INCLUDED__

#include <stdint.h>
#include <openssl/bn.h>

#define SHAMIR_MARSHALLED_SIZE 32

typedef struct {
    BIGNUM *x;
    BIGNUM *y;
} ShamirShare;

ShamirShare *ShamirShare_new();
void ShamirShare_free(ShamirShare *share);

int Shamir_CreateShares(int t, int n, BIGNUM *secret, BIGNUM *prime, ShamirShare **shares);
int Shamir_ReconstructShares(int t, int n, ShamirShare **shares, BIGNUM *prime, BIGNUM *secret);
int Shamir_ValidateShares(int t, int n, ShamirShare **shares, BIGNUM *prime);

void Shamir_Marshal(uint8_t *buf, ShamirShare *share);
void Shamir_Unmarshal(uint8_t *buf, ShamirShare *share);
#endif
