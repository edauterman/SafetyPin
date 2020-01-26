#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <string>
#include <algorithm>

#include "common.h"
#include "shamir.h"

using namespace std;

ShamirShare *ShamirShare_new() {
    int rv;
    ShamirShare *share = NULL;

    CHECK_A (share = (ShamirShare *)malloc(sizeof(ShamirShare)));
    CHECK_A (share->x = BN_new());
    CHECK_A (share->y = BN_new());
cleanup:
    if (rv == OKAY) return share;
    ShamirShare_free(share);
    return NULL;
}

void ShamirShare_free(ShamirShare *share) {
    if (share->x) BN_free(share->x);
    if (share->y) BN_free(share->y);
    if (share) free(share);
}

/* Given polynomial defined by t a's, evaluate at x and place result in y. */
int evalPolynomial(BIGNUM **a, int t, BIGNUM *x, BIGNUM *y, BIGNUM *prime, BN_CTX *ctx) {
    int rv;
    BIGNUM *currX = NULL;
    BIGNUM *currTerm = NULL;

    CHECK_A (currX = BN_new());
    CHECK_A (currTerm = BN_new());
    BN_one(currX);
    BN_zero(y);

    for (int i = 0; i < t; i++) {
        CHECK_C (BN_mod_mul(currTerm, a[i], currX, prime, ctx));
        CHECK_C (BN_mod_add(y, y, currTerm, prime, ctx));
        CHECK_C (BN_mod_mul(currX, currX, x, prime, ctx));
    }
cleanup:
    if (currX) BN_free(currX);
    if (currTerm) BN_free(currTerm);
    return rv;
}

int Shamir_CreateShares(int t, int n, BIGNUM *secret, BIGNUM *prime, ShamirShare **shares, BIGNUM **opt_x) {
    int rv;
    BIGNUM *a[t];
    BN_CTX *ctx = NULL;

    CHECK_A (ctx = BN_CTX_new());

    /* Set a_0 = secret. */
    CHECK_A (a[0] = BN_dup(secret));
    /* Generate t-1 random a's to define polynomial. */
    for (int i = 1; i < t; i++) {
        CHECK_A (a[i] = BN_new());
        CHECK_C (BN_rand_range(a[i], prime));
    }

    /* Generate s random x's to evaluate polynomial at. */
    for (int i = 0; i < n; i++) {
        if (opt_x == NULL) {
            CHECK_C (BN_rand_range(shares[i]->x, prime));
        } else {
            BN_copy(shares[i]->x, opt_x[i]);
        }
        CHECK_C (evalPolynomial(a, t, shares[i]->x, shares[i]->y, prime, ctx));
    }

cleanup:
    if (ctx) BN_CTX_free(ctx);
    return rv;
}

int Shamir_ReconstructShares(int t, int n, ShamirShare **shares, BIGNUM *prime, BIGNUM *secret) {
    int rv;
    BIGNUM *currTerm = NULL;
    BIGNUM *numerator = NULL;
    BIGNUM *denominator = NULL;
    BIGNUM *denominatorInverse = NULL;
    BIGNUM *lambda = NULL;
    BIGNUM *currLambda = NULL;
    BIGNUM *zero = NULL;
    BN_CTX *ctx = NULL;

    CHECK_A (currTerm = BN_new());
    CHECK_A (numerator = BN_new());
    CHECK_A (denominator = BN_new());
    CHECK_A (denominatorInverse = BN_new());
    CHECK_A (lambda = BN_new());
    CHECK_A (currLambda = BN_new());
    CHECK_A (zero = BN_new());
    CHECK_A (ctx = BN_CTX_new());
    BN_zero(secret);
    BN_zero(zero);

    for (int i = 0; i < t; i++) {
        BN_one(lambda);
        for (int j = 0; j < t; j++) {
            if (i == j) continue;
            /* lambda = \prod_{j=1, j!=i}^t -x_j / (x_i - x_j) */
            CHECK_C (BN_mod_sub(numerator, zero, shares[j]->x, prime, ctx));
            CHECK_C (BN_mod_sub(denominator, shares[i]->x, shares[j]->x, prime, ctx));
            BN_mod_inverse(denominatorInverse, denominator, prime, ctx);
            CHECK_C (BN_mod_mul(currLambda, numerator, denominatorInverse, prime, ctx));
            CHECK_C (BN_mod_mul(lambda, lambda, currLambda, prime, ctx));
        }
        /* Add up lambda * y_i */
        CHECK_C (BN_mod_mul(currTerm, lambda, shares[i]->y, prime, ctx));
        CHECK_C (BN_mod_add(secret, secret, currTerm, prime, ctx));
    }

cleanup:
    if (currTerm) BN_free(currTerm);
    if (numerator) BN_free(numerator);
    if (denominator) BN_free(denominator);
    if (denominatorInverse) BN_free(denominatorInverse);
    if (lambda) BN_free(lambda);
    if (currLambda) BN_free(currLambda);
    if (ctx) BN_CTX_free(ctx);
    return rv;
}

int Shamir_ValidateShares(int t, int n, ShamirShare **shares, BIGNUM *prime) {
    int rv;
    BIGNUM *currTerm = NULL;
    BIGNUM *numerator = NULL;
    BIGNUM *denominator = NULL;
    BIGNUM *denominatorInverse = NULL;
    BIGNUM *lambda = NULL;
    BIGNUM *currLambda = NULL;
    BIGNUM *y = NULL;
    BN_CTX *ctx = NULL;

    CHECK_A (currTerm = BN_new());
    CHECK_A (numerator = BN_new());
    CHECK_A (denominator = BN_new());
    CHECK_A (denominatorInverse = BN_new());
    CHECK_A (lambda = BN_new());
    CHECK_A (currLambda = BN_new());
    CHECK_A (y = BN_new());
    CHECK_A (ctx = BN_CTX_new());
    BN_zero(y);

    /* Check remaining points on same polynomial */
    for (int checkPt = t; checkPt < n; checkPt++) {
        BN_zero(y);
        for (int i = 0; i < t; i++) {
            BN_one(lambda);
            for (int j = 0; j < t; j++) {
                if (i == j) continue;
                /* lambda = \prod_{j=1, j!=i}^t x - x_j / (x_i - x_j) */
                CHECK_C (BN_mod_sub(numerator, shares[checkPt]->x, shares[j]->x, prime, ctx));
                CHECK_C (BN_mod_sub(denominator, shares[i]->x, shares[j]->x, prime, ctx));
                BN_mod_inverse(denominatorInverse, denominator, prime, ctx);
                CHECK_C (BN_mod_mul(currLambda, numerator, denominatorInverse, prime, ctx));
                CHECK_C (BN_mod_mul(lambda, lambda, currLambda, prime, ctx));
            }
            /* Add up lambda * y_i */
            CHECK_C (BN_mod_mul(currTerm, lambda, shares[i]->y, prime, ctx));
            CHECK_C (BN_mod_add(y, y, currTerm, prime, ctx));
        }
        /* Check if g(x_checkPt) = y_checkPt  */
        CHECK_C (BN_cmp(y, shares[checkPt]->y) == 0);
    }

cleanup:
    if (currTerm) BN_free(currTerm);
    if (y) BN_free(y);
    if (numerator) BN_free(numerator);
    if (denominator) BN_free(denominator);
    if (denominatorInverse) BN_free(denominatorInverse);
    if (lambda) BN_free(lambda);
    if (currLambda) BN_free(currLambda);
    if (ctx) BN_CTX_free(ctx);
    return rv;
}

int Shamir_ReconstructSharesWithValidation(int t, int n, ShamirShare **shares, BIGNUM *prime, BIGNUM *secret) {
    int rv; 
    ShamirShare **currShares = NULL;
    string bitmask(t, 1); 
    bitmask.resize(n, 0); 

    CHECK_A (currShares = (ShamirShare **)malloc(n * sizeof(ShamirShare *)));

    do {
        int j = 0;
        for (int i = 0; i < n; i++) {
            if (bitmask[i]) {
                currShares[j] = shares[i];
                j++;
            }   
        }   
        for (int i = 0; i < n; i++) {
            if (!bitmask[i]) {
                currShares[j] =  shares[i];
                j++;
            }   
        }   
        if (Shamir_ValidateShares(t, n, currShares, prime) == OKAY) {
            CHECK_C (Shamir_ReconstructShares(t, n, currShares, prime, secret));
            goto cleanup;
        }   
    } while (prev_permutation(bitmask.begin(), bitmask.end()));
    printf("No valid reconstruction");
    rv = ERROR;

cleanup:
    if (currShares) free(currShares);
    return rv; 
}

/* Requires 32 bytes. */
/*void Shamir_Marshal(uint8_t *buf, ShamirShare *share) {
    memset(buf, 0, 32);
    BN_bn2bin(share->x, buf + 16 - BN_num_bytes(share->x));
    BN_bn2bin(share->y, buf + 32 - BN_num_bytes(share->y));
}

void Shamir_Unmarshal(uint8_t *buf, ShamirShare *share) {
    BN_bin2bn(buf, 16, share->x);
    BN_bin2bn(buf + 16, 16, share->y);
}*/

void Shamir_MarshalCompressed(uint8_t *buf, ShamirShare *share) {
    memset(buf, 0, 32);
    BN_bn2bin(share->y, buf + 32 - BN_num_bytes(share->y));
}

void Shamir_UnmarshalCompressed(uint8_t *buf, uint8_t x, ShamirShare *share) {
    BN_bin2bn(x, 1, share->x);
    BN_bin2bn(buf, 32, share->y);
}
