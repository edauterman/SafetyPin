#include <stdlib.h>
#include <stdio.h>
#include <openssl/bn.h>

#include "common.h"
#include "shamir.h"

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

int Shamir_CreateShares(int t, int n, BIGNUM *secret, BIGNUM *prime, ShamirShare *shares) {
    int rv;
    BIGNUM *a[t];
    BN_CTX *ctx = NULL;

    CHECK_A (ctx = BN_CTX_new());

    /* Generate t random a's to define polynomial. */
    for (int i = 0; i < t; i++) {
        CHECK_A (a[i] = BN_new());
        CHECK_C (BN_rand_range(a[i], prime));
    }

    /* Generate s random x's to evaluate polynomial at. */
    for (int i = 0; i < n; i++) {
        CHECK_C (BN_rand_range(shares[i].x, prime));
        CHECK_C (evalPolynomial(a, t, shares[i].x, shares[i].y, prime, ctx));
    }

cleanup:
    if (ctx) BN_CTX_free(ctx);
    return rv;
}

int Shamir_ReconstructShares(int t, int n, ShamirShare *shares, BIGNUM *prime, BIGNUM *secret) {
    int rv;
    BIGNUM *currTerm = NULL;
    BIGNUM *numerator = NULL;
    BIGNUM *denominator = NULL;
    BIGNUM *denominatorInverse = NULL;
    BIGNUM *lambda = NULL;
    BN_CTX *ctx = NULL;

    CHECK_A (currTerm = BN_new());
    CHECK_A (numerator = BN_new());
    CHECK_A (denominator = BN_new());
    CHECK_A (denominatorInverse = BN_new());
    CHECK_A (lambda = BN_new());
    CHECK_A (ctx = BN_CTX_new());
    BN_zero(secret);

    for (int i = 0; i < t; i++) {
       for (int j = 0; j < t; j++) {
            if (i == j) continue;
            /* lambda = -x_j / (x_i - x_j) */
            CHECK_C (BN_mod_sub(numerator, prime, shares[j].x, prime, ctx));
            CHECK_C (BN_mod_sub(denominator, shares[i].x, shares[j].x, prime, ctx));
            BN_mod_inverse(denominatorInverse, denominator, prime, ctx);
            CHECK_C (BN_mod_mul(lambda, numerator, denominatorInverse, prime, ctx));
            /* Add up lambda * y_i */
            CHECK_C (BN_mod_mul(currTerm, lambda, shares[i].y, prime, ctx));
            CHECK_C (BN_mod_add(secret, secret, currTerm, prime, ctx));
       } 
    }

cleanup:
    if (currTerm) BN_free(currTerm);
    if (numerator) BN_free(numerator);
    if (denominator) BN_free(denominator);
    if (denominatorInverse) BN_free(denominatorInverse);
    if (lambda) BN_free(lambda);
    if (ctx) BN_CTX_free(ctx);
    return rv;
}
