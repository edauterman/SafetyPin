#include <stdlib.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <algorithm>
#include <string>

#include "common.h"
#include "hsm.h"
#include "params.h"
#include "shamir.h"
#include "elgamal.h"
#include "elgamal_shamir.h"

using namespace std;

ElGamalCtShare *ElGamalCtShare_new(Params *params) {
    int rv;
    ElGamalCtShare *share = NULL;
    
    CHECK_A (share = (ElGamalCtShare *)malloc(sizeof(ElGamalCtShare)));
    CHECK_A (share->ct = ElGamalCiphertext_new(params));
    CHECK_A (share->x = BN_new());

cleanup:
    if (rv == OKAY) return share;
    ElGamalCtShare_free(share);
    return NULL;
}

void ElGamalCtShare_free(ElGamalCtShare *share) {
    if (share && share->ct) ElGamalCiphertext_free(share->ct);
    if (share && share->x) BN_free(share->x);
    if (share) free(share);
}

ElGamalMsgShare *ElGamalMsgShare_new(Params *params) {
    int rv;
    ElGamalMsgShare *share = NULL;
    
    CHECK_A (share = (ElGamalMsgShare *)malloc(sizeof(ElGamalMsgShare)));
    CHECK_A (share->msg = EC_POINT_new(params->group));
    CHECK_A (share->x = BN_new());

cleanup:
    if (rv == OKAY) return share;
    ElGamalMsgShare_free(share);
    return NULL;
}

void ElGamalMsgShare_free(ElGamalMsgShare *share) {
    if (share && share->msg) EC_POINT_free(share->msg);
    if (share && share->x) BN_free(share->x);
    if (share) free(share);
}

int ElGamalShamir_CreateShares(Params *params, int t, int n, BIGNUM *secret, EC_POINT **pks, ElGamalCtShare **shares) {
    int rv;
    ShamirShare **shamirShares = NULL;
    EC_POINT *msg = NULL;

    CHECK_A (shamirShares = (ShamirShare **)malloc(n * sizeof(ShamirShare *)));
    for (int i = 0; i < n; i++) {
        CHECK_A (shamirShares[i] = ShamirShare_new());
    }
    CHECK_A (msg = EC_POINT_new(params->group));

    CHECK_C (Shamir_CreateShares(t, n, secret, params->order, shamirShares));


    for (int i = 0; i < n; i++) {
        CHECK_A (shares[i]->x = BN_dup(shamirShares[i]->x));
        CHECK_C (EC_POINT_mul(params->group, msg, shamirShares[i]->y, NULL, NULL, params->bn_ctx));
        CHECK_C (ElGamal_Encrypt(params, msg, pks[i], shares[i]->ct)); 
    }

cleanup:
    for (int i = 0; i < n; i++) {
        if (shamirShares && shamirShares[i]) ShamirShare_free(shamirShares[i]);
    }
    if (shamirShares) free(shamirShares);
    if (msg) EC_POINT_free(msg);
    return rv;
}

int ElGamalShamir_ReconstructShares(Params *params, int t, int n, ElGamalMsgShare **shares, EC_POINT *secret) {
    int rv = ERROR;
    EC_POINT *currTerm = NULL;
    BIGNUM *numerator = NULL;
    BIGNUM *denominator = NULL;
    BIGNUM *denominatorInverse = NULL;
    BIGNUM *lambda = NULL;
    BIGNUM *currLambda = NULL;
    const EC_POINT *generator = NULL;
    BIGNUM *zero = NULL;

    CHECK_A (currTerm = EC_POINT_new(params->group));
    CHECK_A (numerator = BN_new());
    CHECK_A (denominator = BN_new());
    CHECK_A (denominatorInverse = BN_new());
    CHECK_A (lambda = BN_new());
    CHECK_A (currLambda = BN_new());
    CHECK_A (generator = EC_GROUP_get0_generator(params->group));
    CHECK_A (zero = BN_new());
    BN_zero(zero);
    //CHECK_C (EC_POINT_copy(secret, generator));

    for (int i = 0; i < t; i++) {
        BN_one(lambda);
        for (int j = 0; j < t; j++) {
            if (i == j) continue;
            /* lambda = \prod_{j=1, j!=i}^t -x_j / (x_i - x_j) */
            CHECK_C (BN_mod_sub(numerator, zero, shares[j]->x, params->order, params->bn_ctx));
            CHECK_C (BN_mod_sub(denominator, shares[i]->x, shares[j]->x, params->order, params->bn_ctx));
            BN_mod_inverse(denominatorInverse, denominator, params->order, params->bn_ctx);
            CHECK_C (BN_mod_mul(currLambda, numerator, denominatorInverse, params->order, params->bn_ctx));
            CHECK_C (BN_mod_mul(lambda, lambda, currLambda, params->order, params->bn_ctx));
        }
        /* Add up terms */
        CHECK_C (EC_POINT_mul(params->group, currTerm, NULL, shares[i]->msg, lambda, params->bn_ctx)); 
        if (i > 0) {
            CHECK_C (EC_POINT_add(params->group, secret, secret, currTerm, params->bn_ctx));
        } else {
            CHECK_C (EC_POINT_copy(secret, currTerm));    
        }
    }


cleanup:
    if (currTerm) EC_POINT_free(currTerm);
    if (numerator) BN_free(numerator);
    if (denominator) BN_free(denominator);
    if (denominatorInverse) BN_free(denominatorInverse);
    if (lambda) BN_free(lambda);
    if (currLambda) BN_free(currLambda);
    if (zero) BN_free(zero);
    return rv;
}

int ElGamalShamir_ValidateShares(Params *params, int t, int n, ElGamalMsgShare **shares) {
    int rv = ERROR;
    int ctr = 0;
    EC_POINT *currTerm = NULL;
    BIGNUM *numerator = NULL;
    BIGNUM *denominator = NULL;
    BIGNUM *denominatorInverse = NULL;
    BIGNUM *lambda = NULL;
    BIGNUM *currLambda = NULL;
    const EC_POINT *generator = NULL;
    BIGNUM *zero = NULL;
    EC_POINT *y = NULL;

    CHECK_A (currTerm = EC_POINT_new(params->group));
    CHECK_A (numerator = BN_new());
    CHECK_A (denominator = BN_new());
    CHECK_A (denominatorInverse = BN_new());
    CHECK_A (lambda = BN_new());
    CHECK_A (currLambda = BN_new());
    CHECK_A (generator = EC_GROUP_get0_generator(params->group));
    CHECK_A (zero = BN_new());
    CHECK_A (y = EC_POINT_new(params->group));
    BN_zero(zero);

    for (int checkPt = t; checkPt < n; checkPt++) {
        for (int i = 0; i < t; i++) {
            BN_one(lambda);
            for (int j = 0; j < t; j++) {
                if (i == j) continue;
                /* lambda = \prod_{j=1, j!=i}^t -x_j / (x_i - x_j) */
                CHECK_C (BN_mod_sub(numerator, shares[checkPt]->x, shares[j]->x, params->order, params->bn_ctx));
                CHECK_C (BN_mod_sub(denominator, shares[i]->x, shares[j]->x, params->order, params->bn_ctx));
                BN_mod_inverse(denominatorInverse, denominator, params->order, params->bn_ctx);
                CHECK_C (BN_mod_mul(currLambda, numerator, denominatorInverse, params->order, params->bn_ctx));
                CHECK_C (BN_mod_mul(lambda, lambda, currLambda, params->order, params->bn_ctx));
            }
            /* Add up terms */
            CHECK_C (EC_POINT_mul(params->group, currTerm, NULL, shares[i]->msg, lambda, params->bn_ctx)); 
            if (i > 0) {
                CHECK_C (EC_POINT_add(params->group, y, y, currTerm, params->bn_ctx));
            } else {
                CHECK_C (EC_POINT_copy(y, currTerm));    
            }
        }
        if (EC_POINT_cmp(params->group, y, shares[checkPt]->msg, params->bn_ctx) == 0) {
            ctr++;
        }
    }
    rv = ctr >= t ? OKAY : ERROR;

cleanup:
    if (currTerm) EC_POINT_free(currTerm);
    if (numerator) BN_free(numerator);
    if (denominator) BN_free(denominator);
    if (denominatorInverse) BN_free(denominatorInverse);
    if (lambda) BN_free(lambda);
    if (currLambda) BN_free(currLambda);
    if (y) EC_POINT_free(y);
    if (zero) BN_free(zero);
    return rv;
}

int ElGamalShamir_ReconstructSharesWithValidation(Params *params, int t, int n, ElGamalMsgShare **shares, EC_POINT *secret) {
    int rv;
    ElGamalMsgShare **currShares = NULL;
    string bitmask(t, 1);
    bitmask.resize(n, 0);

    CHECK_A (currShares = (ElGamalMsgShare **)malloc(n * sizeof(ElGamalMsgShare *)));

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
        if (ElGamalShamir_ValidateShares(params, t, n, currShares) == OKAY) {
            CHECK_C (ElGamalShamir_ReconstructShares(params, t, n, currShares, secret));
            goto cleanup;
        }
    } while (prev_permutation(bitmask.begin(), bitmask.end()));
    printf("No valid reconstruction");
    rv = ERROR;

cleanup:
    if (currShares) free(currShares);
    return rv;
}
