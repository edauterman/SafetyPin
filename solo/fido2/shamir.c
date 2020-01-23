#include <stdlib.h>

#include "hsm.h"
#include "shamir.h"
#include "uECC.h"
//#include "../crypto/cifra/src/arm/unacl/scalarmult.c"

void Shamir_ReconstructShares(int t, int n, struct ShamirShare **shares, fieldElem secret) {
    fieldElem currTerm, numerator, denominator, denominatorInverse, lambda, currLambda, zero;
    uECC_setZero(zero);
    uECC_setZero(secret);

    for (int i = 0; i < t; i++) {
        uECC_setOne(lambda);
        for (int j = 0; j < t; j++) {
            if (i == j) continue;
            /* lambda = \prod_{j=1, j!=i}^t -x_j / (x_i - x_j) */
            uECC_modSub(numerator, zero, shares[j]->x);
            uECC_modSub(denominator, shares[i]->x, shares[j]->x);
            uECC_modInv(denominatorInverse, denominator);
            uECC_modMul(currLambda, numerator, denominatorInverse);
            uECC_modMul(lambda, lambda, currLambda);
        }   
        /* Add up lambda * y_i */
        uECC_modMul(currTerm, lambda, shares[i]->y);
        uECC_modAdd(secret, secret, currTerm);
    }   
}

int Shamir_ValidateShares(int t, int n, struct ShamirShare **shares) {
    fieldElem currTerm, numerator, denominator, denominatorInverse, lambda, currLambda, y, scratch;

    for (int checkPt = t; checkPt < n; checkPt++) {
        uECC_setZero(y);
        for (int i = 0; i < t; i++) {
            uECC_setOne(lambda);
            for (int j = 0; j < t; j++) {
                if (i == j) continue;
                /* lambda = \prod_{j=1, j!=i}^t -x_j / (x_i - x_j) */
                uECC_modSub(numerator, shares[checkPt]->x, shares[j]->x);
                uECC_modSub(denominator, shares[i]->x, shares[j]->x);
                uECC_modInv(denominatorInverse, denominator);
                uECC_modMul(currLambda, numerator, denominatorInverse);
                uECC_modMul(lambda, lambda, currLambda);
            }   
            /* Add up lambda * y_i */
            uECC_modMul(currTerm, lambda, shares[i]->y);
            uECC_modAdd(y, y, currTerm);
        }
        if (!uECC_equal(shares[checkPt]->y, y)) return ERROR;
    }
    return OKAY;
}
