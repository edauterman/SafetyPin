#ifndef _SHAMIR_H
#define _SHAMIR_H

#include "uECC.h"
//#include "../crypto/cifra/src/arm/unacl/scalarmult.c"

struct ShamirShare {
    fieldElem x;
    fieldElem y;
};

void Shamir_ReconstructShares(int t, int n, struct ShamirShare **shares, fieldElem secret);
int Shamir_ValidateShares(int t, int n, struct ShamirShare **shares);

#endif
