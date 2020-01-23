#include <stdlib.h>
#include <stdio.h>

//#include "../crypto/cifra/src/arm/unacl/scalarmult.c"
#include "fe25519.h"

void add(fe25519 *res, fe25519 *y, fe25519 *z) {
    fe25519_add(res, y, z);
}

/* Takes as input shares of x,y and shares of beaver triples a,b,c and
 * computes shares of intermediate values d,e */
void multiplyStart(fe25519 *d, fe25519 *e, fe25519 *y, fe25519 *z, fe25519 *a, fe25519 *b) {
    fe25519_sub(d, y, a);
    fe25519_sub(e, z, b);
}

/* Takes as input secret shares of beaver triples a,b,c and values d,e
 * computed in multiplyStart */
void multiplyFinish(fe25519 *res, fe25519 *a, fe25519 *b, fe25519 *c, fe25519 *d, fe25519 *e, fe25519 *numParties) {
    fe25519 term1, term2, term3, scratch1, scratch2, scratch3, scratch4, numPartiesInverse;
    
    /* d * e / numParties */
    fe25519_mul(&scratch4, d, e);
    fe25519_invert_useProvidedScratchBuffers(&numPartiesInverse, numParties, &scratch1, &scratch2, &scratch3);
    fe25519_mul(&term1, &scratch4, &numPartiesInverse);

    /* d * [b] */
    fe25519_mul(&term2, d, b);

    /* e * [a] */
    fe25519_mul(&term3, e, a);

    /* Sum terms. */
    fe25519_add(&scratch1, &term1, &term2);
    fe25519_add(&scratch2, &scratch1, &term3);
    fe25519_add(res, &scratch2, c);
}
