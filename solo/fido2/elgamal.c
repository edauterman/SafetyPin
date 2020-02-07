#include <stdlib.h>
#include <stdio.h>

#include "uECC.h"

fieldElem sk;

void ElGamal_Init() {
    uECC_randInt(sk);   
}

/* pk must be 33 bytes */
void ElGamal_GetPk(uint8_t *pk) {
    ecPoint pkPt;
    uECC_basePointMult(pkPt, sk);
    uint8_t rawPk[64];
    uECC_pointToBytesUncompressed(rawPk, pkPt);
    printf("pk: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", rawPk[i]);
    }
    printf("\n");
    uECC_pointToBytesCompressed(pk, pkPt);
}

/* ct is 66 bytes, msg is 33 bytes */
void ElGamal_Decrypt(uint8_t *ct, uint8_t *msg) {
    ecPoint R, C;
    ecPoint tmp, result;
    fieldElem skInv;

    uECC_bytesToPointCompressed(R, ct);
    uECC_bytesToPointCompressed(C, ct + 33);
    
    uint8_t rRaw[64];
    uint8_t cRaw[64];
    uECC_pointToBytesUncompressed(rRaw, R);
    uECC_pointToBytesUncompressed(cRaw, C);

    /* R^-sk * C */
    uint8_t skInvBuf[32];
    uint8_t skBuf[32];
    uECC_modNeg(skInv, sk);
    uECC_pointMult(tmp, R, skInv);
    uECC_pointAdd(result, tmp, C);
    uECC_pointToBytesCompressed(msg, result);
}
