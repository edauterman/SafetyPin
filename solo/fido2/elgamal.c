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

    printf("r compressed: ");
    for (int i = 0; i < 33; i++) {
        printf("%02x", ct[i]);
    }
    printf("\n");

    printf("c compressed: ");
    for (int i = 0; i < 33; i++) {
        printf("%02x", (ct + 33)[i]);
    }
    printf("\n");



    uECC_bytesToPointCompressed(R, ct);
    uECC_bytesToPointCompressed(C, ct + 33);
    
    uint8_t rRaw[64];
    uint8_t cRaw[64];
    uECC_pointToBytesUncompressed(rRaw, R);
    uECC_pointToBytesUncompressed(cRaw, C);
    printf("r: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", rRaw[i]);
    }
    printf("\n");

    printf("c: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", cRaw[i]);
    }
    printf("\n");

    /* R^-sk * C */
    uint8_t skInvBuf[32];
    uint8_t skBuf[32];
    uECC_fieldElemToBytes(skInvBuf, skInv);
    printf("skInv before: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", skInvBuf[i]);
    }
    printf("\n");
    
    printf("going to call modinv\n");
    uECC_modNeg(skInv, sk);
    printf("after modinv\n");
    uECC_fieldElemToBytes(skBuf, sk);
    uECC_fieldElemToBytes(skInvBuf, skInv);
    printf("sk: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", skBuf[i]);
    }
    printf("\n");
    printf("skInv: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", skInvBuf[i]);
    }
    printf("\n");
    uECC_pointMult(tmp, R, skInv);
    uECC_pointAdd(result, tmp, C);

    uint8_t resultBuf[64];
    uECC_pointToBytesUncompressed(resultBuf, result);
    printf("result: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", resultBuf[i]);
    }
    printf("\n");

    uECC_pointToBytesCompressed(msg, result);
}
