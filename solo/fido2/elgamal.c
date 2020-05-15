#include <stdlib.h>
#include <stdio.h>

#include "uECC.h"
#include "punc_enc.h"
#include "crypto.h"

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

/* ct is 65 bytes, msg is 32 bytes */
void ElGamal_Decrypt(uint8_t *ct, uint8_t *msg) {
    ecPoint R;
    ecPoint tmp;
    uint8_t tmpBuf[33];
    uint8_t key[32];

    uECC_bytesToPointCompressed(R, ct);
    
    /* R^sk*/
    uECC_pointMult(tmp, R, sk);

    /* H(R^sk) */
    uECC_pointToBytesCompressed(tmpBuf, tmp);
    crypto_sha256_init();
    crypto_sha256_update(tmpBuf, 33);
    crypto_sha256_final(key);

    /* decrypt using H(R^sk) */
    crypto_aes256_init(key, NULL);
    crypto_aes256_decrypt_sep(msg, ct + 33, 32);
}

/* ct is 65 bytes, msg is 32 bytes */
void ElGamal_DecryptWithSk(uint8_t *ct, uint8_t *skBuf, uint8_t *msg) {
    ecPoint R;
    ecPoint tmp;
    uint8_t tmpBuf[33];
    uint8_t key[32];
    fieldElem skCurr;

    uECC_bytesToFieldElem(skCurr, skBuf);

    uECC_bytesToPointCompressed(R, ct);
    
    /* R^sk*/
    uECC_pointMult(tmp, R, skCurr);

    /* H(R^sk) */
    uECC_pointToBytesCompressed(tmpBuf, tmp);
    crypto_sha256_init();
    crypto_sha256_update(tmpBuf, 33);
    crypto_sha256_final(key);

    /* decrypt using H(R^sk) */
    crypto_aes256_init(key, NULL);
    crypto_aes256_decrypt_sep(msg, ct + 33, 32);
}
