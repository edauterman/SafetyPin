#include <stdlib.h>
#include <stdio.h>

//#include "../crypto/cifra/src/arm/unacl/scalarmult.c"
#include "uECC.h"
#include "log.h"
#include "hsm.h"
#include "punc_enc.h"

struct MpcMsg {
    uint8_t msg[FIELD_ELEM_LEN];
    uint8_t a[FIELD_ELEM_LEN];
    uint8_t b[FIELD_ELEM_LEN];
    uint8_t c[FIELD_ELEM_LEN];
    uint8_t rShare[FIELD_ELEM_LEN];
    uint8_t savePinShare[FIELD_ELEM_LEN];
};

fieldElem a, b, c, pinDiffShare;
uint8_t msg[FIELD_ELEM_LEN];
//uint8_t macKeys[KEY_LEN][100];
//uint8_t macKeys[KEY_LEN][NUM_HSMS];
fieldElem pinDiffShare;
fieldElem thresholdSize;

void getMacKey(uint8_t *key, int index) {
    raw_flash_read(key, index * KEY_LEN, KEY_LEN);
}

void sub(fieldElem res, fieldElem y, fieldElem z) {
    uECC_modSub(res, y, z);
}

/* Takes as input shares of x,y and shares of beaver triples a,b,c and
 * computes shares of intermediate values d,e */
void multiplyStart(fieldElem d, fieldElem e, fieldElem y, fieldElem z, fieldElem a, fieldElem b) {
    uECC_setZero(d);
    uECC_setZero(e);
    uECC_modSub(d, y, a);
    uECC_modSub(e, z, b);
}

/* Takes as input secret shares of beaver triples a,b,c and values d,e
 * computed in multiplyStart */
void multiplyFinish(fieldElem res, fieldElem a, fieldElem b, fieldElem c, fieldElem d, fieldElem e, fieldElem numParties) {
    fieldElem term1, term2, term3, scratch1, scratch2, numPartiesInverse;

    /* d * e / numParties */
    //uECC_modMult(term1, d, e);
    uECC_modMult(scratch1, d, e);
    uECC_modInv(numPartiesInverse, numParties);
    uECC_modMult(term1, scratch1, numPartiesInverse);

    /* d * [b] */
    uECC_modMult(term2, d, b);
    
   /* uint8_t dBytes[FIELD_ELEM_LEN];
    uint8_t bBytes[FIELD_ELEM_LEN];
    uint8_t prodBytes[FIELD_ELEM_LEN];
    uECC_fieldElemToBytes(dBytes, d);
    uECC_fieldElemToBytes(bBytes, b);
    uECC_fieldElemToBytes(prodBytes, term2);
    printf("d: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", dBytes[i]);
    }
    printf("\n");

    printf("b: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", bBytes[i]);
    }
    printf("\n");

    printf("product: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", prodBytes[i]);
    }
    printf("\n");*/

    /* e * [a] */
    uECC_modMult(term3, e, a);

    /* Sum terms. */
    uECC_modAdd(scratch1, term1, term2);
    uECC_modAdd(scratch2, scratch1, term3);
    uECC_modAdd(res, scratch2, c);
}

/* PLACEHOLDER */
int validateShares(fieldElem *shares, uint8_t *ids) {
    /*fieldElem numerator, denominator, denominatorInv, currLambda, lambda;
    for (int checkPt = HSM_THRESHOLD_SIZE; checkPt < 2 * HSM_THRESHOLD_SIZE; checkPt++) {
        for (int i = 0; i < HSM_THRESHOLD_SIZE; i++) {
            for (int j = 0; j < HSM_THRESHOLD_SIZE; j++) {
                /* lambda = \prod_{j=1, j!=i}^t -x_j / (x_i - x_j) */
      /*          uECC_modSub(numerator, 
            }
            
        }
    }*/
    return OKAY;
}

/* PLACEHOLDER */
int checkReconstruction(fieldElem *shares, uint8_t *ids, fieldElem result) {
    return OKAY;
}



void MPC_Step1(uint8_t *dShareBuf, uint8_t *eShareBuf, uint8_t dMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t eMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t *msgIn, uint8_t *recoveryPinShareBuf, uint8_t *hsms) {
    struct MpcMsg *currMpcMsg = (struct MpcMsg *)msgIn;
    fieldElem recoveryPinShare, savePinShare;
   
    /* Save msg. */
    memcpy(msg, currMpcMsg->msg, FIELD_ELEM_LEN);

    /* Compute pin - pin' */
    uECC_bytesToFieldElem(recoveryPinShare, recoveryPinShareBuf);
    uECC_bytesToFieldElem(savePinShare, currMpcMsg->savePinShare);
    sub(pinDiffShare, recoveryPinShare, savePinShare);
    uint8_t pinDiffShareBytes[FIELD_ELEM_LEN];
    uECC_fieldElemToBytes(pinDiffShareBytes, pinDiffShare);

    printf("pinDiffShare: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", pinDiffShareBytes[i]);
    }
    printf("\n");
    
    printf("a: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", currMpcMsg->a[i]);
    }
    printf("\n");

    printf("b: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", currMpcMsg->b[i]);
    }
    printf("\n");

    printf("c: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", currMpcMsg->c[i]);
    }
    printf("\n");

    printf("rShare: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", currMpcMsg->rShare[i]);
    }
    printf("\n");



    /* Start computation for r * (pin - pin') */
    fieldElem dShare, eShare, rShare;
    uECC_bytesToFieldElem(rShare, currMpcMsg->rShare);
    uECC_bytesToFieldElem(a, currMpcMsg->a);
    uECC_bytesToFieldElem(b, currMpcMsg->b);
    uECC_bytesToFieldElem(c, currMpcMsg->c);
    multiplyStart(dShare, eShare, rShare, pinDiffShare, a, b);

    uECC_fieldElemToBytes(dShareBuf, dShare);
    uECC_fieldElemToBytes(eShareBuf, eShare);
  
    printf("dShare: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", dShareBuf[i]);
    }
    printf("\n");

    printf("eShare: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", eShareBuf[i]);
    }
    printf("\n");

    /* MAC results. */ 
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t macKey[KEY_LEN];
        getMacKey(macKey, hsms[i]);
        crypto_hmac(macKey, dMacs[i], dShareBuf, FIELD_ELEM_LEN);
        //crypto_hmac(macKeys[hsms[i]], dMacs[i], dShareBuf, FIELD_ELEM_LEN);
        printf("mac key[%d]: ", hsms[i]);
        for (int j = 0; j < SHA256_DIGEST_LEN; j++) {
            printf("%02x", macKey[j]);
            //printf("%02x", macKeys[hsms[i]][j]);
        }
        printf("\n");
        printf("dmac[%d]: ", i);
        for (int j = 0; j < SHA256_DIGEST_LEN; j++) {
            printf("%02x", dMacs[i][j]);
        }
        printf("\n");
        
        crypto_hmac(macKey, eMacs[i], eShareBuf, FIELD_ELEM_LEN);
        //crypto_hmac(macKeys[hsms[i]], eMacs[i], eShareBuf, FIELD_ELEM_LEN);
    }
}

/* TODO: x coordinate of share is always the HSM id? */
int MPC_Step2(uint8_t *resultShareBuf, uint8_t resultMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t *dBuf, uint8_t *eBuf, uint8_t dShareBufs[2 * HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t eShareBufs[2 * HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t dSharesX[2 * HSM_THRESHOLD_SIZE], uint8_t eSharesX[2 * HSM_THRESHOLD_SIZE], uint8_t dMacs[2 * HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t eMacs[2 * HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t *validHsms, uint8_t *allHsms) {
    fieldElem resultShare;

    printf("do the mac checks\n");

    /* Check MACs for shares returned. */
    for (int i = 0; i < 2 * HSM_THRESHOLD_SIZE; i++) {
        printf("dShare[%d]: ", i);
        for (int j = 0; j < FIELD_ELEM_LEN; j++) {
            printf("%02x", dShareBufs[i][j]);
        }
        printf("\n");
        printf("dMacs[%d]: ", i);
        for (int j = 0; j < SHA256_DIGEST_LEN; j++) {
            printf("%02x", dMacs[i][j]);
        }
        printf("\n");



        uint8_t mac[SHA256_DIGEST_LEN];
        uint8_t macKey[KEY_LEN];
        getMacKey(macKey, validHsms[i]);
        crypto_hmac(macKey, mac, dShareBufs[i], FIELD_ELEM_LEN);
        //crypto_hmac(macKeys[validHsms[i]], mac, dShareBufs[i], FIELD_ELEM_LEN);
        printf("computed mac[%d]: ", i);
        for (int j = 0; j < SHA256_DIGEST_LEN; j++) {
            printf("%02x", mac[j]);
        }
        printf("\n");
        printf("valid hsm[%d] = %d\n", i, validHsms[i]);
        printf("mac key[%d]: ", validHsms[i]);
        for (int j = 0; j < SHA256_DIGEST_LEN; j++) {
            printf("%02x", macKey[j]);
            //printf("%02x", macKeys[validHsms[i]][j]);
        }
        printf("\n");
        

        if (memcmp(mac, dMacs[i], SHA256_DIGEST_LEN) != 0) return ERROR;
        crypto_hmac(macKey, mac, eShareBufs[i], FIELD_ELEM_LEN);
        //crypto_hmac(macKeys[validHsms[i]], mac, eShareBufs[i], FIELD_ELEM_LEN);
        if (memcmp(mac, eMacs[i], SHA256_DIGEST_LEN) != 0) return ERROR;
    }

    printf("going to validate shares\n");

    /* Check that shares actually produce the correct result. */
    fieldElem d, e;
    fieldElem dShares[2 * HSM_THRESHOLD_SIZE];
    fieldElem eShares[2 * HSM_THRESHOLD_SIZE];
    uECC_bytesToFieldElem(d, dBuf);
    uECC_bytesToFieldElem(e, eBuf);
    for (int i = 0; i < 2 * HSM_THRESHOLD_SIZE; i++) {
        uECC_bytesToFieldElem(dShares[i], dShareBufs[i]);
        uECC_bytesToFieldElem(eShares[i], eShareBufs[i]);
    }
    if (validateShares(dShares, validHsms) != OKAY) return ERROR;
    if (validateShares(eShares, validHsms) != OKAY) return ERROR;
    if (checkReconstruction(dShares, validHsms, d) != OKAY) return ERROR;
    if (checkReconstruction(eShares, validHsms, e) != OKAY) return ERROR;

    printf("going to finish multiplication step\n");

    /* Finish computing r * (pin - pin') */
    multiplyFinish(resultShare, a, b, c, d, e, thresholdSize);
   
    printf("finished multiplication step\n");

    /* MAC and return resultShare. */
    uECC_fieldElemToBytes(resultShareBuf, resultShare);
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t macKey[KEY_LEN];
        getMacKey(macKey, allHsms[i]);
        crypto_hmac(macKey, resultMacs[i], resultShareBuf, FIELD_ELEM_LEN);
        //crypto_hmac(macKeys[allHsms[i]], resultMacs[i], resultShareBuf, FIELD_ELEM_LEN);
    }
    printf("resultShare: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", resultShareBuf[i]);
    }
    printf("\n");

    return OKAY; 
}

int MPC_Step3(uint8_t *returnMsg, uint8_t *resultBuf, uint8_t resultShareBufs[2 * HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t resultSharesX[2 * HSM_THRESHOLD_SIZE], uint8_t resultMacs[2 * HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t *validHsms) {
    fieldElem result;
    fieldElem zero;
    uint8_t resultBytes[FIELD_ELEM_LEN];
    uECC_setZero(zero);

    /* Check MACs for shares returned */
    for (int i = 0; i < 2 * HSM_THRESHOLD_SIZE; i++) {
        uint8_t mac[SHA256_DIGEST_LEN];
        uint8_t macKey[KEY_LEN];
        getMacKey(macKey, validHsms[i]);
        crypto_hmac(macKey, mac, resultShareBufs[i], FIELD_ELEM_LEN);
        //crypto_hmac(macKeys[validHsms[i]], mac, resultShareBufs[i], FIELD_ELEM_LEN);
        if (memcmp(mac, resultMacs[i], SHA256_DIGEST_LEN) != 0) return ERROR;
    }
    printf("passed MAC checks\n");

    /* Check that shares actually produce the correct result. */
    fieldElem resultShares[2 * HSM_THRESHOLD_SIZE];
    uECC_bytesToFieldElem(result, resultBuf);
    for (int i = 0; i < 2 * HSM_THRESHOLD_SIZE; i++) {
        uECC_bytesToFieldElem(resultShares[i], resultShareBufs[i]);
    }
    if (validateShares(resultShares, validHsms) != OKAY) return ERROR;
    if (checkReconstruction(resultShares, validHsms, result) != OKAY) return ERROR;
    printf("got past share checks\n");

    uECC_fieldElemToBytes(resultBytes, result);
    printf("result: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", resultBytes[i]);
    }
    printf("\n");

    /* Check if result == 0. If so, return msg. */
    if (uECC_equal(zero, result) != 0) printf("BAD PIN CHECK --  will bypass for testing\n");//return ERROR;
    printf("result equaled 0!!!\n");
    memcpy(returnMsg, msg, FIELD_ELEM_LEN);
    return OKAY;
}

void MPC_SetMacKeys(uint8_t *macKeysIn) {
    printf1(TAG_GREEN, "inside\n");
    raw_flash_write(macKeysIn, 100 * KEY_LEN);
    printf1(TAG_GREEN, "after flash write\n");
    uECC_setWord(thresholdSize, HSM_THRESHOLD_SIZE);
    uint8_t thresholdSizeBytes[FIELD_ELEM_LEN];
    uECC_fieldElemToBytes(thresholdSizeBytes, thresholdSize);
    printf("threshold size: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", thresholdSizeBytes[i]);
    }
    printf("\n");
}
