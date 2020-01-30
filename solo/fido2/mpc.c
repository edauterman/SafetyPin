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
    
    /* e * [a] */
    uECC_modMult(term3, e, a);

    /* Sum terms. */
    uECC_modAdd(scratch1, term1, term2);
    uECC_modAdd(scratch2, scratch1, term3);
    uECC_modAdd(res, scratch2, c);
}

/* PLACEHOLDER */
int validateShares(fieldElem *sharesX, fieldElem *sharesY) {
    fieldElem numerator, denominator, denominatorInv, currLambda, lambda, currTerm, y;
    for (int checkPt = HSM_THRESHOLD_SIZE; checkPt < HSM_HONEST_MAJORITY; checkPt++) {
        uECC_setZero(y);
        for (int i = 0; i < HSM_THRESHOLD_SIZE; i++) {
            uECC_setOne(lambda);
            for (int j = 0; j < HSM_THRESHOLD_SIZE; j++) {
                if (i == j) continue;
                /* lambda = \prod_{j=1, j!=i}^t -x_j / (x_i - x_j) */
                uECC_modSub(numerator, sharesX[checkPt], sharesX[j]);
                uECC_modSub(denominator, sharesX[i], sharesX[j]);
                uECC_modInv(denominatorInv, denominator);
                uECC_modMult(currLambda, numerator, denominatorInv);
                uECC_modMult(lambda, lambda, currLambda);
            }
            /* Add up lambda * y_i */
            uECC_modMult(currTerm, lambda, sharesY[i]);
            uECC_modAdd(y, y, currTerm);
        }
        /* Check if share evaluates correctly. */
        if (uECC_equal(y, sharesY[checkPt]) == 0) {
            uint8_t yBuf[FIELD_ELEM_LEN];
            uint8_t sharesYBuf[FIELD_ELEM_LEN];
            uECC_fieldElemToBytes(yBuf, y);
            uECC_fieldElemToBytes(sharesYBuf, sharesY[checkPt]);
            printf1(TAG_HSM, "share validation FAILED\n");
            return ERROR;
        }
    }
    //printf1(TAG_HSM, "share validation succeeded\n");
    return OKAY;
}

/* PLACEHOLDER */
int checkReconstruction(fieldElem *sharesX, fieldElem *sharesY, fieldElem result) {
    fieldElem numerator, denominator, denominatorInv, currLambda, lambda, currTerm, zero, resultTest;
    uECC_setZero(zero);
    uECC_setZero(resultTest);
    for (int i = 0; i < HSM_THRESHOLD_SIZE; i++) {
        uECC_setOne(lambda);
        for (int j = 0; j < HSM_THRESHOLD_SIZE; j++)  {
            if (i == j) continue;
            /* lambda = \prod_{j=1, j!=i}^t -x_j / (x_i - x_j) */
            uECC_modSub(numerator, zero, sharesX[j]);
            uECC_modSub(denominator, sharesX[i], sharesX[j]);
            uECC_modInv(denominatorInv, denominator);
            uECC_modMult(currLambda, numerator, denominatorInv);
            uECC_modMult(lambda, lambda, currLambda);
        }
        /* Add up lambda * y_i */
        uECC_modMult(currTerm, lambda, sharesY[i]);
        uECC_modAdd(resultTest, resultTest, currTerm);
    }
    if (uECC_equal(resultTest, result) == 0) {
        printf1(TAG_HSM, "check reconstruction FAILED\n");
    }
    return (uECC_equal(resultTest, result) != 0) ? OKAY : ERROR;
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

    /*printf("pinDiffShare: ");
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
*/


    /* Start computation for r * (pin - pin') */
    fieldElem dShare, eShare, rShare;
    uECC_bytesToFieldElem(rShare, currMpcMsg->rShare);
    uECC_bytesToFieldElem(a, currMpcMsg->a);
    uECC_bytesToFieldElem(b, currMpcMsg->b);
    uECC_bytesToFieldElem(c, currMpcMsg->c);
    multiplyStart(dShare, eShare, rShare, pinDiffShare, a, b);

    uECC_fieldElemToBytes(dShareBuf, dShare);
    uECC_fieldElemToBytes(eShareBuf, eShare);
  
  /*  printf("dShare: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", dShareBuf[i]);
    }
    printf("\n");

    printf("eShare: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", eShareBuf[i]);
    }
    printf("\n");
*/
    /* MAC results. */ 
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t macKey[KEY_LEN];
        getMacKey(macKey, hsms[i]);
        crypto_hmac(macKey, dMacs[i], dShareBuf, FIELD_ELEM_LEN);
        //crypto_hmac(macKeys[hsms[i]], dMacs[i], dShareBuf, FIELD_ELEM_LEN);
  /*      printf("mac key[%d]: ", hsms[i]);
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
    */    
        crypto_hmac(macKey, eMacs[i], eShareBuf, FIELD_ELEM_LEN);
        //crypto_hmac(macKeys[hsms[i]], eMacs[i], eShareBuf, FIELD_ELEM_LEN);
    }
}

/* TODO: x coordinate of share is always the HSM id? */
int MPC_Step2(uint8_t *resultShareBuf, uint8_t resultMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t *dBuf, uint8_t *eBuf, uint8_t dShareBufs[HSM_HONEST_MAJORITY][FIELD_ELEM_LEN], uint8_t eShareBufs[HSM_HONEST_MAJORITY][FIELD_ELEM_LEN], uint8_t dShareXBufs[HSM_HONEST_MAJORITY], uint8_t eShareXBufs[HSM_HONEST_MAJORITY], uint8_t dMacs[HSM_HONEST_MAJORITY][SHA256_DIGEST_LEN], uint8_t eMacs[HSM_HONEST_MAJORITY][SHA256_DIGEST_LEN], uint8_t *validHsms, uint8_t *allHsms) {
    fieldElem resultShare;

    /* Check MACs for shares returned. */
    for (int i = 0; i < HSM_HONEST_MAJORITY; i++) {
    /*    printf("dShare[%d]: ", i);
        for (int j = 0; j < FIELD_ELEM_LEN; j++) {
            printf("%02x", dShareBufs[i][j]);
        }
        printf("\n");
        printf("dMacs[%d]: ", i);
        for (int j = 0; j < SHA256_DIGEST_LEN; j++) {
            printf("%02x", dMacs[i][j]);
        }
        printf("\n");
*/


        uint8_t mac[SHA256_DIGEST_LEN];
        uint8_t macKey[KEY_LEN];
        getMacKey(macKey, validHsms[i]);
        crypto_hmac(macKey, mac, dShareBufs[i], FIELD_ELEM_LEN);
        //crypto_hmac(macKeys[validHsms[i]], mac, dShareBufs[i], FIELD_ELEM_LEN);
  /*      printf("computed mac[%d]: ", i);
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
    */    

        if (memcmp(mac, dMacs[i], SHA256_DIGEST_LEN) != 0) return ERROR;
        crypto_hmac(macKey, mac, eShareBufs[i], FIELD_ELEM_LEN);
        if (memcmp(mac, eMacs[i], SHA256_DIGEST_LEN) != 0) return ERROR;
    }

    /* Check that shares actually produce the correct result. */
    fieldElem d, e;
    fieldElem dSharesX[HSM_HONEST_MAJORITY];
    fieldElem dSharesY[HSM_HONEST_MAJORITY];
    fieldElem eSharesX[HSM_HONEST_MAJORITY];
    fieldElem eSharesY[HSM_HONEST_MAJORITY];
    uECC_bytesToFieldElem(d, dBuf);
    uECC_bytesToFieldElem(e, eBuf);
    for (int i = 0; i < HSM_HONEST_MAJORITY; i++) {
        uECC_bytesToFieldElem(dSharesY[i], dShareBufs[i]);
        uECC_bytesToFieldElem(eSharesY[i], eShareBufs[i]);
        uECC_word_t word = dShareXBufs[i] & 0xff;
        //printf("dShareX[%d] = %x, %x\n", i, word, dShareXBufs[i]);
        uECC_setWord(dSharesX[i], word);
        word = eShareXBufs[i] & 0xff;
        //printf("eShareX[%d] = %x, %x\n", i, word, eShareXBufs[i]);
        uECC_setWord(eSharesX[i], word);
    }
    if (validateShares(dSharesX, dSharesY) != OKAY) {memset(resultShareBuf, 1, FIELD_ELEM_LEN); return ERROR;}
    if (validateShares(eSharesX, eSharesY) != OKAY) {memset(resultShareBuf, 1, FIELD_ELEM_LEN); return ERROR;}
    if (checkReconstruction(dSharesX, dSharesY, d) != OKAY) {memset(resultShareBuf, 2, FIELD_ELEM_LEN); return ERROR;}
    if (checkReconstruction(eSharesX, eSharesY, e) != OKAY) {memset(resultShareBuf, 2, FIELD_ELEM_LEN); return ERROR;}

    /* Finish computing r * (pin - pin') */
    multiplyFinish(resultShare, a, b, c, d, e, thresholdSize);
   
    /* MAC and return resultShare. */
    uECC_fieldElemToBytes(resultShareBuf, resultShare);
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t macKey[KEY_LEN];
        getMacKey(macKey, allHsms[i]);
        crypto_hmac(macKey, resultMacs[i], resultShareBuf, FIELD_ELEM_LEN);
        //crypto_hmac(macKeys[allHsms[i]], resultMacs[i], resultShareBuf, FIELD_ELEM_LEN);
    }
    /*printf("resultShare: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", resultShareBuf[i]);
    }
    printf("\n");
*/
    return OKAY; 
}

int MPC_Step3(uint8_t *returnMsg, uint8_t *resultBuf, uint8_t resultShareBufs[HSM_HONEST_MAJORITY][FIELD_ELEM_LEN], uint8_t resultShareXBufs[HSM_HONEST_MAJORITY], uint8_t resultMacs[HSM_HONEST_MAJORITY][SHA256_DIGEST_LEN], uint8_t *validHsms) {
    fieldElem result;
    fieldElem zero;
    uint8_t resultBytes[FIELD_ELEM_LEN];
    uECC_setZero(zero);

    /* Check MACs for shares returned */
    for (int i = 0; i < HSM_HONEST_MAJORITY; i++) {
        uint8_t mac[SHA256_DIGEST_LEN];
        uint8_t macKey[KEY_LEN];
        getMacKey(macKey, validHsms[i]);
        crypto_hmac(macKey, mac, resultShareBufs[i], FIELD_ELEM_LEN);
        //crypto_hmac(macKeys[validHsms[i]], mac, resultShareBufs[i], FIELD_ELEM_LEN);
        if (memcmp(mac, resultMacs[i], SHA256_DIGEST_LEN) != 0) {
            memset(returnMsg, 0xaa, FIELD_ELEM_LEN);
            return ERROR;
        }
    }
    //printf1(TAG_HSM, "passed MAC checks\n");

    /* Check that shares actually produce the correct result. */
    fieldElem resultSharesX[HSM_HONEST_MAJORITY];
    fieldElem resultSharesY[HSM_HONEST_MAJORITY];
    uECC_bytesToFieldElem(result, resultBuf);
    for (int i = 0; i < HSM_HONEST_MAJORITY; i++) {
        uECC_bytesToFieldElem(resultSharesY[i], resultShareBufs[i]);
        uECC_word_t word = resultShareXBufs[i] & 0xff;
        uECC_setWord(resultSharesX[i], word);
    }
    if (validateShares(resultSharesX, resultSharesY) != OKAY) {memset(returnMsg, 0xbb, FIELD_ELEM_LEN); return ERROR;}
    if (checkReconstruction(resultSharesX, resultSharesY, result) != OKAY) {memset(returnMsg, 0xcc, FIELD_ELEM_LEN); return ERROR;}

    uECC_fieldElemToBytes(resultBytes, result);
/*    printf("result: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", resultBytes[i]);
    }
    printf("\n");
*/
    /* Check if result == 0. If so, return msg. */
    if (uECC_equal(zero, result) == 0) return ERROR;
    //if (uECC_equal(zero, result) == 0) printf("BAD PIN CHECK --  will bypass for testing\n");//return ERROR;
    printf1(TAG_HSM, "pin check passed\n");
    memcpy(returnMsg, msg, FIELD_ELEM_LEN);
    return OKAY;
}

void MPC_SetMacKeys(uint8_t *macKeysIn) {
    raw_flash_write(macKeysIn, 100 * KEY_LEN);
    uECC_setWord(thresholdSize, HSM_THRESHOLD_SIZE);
}
