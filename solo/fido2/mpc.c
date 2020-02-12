#include <stdlib.h>
#include <stdio.h>

//#include "../crypto/cifra/src/arm/unacl/scalarmult.c"
#include "crypto.h"
#include "uECC.h"
#include "log.h"
#include "hsm.h"
#include "punc_enc.h"

struct InnerMpcMsg {
    uint8_t msg[FIELD_ELEM_LEN];
    uint8_t a[NUM_ATTEMPTS][FIELD_ELEM_LEN];
    uint8_t b[NUM_ATTEMPTS][FIELD_ELEM_LEN];
    uint8_t c[NUM_ATTEMPTS][FIELD_ELEM_LEN];
    uint8_t rShare[FIELD_ELEM_LEN];
    uint8_t savePinShare[FIELD_ELEM_LEN];
};

struct MpcMsg {
    uint8_t aesKey[KEY_LEN];
    uint8_t hmacKey[KEY_LEN];
};

fieldElem a, b, c, pinDiffShare;
uint8_t msg[FIELD_ELEM_LEN];
fieldElem lambdas[HSM_THRESHOLD_SIZE];

uint8_t dShareBuf[FIELD_ELEM_LEN];
uint8_t eShareBuf[FIELD_ELEM_LEN];
uint8_t resultShareBuf[FIELD_ELEM_LEN];

uint8_t dOpening[FIELD_ELEM_LEN];
uint8_t eOpening[FIELD_ELEM_LEN];
uint8_t resultOpening[FIELD_ELEM_LEN];

uint8_t commits1[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN];
uint8_t commits2[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN];

//uint8_t macKeys[KEY_LEN][100];
//uint8_t macKeys[KEY_LEN][NUM_HSMS];

//fieldElem sharesX[2 * HSM_THRESHOLD_SIZE];
//fieldElem sharesY[2 * HSM_THRESHOLD_SIZE];

uint8_t groupSize, thresholdSize;

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
void multiplyFinish(fieldElem res, fieldElem a, fieldElem b, fieldElem c, fieldElem d, fieldElem e) {
    fieldElem term1, term2, term3, scratch1, scratch2/*, numPartiesInverse*/;

    /* d * e / numParties */
    //uECC_modMult(term1, d, e);
    uECC_modMult(term1, d, e);
    //uECC_modInv(numPartiesInverse, numParties);
    //uECC_modMult(term1, scratch1, numPartiesInverse);

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

void precomputeLambdas() {
    fieldElem numerator, denominator, denominatorInverse, x_i, x_j, zero;
    uECC_setZero(zero);

    for (int i = 0; i < thresholdSize; i++) {
        uECC_setOne(lambdas[i]);
        uECC_setWord(x_i, i + 1);
        for (int j = 0; j < thresholdSize; j++) {
            if (i == j) continue;
            uECC_setWord(x_j, j + 1);
            uECC_modSub(numerator, zero, x_j);
            uECC_modSub(denominator, x_i, x_j);
            uECC_modInv(denominatorInverse, denominator);
            uECC_modMult(lambdas[i], lambdas[i], numerator);
            uECC_modMult(lambdas[i], lambdas[i], denominatorInverse);
        }
    }
}

/* will only call this to evaluate that the reconstruction is correct, can change 2 * t to t */
void evalWithLambdas(fieldElem *sharesY, fieldElem y) {
    fieldElem tmp, prod, tmpInv, curr, x_i;
    uECC_setOne(prod);
    uECC_setZero(y);

    for (int i = 0; i < thresholdSize; i++) {
        uECC_modMult(curr, lambdas[i], sharesY[i]);
        uECC_modAdd(y, y, curr);
    }
}

int checkReconstructionWithLambdas(fieldElem *sharesY, fieldElem result) {
    fieldElem result_test;
    evalWithLambdas(sharesY, result_test);
    return (uECC_equal(result_test, result) == 0) ? ERROR : OKAY;
}

void getCoefficients(fieldElem *sharesX, fieldElem *sharesY, fieldElem *cfs) {
    fieldElem denominator, denominatorInverse;

    for (int i = 0; i < thresholdSize; i++) {
        uECC_setOne(cfs[i]);
        for (int j = 0; j < thresholdSize; j++) {
            if (i == j) continue;
            uECC_modSub(denominator, sharesX[i], sharesX[j]);
            uECC_modInv(denominatorInverse, denominator);
            uECC_modMult(cfs[i], cfs[i], denominatorInverse);
        }
        uECC_modMult(cfs[i], cfs[i], sharesY[i]);
    }
}

void evalWithCoefficients(fieldElem *sharesX, fieldElem *sharesY, fieldElem *cfs, fieldElem x, fieldElem y) {
    fieldElem tmp, prod, tmpInv, curr;
    uECC_setOne(prod);
    uECC_setZero(y);

    for (int i = 0; i < thresholdSize; i++) {
        uECC_modSub(tmp, x, sharesX[i]);
        uECC_modMult(prod, prod, tmp);
    }

    for (int i = 0; i < thresholdSize; i++) {
        uECC_modSub(tmp, x, sharesX[i]);
        uECC_modInv(tmpInv, tmp);
        uECC_modMult(curr, prod, tmpInv);
        uECC_modMult(curr, curr, cfs[i]);
        uECC_modAdd(y, y, curr);
    }
}

int checkShares(fieldElem *sharesX, fieldElem *sharesY, fieldElem result) {
    fieldElem cfs[HSM_THRESHOLD_SIZE];
    fieldElem y;
    fieldElem x;
    uECC_setZero(x);
    
    getCoefficients(sharesX, sharesY, cfs);

    evalWithCoefficients(sharesX, sharesY, cfs, x, y);
    if (uECC_equal(y, result) == 0) return ERROR;

    for (int i = thresholdSize; i < 2 * thresholdSize; i++) {
        evalWithCoefficients(sharesX, sharesY, cfs, sharesX[i], y);
        if (uECC_equal(y, sharesY[i]) == 0) return ERROR;
    }

    return OKAY;
}

/* PLACEHOLDER */
int validateShares(fieldElem *sharesX, fieldElem *sharesY) {
    fieldElem numerator, denominator, denominatorInv, currLambda, lambda, currTerm, y;
    for (int checkPt = thresholdSize; checkPt < 2 * thresholdSize; checkPt++) {
        uECC_setZero(y);
        for (int i = 0; i < thresholdSize; i++) {
            uECC_setOne(lambda);
            for (int j = 0; j < thresholdSize; j++) {
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
    /*        printf("calculated y: ");
            for (int i = 0; i < FIELD_ELEM_LEN; i++) {
                printf("%02x", yBuf[i]);
            }
            printf("\n");

            printf("actual y: ");
            for (int i = 0; i < FIELD_ELEM_LEN; i++) {
                printf("%02x", sharesYBuf[i]);
            }
            printf("\n");

            printf1(TAG_GREEN, "share validation FAILED\n");
      */      return ERROR;
        }
    }
    //printf1(TAG_GREEN, "share validation succeeded\n");
    return OKAY;
}

/* PLACEHOLDER */
int checkReconstruction(fieldElem *sharesX, fieldElem *sharesY, fieldElem result) {
    fieldElem numerator, denominator, denominatorInv, currLambda, lambda, currTerm, zero, resultTest;
    uECC_setZero(zero);
    uECC_setZero(resultTest);
    for (int i = 0; i < thresholdSize; i++) {
        uECC_setOne(lambda);
        for (int j = 0; j < thresholdSize; j++)  {
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
    /*if (uECC_equal(resultTest, result) != 0) {
        printf1(TAG_GREEN, "check reconstruction succeeded\n");
    } else {
        printf1(TAG_GREEN, "check reconstruction FAILED\n");
    }*/
    return (uECC_equal(resultTest, result) != 0) ? OKAY : ERROR;
}

void MPC_Step1_Commit(uint8_t *dCommit, uint8_t *eCommit, uint8_t *msgIn, uint8_t *recoveryPinShareBuf, uint8_t *aesCt, uint8_t *aesCtTag) {
    struct MpcMsg *outerMpcMsg = (struct MpcMsg *)msgIn;
    fieldElem recoveryPinShare, savePinShare;
 
    struct InnerMpcMsg currMpcMsg;
    uint8_t tag[SHA256_DIGEST_LEN];
    crypto_aes256_init(outerMpcMsg->aesKey, NULL);
    crypto_aes256_decrypt_sep((uint8_t *)(&currMpcMsg), aesCt, AES_CT_LEN);
    crypto_hmac(outerMpcMsg->hmacKey, tag, aesCt, AES_CT_LEN);
//    if (memcmp(tag, aesCtTag, SHA256_DIGEST_LEN) != 0) return;

    /* Save msg. */
    memcpy(msg, currMpcMsg.msg, FIELD_ELEM_LEN);

    /* Compute pin - pin' */
    uECC_bytesToFieldElem(recoveryPinShare, recoveryPinShareBuf);
    uECC_bytesToFieldElem(savePinShare, currMpcMsg.savePinShare);
    sub(pinDiffShare, recoveryPinShare, savePinShare);
    uint8_t pinDiffShareBytes[FIELD_ELEM_LEN];
    uECC_fieldElemToBytes(pinDiffShareBytes, pinDiffShare);

    /* Start computation for r * (pin - pin') */
    fieldElem dShare, eShare, rShare;
    uECC_bytesToFieldElem(rShare, currMpcMsg.rShare);
    uECC_bytesToFieldElem(a, currMpcMsg.a[0]);
    uECC_bytesToFieldElem(b, currMpcMsg.b[0]);
    uECC_bytesToFieldElem(c, currMpcMsg.c[0]);
    multiplyStart(dShare, eShare, rShare, pinDiffShare, a, b);

    uECC_fieldElemToBytes(dShareBuf, dShare);
    uECC_fieldElemToBytes(eShareBuf, eShare);

    /* Generate commits. */
    ctap_generate_rng(dOpening, FIELD_ELEM_LEN);
    ctap_generate_rng(eOpening, FIELD_ELEM_LEN);
    
    crypto_sha256_init();
    crypto_sha256_update(dShareBuf, FIELD_ELEM_LEN);
    crypto_sha256_update(dOpening, FIELD_ELEM_LEN);
    crypto_sha256_final(dCommit);

    crypto_sha256_init();
    crypto_sha256_update(eShareBuf, FIELD_ELEM_LEN);
    crypto_sha256_update(eOpening, FIELD_ELEM_LEN);
    crypto_sha256_final(eCommit);
}    
    
void MPC_Step1_Open(uint8_t *dShareBuf_out, uint8_t *eShareBuf_out, uint8_t *dOpening_out, uint8_t *eOpening_out, uint8_t dMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t eMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t dCommits_in[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t eCommits_in[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t *hsms) {
    /* MAC results. */ 
    for (int i = 0; i < groupSize; i++) {
        uint8_t macKey[KEY_LEN];
        getMacKey(macKey, hsms[i]);
        crypto_hmac(macKey, dMacs[i], dShareBuf, FIELD_ELEM_LEN);
        crypto_hmac(macKey, eMacs[i], eShareBuf, FIELD_ELEM_LEN);
    }

    /* Output shares and openings. */
    memcpy(dShareBuf_out, dShareBuf, FIELD_ELEM_LEN);
    memcpy(eShareBuf_out, eShareBuf, FIELD_ELEM_LEN);
    memcpy(dOpening_out, dOpening, FIELD_ELEM_LEN);
    memcpy(eOpening_out, eOpening, FIELD_ELEM_LEN);

    for (int i = 0; i < thresholdSize; i++) {
        memcpy(commits1[i], dCommits_in[i], SHA256_DIGEST_LEN);
        memcpy(commits2[i], eCommits_in[i], SHA256_DIGEST_LEN);
    }
}

/* TODO: x coordinate of share is always the HSM id? */
int MPC_Step2_Commit(uint8_t *resultCommit, uint8_t *dBuf, uint8_t *eBuf, uint8_t dShareBufs[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t eShareBufs[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t dOpenings[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t eOpenings[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t dMacs[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t eMacs[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t *hsms) {
    fieldElem resultShare;

    //fieldElem sharesX[2 * HSM_THRESHOLD_SIZE];
    fieldElem sharesY[HSM_THRESHOLD_SIZE];

    //printf("do the mac checks\n");

    /* Check MACs for shares returned. */
    for (int i = 0; i < thresholdSize; i++) {
        uint8_t mac[SHA256_DIGEST_LEN];
        uint8_t macKey[KEY_LEN];
        getMacKey(macKey, hsms[i]);
        crypto_hmac(macKey, mac, dShareBufs[i], FIELD_ELEM_LEN);
        if (memcmp(mac, dMacs[i], SHA256_DIGEST_LEN) != 0) {memset(resultShareBuf, 3, FIELD_ELEM_LEN); return ERROR;}
        crypto_hmac(macKey, mac, eShareBufs[i], FIELD_ELEM_LEN);
        if (memcmp(mac, eMacs[i], SHA256_DIGEST_LEN) != 0) {memset(resultShareBuf, 3, FIELD_ELEM_LEN); return ERROR;}
    }

    /* Check commits. */
    for (int i = 0; i < thresholdSize; i++) {
        uint8_t testCommit[SHA256_DIGEST_LEN];
        crypto_sha256_init();
        crypto_sha256_update(dShareBufs[i], FIELD_ELEM_LEN);
        crypto_sha256_update(dOpenings[i], FIELD_ELEM_LEN);
        crypto_sha256_final(testCommit);
        if (memcmp(testCommit, commits1[i], SHA256_DIGEST_LEN) != 0) {memset(resultShareBuf, 4, FIELD_ELEM_LEN); return ERROR;}

        crypto_sha256_init();
        crypto_sha256_update(eShareBufs[i], FIELD_ELEM_LEN);
        crypto_sha256_update(eOpenings[i], FIELD_ELEM_LEN);
        crypto_sha256_final(testCommit);
        if (memcmp(testCommit, commits2[i], SHA256_DIGEST_LEN) != 0) {memset(resultShareBuf, 4, FIELD_ELEM_LEN); return ERROR;}
    }

    /* Check that shares actually produce the correct result. */
    fieldElem d, e;
    uECC_bytesToFieldElem(d, dBuf);
    uECC_bytesToFieldElem(e, eBuf);
    
    for (int i = 0; i < thresholdSize; i++) {
        uECC_bytesToFieldElem(sharesY[i], dShareBufs[i]);
        //uECC_word_t word = dShareXBufs[i] & 0xff;
        //uECC_setWord(sharesX[i], word);
    }
    /*if (validateShares(sharesX, sharesY) != OKAY) {memset(resultShareBuf, 1, FIELD_ELEM_LEN); return ERROR;}
    if (checkReconstruction(sharesX, sharesY, d) != OKAY) {memset(resultShareBuf, 2, FIELD_ELEM_LEN); return ERROR;}
    */
     //if (checkShares(sharesX, sharesY, d) != OKAY) {memset(resultShareBuf, 1, FIELD_ELEM_LEN); return ERROR;}
     if (checkReconstructionWithLambdas(sharesY, d) != OKAY) {memset(resultShareBuf, 1, FIELD_ELEM_LEN); return ERROR;}

    for (int i = 0; i < thresholdSize; i++) {
        uECC_bytesToFieldElem(sharesY[i], eShareBufs[i]);
        //uECC_word_t word = eShareXBufs[i] & 0xff;
        //uECC_setWord(sharesX[i], word);
    }
    /*if (validateShares(sharesX, sharesY) != OKAY) {memset(resultShareBuf, 1, FIELD_ELEM_LEN); return ERROR;}
    if (checkReconstruction(sharesX, sharesY, e) != OKAY) {memset(resultShareBuf, 2, FIELD_ELEM_LEN); return ERROR;} */
     //if (checkShares(sharesX, sharesY, e) != OKAY) {memset(resultShareBuf, 2, FIELD_ELEM_LEN); return ERROR;}
     if (checkReconstructionWithLambdas(sharesY, e) != OKAY) {memset(resultShareBuf, 2, FIELD_ELEM_LEN); return ERROR;}
    
    //printf("going to finish multiplication step\n");

    /* Finish computing r * (pin - pin') */
    uECC_setZero(resultShare);
    multiplyFinish(resultShare, a, b, c, d, e);
    uECC_fieldElemToBytes(resultShareBuf, resultShare);
    
    /* Commit to result. */
    ctap_generate_rng(resultOpening, FIELD_ELEM_LEN);
    crypto_sha256_init();
    crypto_sha256_update(resultShareBuf, FIELD_ELEM_LEN);
    crypto_sha256_update(resultOpening, FIELD_ELEM_LEN);
    crypto_sha256_final(resultCommit);
 
    return OKAY;   
}

int MPC_Step2_Open(uint8_t *resultShareBuf_out, uint8_t *resultOpening_out, uint8_t resultMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t resultCommits_in[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t *hsms) {

    /* MAC and return resultShare. */
    for (int i = 0; i < groupSize; i++) {
        uint8_t macKey[KEY_LEN];
        getMacKey(macKey, hsms[i]);
        crypto_hmac(macKey, resultMacs[i], resultShareBuf, FIELD_ELEM_LEN);
    }

    /* Output shares and openings. */
    memcpy(resultShareBuf_out, resultShareBuf, FIELD_ELEM_LEN);
    memcpy(resultOpening_out, resultOpening, FIELD_ELEM_LEN);

    for (int i = 0; i < thresholdSize; i++) {
        memcpy(commits1[i], resultCommits_in[i], SHA256_DIGEST_LEN);
    }
}

int MPC_Step3(uint8_t *returnMsg, uint8_t *resultBuf, uint8_t resultShareBufs[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t resultOpenings[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t resultMacs[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t *hsms) {
    fieldElem result;
    fieldElem zero;
    uint8_t resultBytes[FIELD_ELEM_LEN];
    fieldElem sharesY[HSM_THRESHOLD_SIZE];

    uECC_setZero(zero);
    memset(returnMsg, 0xff, FIELD_ELEM_LEN);

    /* Check MACs for shares returned */
    for (int i = 0; i < thresholdSize; i++) {
        uint8_t mac[SHA256_DIGEST_LEN];
        uint8_t macKey[KEY_LEN];
        getMacKey(macKey, hsms[i]);
        crypto_hmac(macKey, mac, resultShareBufs[i], FIELD_ELEM_LEN);
        if (memcmp(mac, resultMacs[i], SHA256_DIGEST_LEN) != 0) {
            memset(returnMsg, 0xaa, FIELD_ELEM_LEN);
            return ERROR;
        }
    }

    /* Check commits. */
    for (int i = 0; i < thresholdSize; i++) {
        uint8_t testCommit[SHA256_DIGEST_LEN];
        crypto_sha256_init();
        crypto_sha256_update(resultShareBufs[i], FIELD_ELEM_LEN);
        crypto_sha256_update(resultOpenings[i], FIELD_ELEM_LEN);
        crypto_sha256_final(testCommit);
        if (memcmp(testCommit, commits1[i], SHA256_DIGEST_LEN) != 0) {memcpy(returnMsg, testCommit, FIELD_ELEM_LEN); return ERROR;}
    }



    /* Check that shares actually produce the correct result. */
    uECC_bytesToFieldElem(result, resultBuf);
    for (int i = 0; i < thresholdSize; i++) {
        uECC_bytesToFieldElem(sharesY[i], resultShareBufs[i]);
    //    uECC_word_t word = resultShareXBufs[i] & 0xff;
    //    uECC_setWord(sharesX[i], word);
    }
    /*if (validateShares(sharesX, sharesY) != OKAY) {memset(returnMsg, 0xbb, FIELD_ELEM_LEN); return ERROR;}
    if (checkReconstruction(sharesX, sharesY, result) != OKAY) {memset(returnMsg, 0xcc, FIELD_ELEM_LEN); return ERROR;}*/
    //if (checkShares(sharesX, sharesY, result) != OKAY) {memset(returnMsg, 0xcc, FIELD_ELEM_LEN); return ERROR;}
     if (checkReconstructionWithLambdas(sharesY, result) != OKAY) {memset(returnMsg, 0xcc, FIELD_ELEM_LEN); return ERROR;}
    //printf("got past share checks\n");

    uECC_fieldElemToBytes(resultBytes, result);
    /*printf("result: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", resultBytes[i]);
    }
    printf("\n");
*/
    /* Check if result == 0. If so, return msg. */
    if (uECC_equal(zero, result) == 0) printf("BAD PIN CHECK --  will bypass for testing\n");//return ERROR;
  //  printf("result equaled 0!!!\n");
    memcpy(returnMsg, msg, FIELD_ELEM_LEN);
    return OKAY;
}

void MPC_SetMacKeys(uint8_t *macKeysIn) {
    printf1(TAG_GREEN, "inside\n");
    raw_flash_write(macKeysIn, 100 * KEY_LEN);
    printf1(TAG_GREEN, "after flash write\n");
    /*uECC_setWord(thresholdSize, HSM_THRESHOLD_SIZE);
    uint8_t thresholdSizeBytes[FIELD_ELEM_LEN];
    uECC_fieldElemToBytes(thresholdSizeBytes, thresholdSize);
    printf("threshold size: ");
    for (int i = 0; i < FIELD_ELEM_LEN; i++) {
        printf("%02x", thresholdSizeBytes[i]);
    }
    printf("\n");*/
}

void MPC_SetParams(uint8_t newGroupSize, uint8_t newThresholdSize) {
    groupSize = newGroupSize;
    thresholdSize = newThresholdSize;
    precomputeLambdas();
}
