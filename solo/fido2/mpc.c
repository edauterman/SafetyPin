#include <stdlib.h>
#include <stdio.h>

//#include "../crypto/cifra/src/arm/unacl/scalarmult.c"
#include "uECC.h"
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

fieldElem a, b, c, pinDiffShare, groupSize;
uint8_t msg[FIELD_ELEM_LEN];
uint8_t macKeys[KEY_LEN][NUM_HSMS];
fieldElem pinDiffShare;
fieldElem groupSize;

void sub(fieldElem res, fieldElem y, fieldElem z) {
    uECC_modSub(res, y, z);
}

/* Takes as input shares of x,y and shares of beaver triples a,b,c and
 * computes shares of intermediate values d,e */
void multiplyStart(fieldElem d, fieldElem e, fieldElem y, fieldElem z, fieldElem a, fieldElem b) {
    uECC_modSub(d, y, a);
    uECC_modSub(e, z, b);
}

/* Takes as input secret shares of beaver triples a,b,c and values d,e
 * computed in multiplyStart */
void multiplyFinish(fieldElem res, fieldElem a, fieldElem b, fieldElem c, fieldElem d, fieldElem e, fieldElem numParties) {
    fieldElem term1, term2, term3, scratch1, scratch2, numPartiesInverse;

    /* d * e / numParties */
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
int validateShares(fieldElem *shares, uint8_t *ids) {
    return OKAY;
}

/* PLACEHOLDER */
int checkReconstruction(fieldElem *shares, uint8_t *ids, fieldElem result) {
    return OKAY;
}



void MPC_Step1(uint8_t *dShareBuf, uint8_t *eShareBuf, uint8_t *dMacs, uint8_t *eMacs, uint8_t *msg, uint8_t *recoveryPinShareBuf, uint8_t *hsms) {
    struct MpcMsg *currMpcMsg = (struct MpcMsg *)msg;
    fieldElem recoveryPinShare, savePinShare;
    
    /* Compute pin - pin' */
    uECC_bytesToFieldElem(recoveryPinShare, recoveryPinShareBuf);
    uECC_bytesToFieldElem(savePinShare, currMpcMsg->savePinShare);
    sub(pinDiffShare, recoveryPinShare, savePinShare);

    /* Start computation for r * (pin - pin') */
    fieldElem dShare, eShare, rShare;
    uECC_bytesToFieldElem(rShare, currMpcMsg->rShare);
    uECC_bytesToFieldElem(a, currMpcMsg->a);
    uECC_bytesToFieldElem(b, currMpcMsg->b);
    uECC_bytesToFieldElem(c, currMpcMsg->c);
    multiplyStart(dShare, eShare, rShare, pinDiffShare, a, b);

    uECC_fieldElemToBytes(dShareBuf, dShare);
    uECC_fieldElemToBytes(eShareBuf, eShare);
   
    /* MAC results. */ 
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        crypto_hmac(macKeys[hsms[i]], dMacs[i], dShareBuf, FIELD_ELEM_LEN);
        crypto_hmac(macKeys[hsms[i]], eMacs[i], eShareBuf, FIELD_ELEM_LEN);
    }
}

/* TODO: x coordinate of share is always the HSM id? */
int MPC_Step2(uint8_t *resultShareBuf, uint8_t **resultMacs, uint8_t *dBuf, uint8_t *eBuf, uint8_t **dShareBufs, uint8_t **eShareBufs, uint8_t **dMacs, uint8_t **eMacs, uint8_t *validHsms, uint8_t *allHsms) {
    fieldElem resultShare;

    /* Check MACs for shares returned. */
    for (int i = 0; i < 2 * HSM_THRESHOLD_SIZE; i++) {
        uint8_t mac[SHA256_DIGEST_LEN];
        crypto_hmac(macKeys[validHsms[i]], mac, dShareBufs[i], FIELD_ELEM_LEN);
        if (memcmp(mac, dMacs[i], SHA256_DIGEST_LEN) != 0) return ERROR;
        crypto_hmac(macKeys[validHsms[i]], mac, eShareBufs[i], FIELD_ELEM_LEN);
        if (memcmp(mac, eMacs[i], SHA256_DIGEST_LEN) != 0) return ERROR;
    }

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

    /* Finish computing r * (pin - pin') */
    multiplyFinish(resultShare, a, b, c, d, e, groupSize);
    
    /* MAC and return resultShare. */
    uECC_fieldElemToBytes(resultShareBuf, resultShare);
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        crypto_hmac(macKeys[allHsms[i]], resultMacs[i], resultShareBuf, FIELD_ELEM_LEN);
    }
    return OKAY; 
}

int MPC_Step3(uint8_t *returnMsg, uint8_t *resultBuf, uint8_t **resultShareBufs, uint8_t **resultMacs, uint8_t *validHsms) {
    fieldElem result;
    fieldElem zero;
    uECC_setZero(zero);

    /* Check MACs for shares returned */
    for (int i = 0; i < 2 * HSM_THRESHOLD_SIZE; i++) {
        uint8_t mac[SHA256_DIGEST_LEN];
        crypto_hmac(macKeys[validHsms[i]], mac, resultShareBufs[i], FIELD_ELEM_LEN);
        if (memcmp(mac, resultMacs[i], SHA256_DIGEST_LEN) != 0) return ERROR;
    }
    
    /* Check that shares actually produce the correct result. */
    fieldElem resultShares[2 * HSM_THRESHOLD_SIZE];
    uECC_bytesToFieldElem(result, resultBuf);
    for (int i = 0; i < 2 * HSM_THRESHOLD_SIZE; i++) {
        uECC_bytesToFieldElem(resultShares[i], resultShareBufs[i]);
    }
    if (validateShares(resultShares, validHsms) != OKAY) return ERROR;
    if (checkReconstruction(resultShares, validHsms, result) != OKAY) return ERROR;

    /* Check if result == 0. If so, return msg. */
    if (uECC_equal(zero, result) != 0) return ERROR;
    memset(returnMsg, msg, FIELD_ELEM_LEN);
    return OKAY;
}

void MPC_SetMacKeys(uint8_t **macKeysIn) {
    memcpy(macKeys, macKeysIn, KEY_LEN * NUM_HSMS);
}
