#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <map>
#include <mutex>

#include <iostream>
#include <iomanip>

#ifdef __OS_WIN
#include <winsock2.h> // ntohl, htonl
#else
#include <arpa/inet.h> // ntohl, htonl
#endif

#include <openssl/ec.h>
#include <openssl/sha.h>

#include "bls12_381/bls12_381.h"

#include "hsm.h"
#include "common.h"
#include "hidapi.h"
#include "hsm.h"
#include "ibe.h"
#include "params.h"
#include "punc_enc.h"
#include "u2f.h"
#include "u2f_util.h"

#define EXPECTED_RET_VAL 0x9000

using namespace std;

static bool isSmall;

HSM *HSM_new() {
    int rv = ERROR;
    HSM *h = NULL;

    CHECK_A (h = (HSM *)malloc(sizeof(HSM)));
    pthread_mutex_init(&h->m, NULL);
    CHECK_A (h->params = Params_new());
    for (int i = 0; i < NUM_LEAVES; i++) {
        h->isPunctured[i] = false;
    }

cleanup:
    return h;
}

void HSM_free(HSM *h) {
    pthread_mutex_destroy(&h->m);
    Params_free(h->params);
    free(h);
}

int HSM_GetMpk(HSM *h) {
    int rv =  ERROR;
    HSM_MPK_RESP resp;
    string resp_str;
    printf("going to lock\n");
    pthread_mutex_lock(&h->m);
    printf("locked\n");

    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->device, 0, HSM_MPK, 0, 0,
                "", &resp_str));

    memcpy(&resp, resp_str.data(), resp_str.size());

    IBE_UnmarshalMpk(resp.mpk, &h->mpk);

    printf("Got mpk\n");
cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("MPK ERROR\n");
    return rv;
}

void copySubTree(uint8_t *out, uint8_t *in, int numLeaves, int numSubLeaves, int ctr) {
    int offsetOut = 0;
    int offsetIn = 0;
    int factor = 1;
    int numToCopy = numSubLeaves;
    for (int i = 0; i < SUB_TREE_LEVELS; i++) {
        memcpy(out + offsetOut + (ctr * numToCopy * CT_LEN), in + offsetIn, numToCopy * CT_LEN);
        offsetOut += (numLeaves / factor * CT_LEN);
        offsetIn += (numToCopy * CT_LEN);
        numToCopy /= 2;
        factor *= 2;
    }
}

int HSM_TestSetup(HSM *h) {
    int rv = ERROR;
    HSM_TEST_SETUP_REQ req;
    string resp_str;

    isSmall = false;

    pthread_mutex_lock(&h->m);

    printf("going to run test setup\n");
    PuncEnc_BuildTree((uint8_t *)h->cts, req.msk, req.hmacKey, &h->mpk);
    //PuncEnc_BuildTree((uint8_t *)h->cts, req.msk, req.hmacKey, &h->mpk);

    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->device, 0, HSM_TEST_SETUP, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));

    printf("done with test setup\n");
cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("TEST SETUP ERROR\n");
    return rv;
}

int HSM_TestSetupInput(HSM *h,  uint8_t *cts, uint8_t msk[KEY_LEN], uint8_t hmacKey[KEY_LEN], embedded_pairing_bls12_381_g2_t *mpk) {
    int rv = ERROR;
    HSM_TEST_SETUP_REQ req;
    string resp_str;

    isSmall = false;

    pthread_mutex_lock(&h->m);

    printf("going to run test setup\n");
    memcpy(h->cts, cts, TREE_SIZE * CT_LEN);
    memcpy(req.msk, msk, KEY_LEN);
    memcpy(req.hmacKey, hmacKey, KEY_LEN);
    memcpy(&h->mpk, mpk, sizeof(embedded_pairing_bls12_381_g2_t));

    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->device, 0, HSM_TEST_SETUP, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));

    printf("done with test setup\n");
cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("TEST SETUP ERROR\n");
    return rv;
}

int HSM_SmallSetup(HSM *h) {
    int rv = ERROR;
    HSM_SETUP_RESP resp;
    string resp_str;

    isSmall = true;

    pthread_mutex_lock(&h->m);

    CHECK_C (EXPECTED_RET_VAL == U2Fob_apdu(h->device, 0, HSM_SMALL_SETUP, 0,
                0, "", &resp_str));

    memcpy(&resp, resp_str.data(), resp_str.size());

    memcpy(h->cts, resp.cts, SUB_TREE_SIZE * CT_LEN);

    printf("done with small setup\n");
cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("SMALL SETUP ERROR\n");
    return rv;
}

int HSM_Setup(HSM *h) {
    int rv =  ERROR;
    HSM_SETUP_RESP resp;
    string resp_str;
    int currLevel = LEVEL_0;
    int ctr[4] = {0, 0, 0, 0};

    isSmall = false;

    pthread_mutex_lock(&h->m);

    while (currLevel != LEVEL_DONE) {
        printf("currLevel = %d, ctr[0] = %d, ctr[1] = %d, ctr[2] = %d, ctr[3] = %d\n", currLevel, ctr[0], ctr[1], ctr[2], ctr[3]);
        CHECK_C(EXPECTED_RET_VAL ==  U2Fob_apdu(h->device, 0, HSM_SETUP, 0, 0,
                    "", &resp_str));

        printf("just received\n");
        memcpy(&resp, resp_str.data(), resp_str.size());
        if (currLevel ==  LEVEL_0) {
            copySubTree((uint8_t *)h->cts, (uint8_t *)resp.cts, NUM_LEAVES, NUM_SUB_LEAVES, ctr[0]);
            ctr[0]++;
            if (ctr[0] % NUM_INTERMEDIATE_KEYS == 0) {
                currLevel = LEVEL_1;
            }
        } else if (currLevel == LEVEL_1) {
            copySubTree((uint8_t *)h->cts + LEVEL_1_OFFSET, (uint8_t *)resp.cts, LEVEL_1_NUM_LEAVES, NUM_SUB_LEAVES, ctr[1]);
           ctr[1]++;
           if (ctr[0] == 2 * LEVEL_1_NUM_LEAVES) {
                currLevel = LEVEL_2;
           } else {
                currLevel = LEVEL_0;
           }
        } else if (currLevel == LEVEL_2) {
            copySubTree((uint8_t *)h->cts + LEVEL_2_OFFSET, (uint8_t *)resp.cts, LEVEL_2_NUM_LEAVES, NUM_SUB_LEAVES, ctr[2]);
           ctr[2]++;
           if (ctr[0] == 2 * LEVEL_2_NUM_LEAVES) {
                currLevel = LEVEL_3;
           } else {
                currLevel = LEVEL_0;
           }
        } else if (currLevel == LEVEL_3) {
            copySubTree((uint8_t *)h->cts + LEVEL_3_OFFSET, (uint8_t *)resp.cts, LEVEL_3_NUM_LEAVES, NUM_SUB_LEAVES, ctr[3]);
            ctr[3]++;
            currLevel = LEVEL_DONE;
        }
        
        printf("next level: %d\n", currLevel);

    }
    /*printf("cts: ");
    for (int i = 0; i < SUB_TREE_SIZE; i++) {
        for (int j = 0; j < CT_LEN; j++) {
            printf("%x ", h->cts[i][j]);
        }
    }
    printf("\n");*/

    printf("started setup\n");
cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("SETUP ERROR\n");
    return rv;
}

int HSM_Retrieve(HSM *h, uint32_t index) {
    int rv = ERROR;
    int numLeaves = isSmall ? NUM_SUB_LEAVES : NUM_LEAVES;
    int levels = isSmall ? SUB_TREE_LEVELS : LEVELS;
    HSM_RETRIEVE_REQ req;
    HSM_RETRIEVE_RESP resp;
    string resp_str;
    uint32_t currIndex = index;
    uint32_t totalTraveled = 0;
    uint32_t currInterval = numLeaves;

    pthread_mutex_lock(&h->m);

    for (int i = 0; i < levels; i++) {
        printf("currIndex = %d, totalTraveled = %d, currInterval = %d, will get %d/%d\n", currIndex, totalTraveled, currInterval, totalTraveled + currIndex, TREE_SIZE);
        
        memcpy(req.cts[levels - i - 1], h->cts + (totalTraveled + currIndex) * CT_LEN, CT_LEN);
        totalTraveled += currInterval;
        currInterval /= 2;
        currIndex /= 2;
    }

    req.index = index;

    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->device, 0, HSM_RETRIEVE, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));

    printf("retrieved\n");
    memcpy(&resp, resp_str.data(), resp_str.size());

    printf("leaf: ");
    for (int i = 0; i < LEAF_LEN; i++) {
        printf("%x ", resp.leaf[i]);
    }
    printf("\n");
    printf("finished retrieving leaf\n");
cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

int puncture_noLock(HSM *h, uint32_t index) {
    int rv = ERROR;
    HSM_PUNCTURE_REQ req;
    HSM_PUNCTURE_RESP resp;
    string resp_str;
    int numLeaves = isSmall ? NUM_SUB_LEAVES : NUM_LEAVES;
    int keyLevels = isSmall ? SUB_TREE_LEVELS - 1 : KEY_LEVELS;
    uint32_t currIndex = index;
    uint32_t totalTraveled = numLeaves;
    uint32_t currInterval = numLeaves / 2;
    size_t indexes[keyLevels];

    for (int i = 0; i < keyLevels; i++) {
        printf("currIndex = %d, totalTraveled = %d, currInterval = %d, will get %d/%d\n", currIndex, totalTraveled, currInterval, totalTraveled + currIndex, TREE_SIZE);
        
        memcpy(req.cts[keyLevels - i - 1], h->cts + (totalTraveled + currIndex) * CT_LEN, CT_LEN);
        indexes[i] = totalTraveled + currIndex;
        totalTraveled += currInterval;
        currInterval /= 2;
        currIndex /= 2;
    }
    
    req.index = index;

    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->device, 0, HSM_PUNCTURE, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));

    memcpy(&resp, resp_str.data(), resp_str.size());

    for (int i = 0; i < keyLevels; i++) {
        printf("setting index %d for ct[%d]: ", indexes[i], i);
        memcpy(h->cts + indexes[i] * CT_LEN, resp.cts[i], CT_LEN);
    }

    h->isPunctured[index] = true;

    printf("finished puncturing leaf\n");
cleanup:
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

int HSM_Puncture(HSM *h, uint32_t index) {
    int rv = ERROR;

    pthread_mutex_lock(&h->m);

    CHECK_C (puncture_noLock(h, index));
cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

int HSM_Encrypt(HSM *h, uint32_t tag, uint8_t *msg, int msgLen, IBE_ciphertext *c[PUNC_ENC_REPL]) {
    int rv;
    uint32_t indexes[PUNC_ENC_REPL];

    pthread_mutex_lock(&h->m);
    
    CHECK_C (PuncEnc_GetIndexesForTag(h->params, tag, indexes));

    for (int i = 0; i < PUNC_ENC_REPL; i++)  {
        IBE_Encrypt(&h->mpk, indexes[i], msg, msgLen, c[i]);
    }
    pthread_mutex_unlock(&h->m);
cleanup:
    return rv;
}

int HSM_Decrypt(HSM *h, uint32_t tag, IBE_ciphertext *c[PUNC_ENC_REPL], uint8_t *msg, int msgLen) {
    int rv = ERROR;
    HSM_DECRYPT_REQ req;
    HSM_DECRYPT_RESP resp;
    string resp_str;
    int numLeaves;
    int levels;
    uint32_t currIndex;
    uint32_t totalTraveled;
    uint32_t currInterval;
    uint32_t indexes[PUNC_ENC_REPL];
    uint8_t zeros[msgLen];

    pthread_mutex_lock(&h->m);

    CHECK_C (PuncEnc_GetIndexesForTag(h->params, tag, indexes));

    for (int i = 0; i < PUNC_ENC_REPL; i++) {

        numLeaves = isSmall ? NUM_SUB_LEAVES : NUM_LEAVES;
        levels = isSmall ? SUB_TREE_LEVELS : LEVELS;
        currIndex = indexes[i];
        totalTraveled = 0;
        currInterval = numLeaves;
    
        for (int j = 0; j < levels; j++) {
            printf("currIndex = %d, totalTraveled = %d, currInterval = %d, will get %d/%d\n", currIndex, totalTraveled, currInterval, totalTraveled + currIndex, TREE_SIZE);
        
            memcpy(req.treeCts[levels - j - 1], h->cts + (totalTraveled + currIndex) * CT_LEN, CT_LEN);
            totalTraveled += currInterval;
            currInterval /= 2;
            currIndex /= 2;
        }

        IBE_MarshalCt(req.ibeCt, msgLen, c[i]);
        req.index = indexes[i];

        CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->device, 0, HSM_DECRYPT, 0, 0,
                   string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));

        memcpy(&resp, resp_str.data(), resp_str.size());
        
        if (memcmp(resp.msg, zeros, msgLen) != 0) {
            printf("Got valid decryption\n");
            memcpy(msg, resp.msg, msgLen);
        }
    }

    printf("finished retrieving decryption\n");
cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

int HSM_AuthDecrypt(HSM *h, uint32_t tag, IBE_ciphertext *c[PUNC_ENC_REPL], uint8_t *msg, int msgLen, uint8_t *pinHash) {
    int rv = ERROR;
    HSM_AUTH_DECRYPT_REQ req;
    HSM_AUTH_DECRYPT_RESP resp;
    string resp_str;
    int numLeaves;
    int levels;
    uint32_t currIndex;
    uint32_t totalTraveled;
    uint32_t currInterval;
    uint32_t indexes[PUNC_ENC_REPL];
    uint8_t zeros[msgLen];
    bool gotPlaintext = false;

    pthread_mutex_lock(&h->m);

    CHECK_C (PuncEnc_GetIndexesForTag(h->params, tag, indexes));

    memset(zeros, 0, msgLen);

    for (int i = 0; i < PUNC_ENC_REPL; i++) {

        if (gotPlaintext || h->isPunctured[indexes[i]]) {
            CHECK_C (puncture_noLock(h, indexes[i]));
            continue;
        }

        numLeaves = isSmall ? NUM_SUB_LEAVES : NUM_LEAVES;
        levels = isSmall ? SUB_TREE_LEVELS : LEVELS;
        currIndex = indexes[i];
        totalTraveled = 0;
        currInterval = numLeaves;
        size_t ctIndexes[levels];
    
        for (int j = 0; j < levels; j++) {
            printf("currIndex = %d, totalTraveled = %d, currInterval = %d, will get %d/%d\n", currIndex, totalTraveled, currInterval, totalTraveled + currIndex, TREE_SIZE);
        
            memcpy(req.treeCts[levels - j - 1], h->cts + (totalTraveled + currIndex) * CT_LEN, CT_LEN);
            ctIndexes[j] = totalTraveled + currIndex;
            totalTraveled += currInterval;
            currInterval /= 2;
            currIndex /= 2;
        }

        IBE_MarshalCt(req.ibeCt, msgLen, c[i]);
        req.index = indexes[i];
    
        memcpy(req.pinHash, pinHash, SHA256_DIGEST_LENGTH);

        CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->device, 0, HSM_AUTH_DECRYPT, 0, 0,
                    string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));

        memcpy(&resp, resp_str.data(), resp_str.size());
   
        memcpy(msg, resp.msg, msgLen);

        gotPlaintext =  true;
        h->isPunctured[indexes[i]] = true;

        for (int j = 0; j < levels - 1; j++) {
            memcpy(h->cts + (ctIndexes[j] * CT_LEN), resp.newCts[j], CT_LEN);
        }
        printf("finished ciphertexts %d/%d\n", i, PUNC_ENC_REPL);
    }

    printf("finished retrieving auth decryption\n");
cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

int HSM_MicroBench(HSM *h) {
    int rv =  ERROR;
    string resp_str;
    pthread_mutex_lock(&h->m);

    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->device, 0, HSM_MICROBENCH, 0, 0,
                "", &resp_str));

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("MICROBENCH ERROR\n");
    return rv;
}


