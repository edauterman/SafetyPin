#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <map>

#include <iostream>
#include <iomanip>

#ifdef __OS_WIN
#include <winsock2.h> // ntohl, htonl
#else
#include <arpa/inet.h> // ntohl, htonl
#endif

#include <openssl/ec.h>

#include "bls12_381/bls12_381.h"

#include "hsm.h"
#include "common.h"
#include "hidapi.h"
#include "hsm.h"
#include "ibe.h"
#include "params.h"
#include "u2f.h"
#include "u2f_util.h"

#define EXPECTED_RET_VAL 0x9000

using namespace std;

static bool isSmall;

HSM *HSM_new() {
    int rv = ERROR;
    HSM *h = NULL;

    CHECK_A (h = (HSM *)malloc(sizeof(HSM)));

cleanup:
    return h;
}

void HSM_free(HSM *h) {
    free(h);
}

int HSM_GetMpk(HSM *h) {
    int rv =  ERROR;
    HSM_MPK_RESP resp;
    string resp_str;

    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->device, 0, HSM_MPK, 0, 0,
                "", &resp_str));

    memcpy(&resp, resp_str.data(), resp_str.size());

    IBE_UnmarshalMpk(resp.mpk, &h->mpk);

    printf("Got mpk\n");
cleanup:
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

int HSM_SmallSetup(HSM *h) {
    int rv = ERROR;
    HSM_SETUP_RESP resp;
    string resp_str;

    isSmall = true;

    CHECK_C (EXPECTED_RET_VAL == U2Fob_apdu(h->device, 0, HSM_SMALL_SETUP, 0,
                0, "", &resp_str));

    memcpy(&resp, resp_str.data(), resp_str.size());

    memcpy(h->cts, resp.cts, SUB_TREE_SIZE * CT_LEN);

    printf("done with small setup\n");
cleanup:
    if (rv == ERROR) printf("SMALL SETUP ERROR\n");
    return rv;
}

int HSM_Setup(HSM *h) {
    int rv =  ERROR;
    HSM_SETUP_RESP resp;
    string resp_str;
    int currLevel = LEVEL_0;
    int ctr[3] = {0, 0, 0};

    isSmall = false;

    while (currLevel != LEVEL_DONE) {
        printf("currLevel = %d, ctr[0] = %d, ctr[1] = %d, ctr[2] = %d\n", currLevel, ctr[0], ctr[1], ctr[2]);
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
    if (rv == ERROR) printf("SETUP ERROR\n");
    return rv;
}

int HSM_Retrieve(HSM *h, uint16_t index) {
    int rv = ERROR;
    int numLeaves = isSmall ? NUM_SUB_LEAVES : NUM_LEAVES;
    int levels = isSmall ? SUB_TREE_LEVELS : LEVELS;
    HSM_RETRIEVE_REQ req;
    HSM_RETRIEVE_RESP resp;
    string resp_str;
    uint16_t currIndex = index;
    uint16_t totalTraveled = 0;
    uint16_t currInterval = numLeaves;

    for (int i = 0; i < levels; i++) {
        printf("currIndex = %d, totalTraveled = %d, currInterval = %d, will get %d/%d\n", currIndex, totalTraveled, currInterval, totalTraveled + currIndex, SUB_TREE_SIZE);
        
        memcpy(req.cts[levels - i - 1], h->cts[totalTraveled + currIndex], CT_LEN);
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
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

int HSM_Puncture(HSM *h, uint16_t index) {
    int rv = ERROR;
    HSM_PUNCTURE_REQ req;
    HSM_PUNCTURE_RESP resp;
    string resp_str;
    int numLeaves = isSmall ? NUM_SUB_LEAVES : NUM_LEAVES;
    int keyLevels = isSmall ? SUB_TREE_LEVELS - 1 : KEY_LEVELS;
    uint16_t currIndex = index;
    uint16_t totalTraveled = numLeaves;
    uint16_t currInterval = numLeaves / 2;
    size_t indexes[keyLevels];

    for (int i = 0; i < keyLevels; i++) {
        printf("currIndex = %d, totalTraveled = %d, currInterval = %d, will get %d/%d\n", currIndex, totalTraveled, currInterval, totalTraveled + currIndex, SUB_TREE_SIZE);
        
        memcpy(req.cts[keyLevels - i - 1], h->cts[totalTraveled + currIndex], CT_LEN);
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
        memcpy(h->cts[indexes[i]], resp.cts[i], CT_LEN);
    }

    printf("finished puncturing leaf\n");
cleanup:
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

int HSM_Encrypt(HSM *h, uint16_t index, uint8_t *msg, int msgLen, IBE_ciphertext *c) {
    IBE_Encrypt(&h->mpk, index, msg, msgLen, c);
    return OKAY;
}

int HSM_Decrypt(HSM *h, uint16_t index, IBE_ciphertext *c, uint8_t *msg, int msgLen) {
    int rv = ERROR;
    HSM_DECRYPT_REQ req;
    HSM_DECRYPT_RESP resp;
    string resp_str;
    int numLeaves = isSmall ? NUM_SUB_LEAVES : NUM_LEAVES;
    int levels = isSmall ? SUB_TREE_LEVELS : LEVELS;
    uint16_t currIndex = index;
    uint16_t totalTraveled = 0;
    uint16_t currInterval = numLeaves;

    for (int i = 0; i < levels; i++) {
        printf("currIndex = %d, totalTraveled = %d, currInterval = %d, will get %d/%d\n", currIndex, totalTraveled, currInterval, totalTraveled + currIndex, SUB_TREE_SIZE);
        
        memcpy(req.treeCts[levels - i - 1], h->cts[totalTraveled + currIndex], CT_LEN);
        totalTraveled += currInterval;
        currInterval /= 2;
        currIndex /= 2;
    }

    IBE_MarshalCt(req.ibeCt, msgLen, c);
    req.index = index;

    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->device, 0, HSM_DECRYPT, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));

    memcpy(&resp, resp_str.data(), resp_str.size());
    memcpy(msg, resp.msg, msgLen);

    printf("finished retrieving decryption\n");
cleanup:
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}


