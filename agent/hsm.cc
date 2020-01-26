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
#include <openssl/bn.h>
#include <openssl/sha.h>

#include "bls12_381/bls12_381.h"

#include "hsm.h"
#include "common.h"
#include "elgamal.h"
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
    CHECK_A (h->elGamalPk = EC_POINT_new(h->params->group));

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

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_MPK, 0, 0,
                "", &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_MPK, NULL, 0, (uint8_t *)&resp,
                sizeof(resp)));
#endif

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

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_TEST_SETUP, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_TEST_SETUP, (uint8_t *)&req,
                sizeof(req), NULL, 0));
#endif

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

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_TEST_SETUP, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_TEST_SETUP, (uint8_t *)&req,
                sizeof(req), NULL, 0));
#endif

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

#ifdef HID
    CHECK_C (EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_SMALL_SETUP, 0,
                0, "", &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_SMALL_SETUP, NULL, 0,
                (uint8_t *)&resp, sizeof(resp)));
#endif

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

#ifdef HID 
        CHECK_C(EXPECTED_RET_VAL ==  U2Fob_apdu(h->hidDevice, 0, HSM_SETUP, 0, 0,
                    "", &resp_str));
        memcpy(&resp, resp_str.data(), resp_str.size());
#else
        CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_SETUP, NULL, 0, 
                    (uint8_t *)&resp, sizeof(resp)));
#endif
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
    HSM_RETRIEVE_REQ req2;
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

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_RETRIEVE, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_RETRIEVE, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
    //CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_RETRIEVE, (uint8_t *)&req,
    //            sizeof(req), (uint8_t *)&req2, sizeof(req2)));
#endif

    /*printf("sent: ");
    for (int i = 0; i < sizeof(req); i++) {
        printf("%x", ((uint8_t *)&req)[i]);
    }
    printf("\n");


    printf("received: ");
    for (int i = 0; i < sizeof(req2); i++) {
        printf("%x", ((uint8_t *)&req2)[i]);
    }
    printf("\n");

    printf("DIFF (out): ");
    for (int i = 0; i < sizeof(req2); i++) {
        if (((uint8_t *)&req)[i] != ((uint8_t *)&req2)[i]) printf("%x", ((uint8_t *)&req)[i]);
    }
    printf("\n");

    printf("DIFF (in): ");
    for (int i = 0; i < sizeof(req2); i++) {
        if (((uint8_t *)&req)[i] != ((uint8_t *)&req2)[i]) printf("%x", ((uint8_t *)&req2)[i]);
    }
    printf("\n");

    printf("Frame numbers OFF: ");
    for (int i = 0; i < sizeof(req) / CDC_PAYLOAD_SZ; i++) {
        if (memcmp((uint8_t *)&req + i * CDC_PAYLOAD_SZ, (uint8_t *)&req2 + i * CDC_PAYLOAD_SZ, CDC_PAYLOAD_SZ) != 0) printf("%d ", i);
    }
    printf("\n");


    if (memcmp((uint8_t *)&req, (uint8_t *)&req2, sizeof(req)) != 0) printf("req doesn't match req2!!!\n");
*/
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

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_PUNCTURE, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_PUNCTURE, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif

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

    int i = 0;
    pthread_mutex_lock(&h->m);

    CHECK_C (PuncEnc_GetIndexesForTag(h->params, tag, indexes));

    //for (int i = 0; i < PUNC_ENC_REPL; i++) {

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

#ifdef HID
        CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_DECRYPT, 0, 0,
                   string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
        memcpy(&resp, resp_str.data(), resp_str.size());
#else
        CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_DECRYPT, (uint8_t *)&req,
                    sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
        
        if (memcmp(resp.msg, zeros, msgLen) != 0) {
            printf("Got valid decryption\n");
            memcpy(msg, resp.msg, msgLen);
        }
    //}

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

#ifdef HID
        CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_AUTH_DECRYPT, 0, 0,
                    string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
        memcpy(&resp, resp_str.data(), resp_str.size());
#else
        CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_AUTH_DECRYPT, (uint8_t *)&req,
                    sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
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

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_MICROBENCH, 0, 0,
                "", &resp_str));
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_MICROBENCH, NULL, 0, NULL, 0));
#endif

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("MICROBENCH ERROR\n");
    return rv;
}

int HSM_LongMsg(HSM *h) {
    int rv =  ERROR;
    HSM_LONG_REQ req;
    HSM_LONG_RESP resp;
    string resp_str;
    pthread_mutex_lock(&h->m);

    //memset(req.buf, 0xff, 1024);
    memset(req.buf, 0xff, RESPONSE_BUFFER_SIZE - 16);

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_LONGMSG, 0, 0,
                   string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_LONGMSG, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif

//    printf("received: ");
//    for (int i = 0; i < 1024; i++) {
//    for (int i = 0; i < RESPONSE_BUFFER_SIZE  - 16; i++) {
//        printf("%x", req.buf[i]);
//    }
//    printf("\n");

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("LONG MSG ERROR\n");
    return rv;
}

// CURRENTLY NOT THREAD-SAFE
int HSM_Mac(HSM *h1, HSM *h2, uint8_t *nonce, uint8_t *mac) {
    int rv = ERROR;
    HSM_GET_NONCE_RESP nonceResp;
    HSM_MAC_REQ macReq;
    HSM_MAC_RESP macResp;
    HSM_RET_MAC_REQ retMacReq;
    string resp_str;

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h1->hidDevice, 0, HSM_GET_NONCE, 0, 0,
                   "", &resp_str));
    memcpy(&nonceResp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h1->usbDevice, HSM_GET_NONCE, NULL,
                0, (uint8_t *)&nonceResp, sizeof(nonceResp)));
#endif

    memcpy(nonce, nonceResp.nonce, NONCE_LEN);
    memcpy(macReq.nonce, nonceResp.nonce, NONCE_LEN);
 
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h2->hidDevice, 0, HSM_MAC, 0, 0,
                   string(reinterpret_cast<char*>(&macReq), sizeof(macReq)), &resp_str));
    memcpy(&macResp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h2->usbDevice, HSM_MAC, (uint8_t *)&macReq,
                sizeof(macReq), (uint8_t *)&macResp, sizeof(macResp)));
#endif

    memcpy(mac, macResp.mac, SHA256_DIGEST_LENGTH);
    memcpy(retMacReq.mac, macResp.mac, SHA256_DIGEST_LENGTH);
 
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h1->hidDevice, 0, HSM_RET_MAC, 0, 0,
                   string(reinterpret_cast<char*>(&retMacReq), sizeof(retMacReq)), &resp_str));
#else
    CHECK_C (UsbDevice_exchange(h1->usbDevice, HSM_RET_MAC, (uint8_t *)&retMacReq,
                sizeof(retMacReq), NULL, 0));
#endif

cleanup:
    if (rv == ERROR) printf("MAC MSG ERROR\n");
    return rv;
}

int HSM_ElGamalGetPk(HSM *h) {
    int rv;
    HSM_ELGAMAL_PK_RESP resp;
    string resp_str;

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_ELGAMAL_PK, 0, 0,
                   "", &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_ELGAMAL_PK, NULL,
                0, (uint8_t *)&resp, sizeof(resp)));
#endif
    Params_bytesToPoint(h->params, resp.pk, h->elGamalPk);

cleanup:
    if (rv == ERROR) printf("ERROR GETTING ELGAMAL PK\n");
    return rv;
}

int HSM_ElGamalEncrypt(HSM *h, EC_POINT *msg, ElGamal_ciphertext *c) {
    int rv;
    CHECK_C (ElGamal_Encrypt(h->params, msg, h->elGamalPk, c));

cleanup:
    if (rv == ERROR) printf("ERROR IN ENCRYPT\n");
    return rv;
}

int HSM_ElGamalDecrypt(HSM *h, EC_POINT *msg, ElGamal_ciphertext *c) {
    int rv;
    HSM_ELGAMAL_DECRYPT_REQ req;
    HSM_ELGAMAL_DECRYPT_RESP resp;
    string resp_str;

    printf("starting decrypt\n");
    ElGamal_Marshal(h->params, req.ct, c);
    printf("did the marshal\n");
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_ELGAMAL_DECRYPT, 0, 0,
                   string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_ELGAMAL_DECRYPT, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
    printf("got resp\n");
    Params_bytesToPoint(h->params, resp.msg, msg);
    printf("finished getting point\n");

cleanup:
    if (rv == ERROR) printf("ERROR IN DECRYPTION\n");
    return rv;
}

int HSM_AuthMPCDecrypt1(HSM *h, ShamirShare *dShare, ShamirShare *eShare, uint8_t *dMacs, uint8_t *eMacs, uint32_t tag, IBE_ciphertext *c[PUNC_ENC_REPL], ShamirShare *pinShare, uint8_t *hsms) {
    int rv = ERROR;
    HSM_AUTH_MPC_DECRYPT_1_REQ req;
    HSM_AUTH_MPC_DECRYPT_1_RESP resp;
    string resp_str;
    int numLeaves;
    int levels;
    uint32_t currIndex;
    uint32_t totalTraveled;
    uint32_t currInterval;
    uint32_t indexes[PUNC_ENC_REPL];
    bool gotPlaintext = false;

    pthread_mutex_lock(&h->m);

    CHECK_C (PuncEnc_GetIndexesForTag(h->params, tag, indexes));

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

        IBE_MarshalCt(req.ibeCt, IBE_MSG_LEN, c[i]);
        req.index = indexes[i];
   
        Shamir_MarshalCompressed(req.pinShare, pinShare); 
        memcpy(req.hsms, hsms, HSM_GROUP_SIZE);

#ifdef HID
        CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_AUTH_MPC_DECRYPT_1, 0, 0,
                    string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
        memcpy(&resp, resp_str.data(), resp_str.size());
#else
        CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_AUTH_MPC_DECRYPT_1, (uint8_t *)&req,
                    sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
        Shamir_UnmarshalCompressed(resp.dShare, h->id, dShare);
        Shamir_UnmarshalCompressed(resp.eShare, h->id, eShare);
        memcpy(dMacs, resp.dMacs, SHA256_DIGEST_LENGTH * HSM_GROUP_SIZE);
        memcpy(eMacs, resp.eMacs, SHA256_DIGEST_LENGTH * HSM_GROUP_SIZE);

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

int HSM_AuthMPCDecrypt2(HSM *h, ShamirShare *resultShare, uint8_t **resultMacs, BIGNUM *d, BIGNUM *e, ShamirShare **dShares, ShamirShare **eShares, uint8_t **dMacs, uint8_t **eMacs, uint8_t *validHsms, uint8_t *allHsms) {
    int rv;
    HSM_AUTH_MPC_DECRYPT_2_REQ req;
    HSM_AUTH_MPC_DECRYPT_2_RESP resp;
    string resp_str;

    pthread_mutex_lock(&h->m);
    
    memset(req.d, 0, FIELD_ELEM_LEN);
    BN_bn2bin(d, req.d + FIELD_ELEM_LEN  - BN_num_bytes(d));
    memset(req.e, 0, FIELD_ELEM_LEN);
    BN_bn2bin(e, req.e + FIELD_ELEM_LEN  - BN_num_bytes(e));
    for (int i = 0; i < 2 * HSM_THRESHOLD_SIZE; i++)  {
        Shamir_MarshalCompressed(req.dShares[i], dShares[i]);
        Shamir_MarshalCompressed(req.eShares[i], eShares[i]);
        memcpy(req.dMacs[i], dMacs[i], SHA256_DIGEST_LENGTH);
        memcpy(req.eMacs[i], eMacs[i], SHA256_DIGEST_LENGTH);
    }
    memcpy(req.validHsms, validHsms, 2 * HSM_THRESHOLD_SIZE);
    memcpy(req.allHsms, allHsms, HSM_GROUP_SIZE);
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_AUTH_MPC_DECRYPT_2, 0, 0,
                   string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_AUTH_MPC_DECRYPT_2, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
    printf("got resp\n");
    
    Shamir_UnmarshalCompressed(resp.resultShare, h->id, resultShare);
    memcpy(resultMacs, resp.resultMacs, SHA256_DIGEST_LENGTH * HSM_GROUP_SIZE);

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("ERROR IN DECRYPTION\n");
    return rv;
}

int HSM_AuthMPCDecrypt3(HSM *h, uint8_t *msg, BIGNUM *result, ShamirShare **resultShares, uint8_t **resultMacs, uint8_t *validHsms) {
    int rv;
    HSM_AUTH_MPC_DECRYPT_3_REQ req;
    HSM_AUTH_MPC_DECRYPT_3_RESP resp;
    string resp_str;

    pthread_mutex_lock(&h->m);
    
    memset(req.result, 0, FIELD_ELEM_LEN);
    BN_bn2bin(result, req.result + FIELD_ELEM_LEN - BN_num_bytes(result));
    for (int i = 0; i < 2 * HSM_THRESHOLD_SIZE; i++)  {
        Shamir_MarshalCompressed(req.resultShares[i], resultShares[i]);
        memcpy(req.resultMacs[i], resultMacs[i], SHA256_DIGEST_LENGTH);
    }
    memcpy(req.validHsms, validHsms, 2 * HSM_THRESHOLD_SIZE);
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_AUTH_MPC_DECRYPT_3, 0, 0,
                   string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_AUTH_MPC_DECRYPT_3, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
    printf("got resp\n");
    
    memcpy(msg, resp.msg, KEY_LEN);

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("ERROR IN DECRYPTION\n");
    return rv;
}


