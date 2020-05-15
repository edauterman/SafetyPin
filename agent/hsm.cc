#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
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
#include "log.h"
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

    // TODO: need to redo this!!
    //IBE_UnmarshalMpk(resp.mpk, &h->mpk);

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
    PuncEnc_BuildTree(h->params, (uint8_t *)h->cts, req.msk, req.hmacKey, h->mpk);
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

int HSM_TestSetupInput(HSM *h,  uint8_t *cts, uint8_t msk[KEY_LEN], uint8_t hmacKey[KEY_LEN], EC_POINT **mpk) {
    int rv = ERROR;
    HSM_TEST_SETUP_REQ req;
    string resp_str;

    isSmall = false;

    pthread_mutex_lock(&h->m);

    printf("going to run test setup\n");
    memcpy(h->cts, cts, TREE_SIZE * CT_LEN);
    memcpy(req.msk, msk, KEY_LEN);
    memcpy(req.hmacKey, hmacKey, KEY_LEN);
    h->mpk = mpk;
    //memcpy(&h->mpk, mpk, sizeof(embedded_pairing_bls12_381_g2_t));

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
//        printf("currIndex = %d, totalTraveled = %d, currInterval = %d, will get %d/%d\n", currIndex, totalTraveled, currInterval, totalTraveled + currIndex, TREE_SIZE);
        
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
//        printf("setting index %d for ct[%d]: ", indexes[i], i);
        memcpy(h->cts + indexes[i] * CT_LEN, resp.cts[i], CT_LEN);
    }

    h->isPunctured[index] = true;

//    printf("finished puncturing leaf\n");
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

int HSM_Encrypt(HSM *h, uint32_t tag, BIGNUM *msg, ElGamal_ciphertext *c[PUNC_ENC_REPL]) {
    int rv;
    uint32_t indexes[PUNC_ENC_REPL];

    pthread_mutex_lock(&h->m);
    
    CHECK_C (PuncEnc_GetIndexesForTag(h->params, tag, indexes));

    for (int i = 0; i < PUNC_ENC_REPL; i++)  {
        printf("encrypt to %d\n", indexes[i]);
        ElGamal_Encrypt(h->params, msg, h->mpk[indexes[i]], NULL, NULL, c[i]);
    }
    pthread_mutex_unlock(&h->m);
cleanup:
    return rv;
}

int HSM_AuthDecrypt(HSM *h, uint32_t tag, ElGamal_ciphertext *c[PUNC_ENC_REPL], BIGNUM *msg) {
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

        ElGamal_Marshal(h->params, req.elGamalCt, c[i]);
        req.index = indexes[i];
        printf("retrieving from %d\n", indexes[i]);

#ifdef HID
        CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_AUTH_DECRYPT, 0, 0,
                    string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
        memcpy(&resp, resp_str.data(), resp_str.size());
#else
        CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_AUTH_DECRYPT, (uint8_t *)&req,
                    sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
        BN_bin2bn(resp.msg, FIELD_ELEM_LEN, msg);

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

    pthread_mutex_lock(&h->m);

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_ELGAMAL_PK, 0, 0,
                   "", &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_ELGAMAL_PK, NULL,
                0, (uint8_t *)&resp, sizeof(resp)));
#endif
    Params_bytesToPoint(h->params, resp.pk, h->elGamalPk);

    printf("got el gamal public key\n");

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("ERROR GETTING ELGAMAL PK\n");
    return rv;
}

int HSM_ElGamalEncrypt(HSM *h, BIGNUM *msg, ElGamal_ciphertext *c) {
    int rv;
    CHECK_C (ElGamal_Encrypt(h->params, msg, h->elGamalPk, NULL, NULL, c));

cleanup:
    if (rv == ERROR) printf("ERROR IN ENCRYPT\n");
    return rv;
}

int HSM_ElGamalDecrypt(HSM *h, BIGNUM *msg, ElGamal_ciphertext *c) {
    int rv;
    HSM_ELGAMAL_DECRYPT_REQ req;
    HSM_ELGAMAL_DECRYPT_RESP resp;
    string resp_str;

    pthread_mutex_lock(&h->m);
    
    ElGamal_Marshal(h->params, req.ct, c);
    printf("ct: ");
    for (int i = 0; i < 65; i++) printf("%02x", req.ct[i]);
    printf("\n");
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_ELGAMAL_DECRYPT, 0, 0,
                   string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_ELGAMAL_DECRYPT, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
    BN_bin2bn(resp.msg, FIELD_ELEM_LEN, msg);

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("ERROR IN DECRYPTION\n");
    return rv;
}

/*
int HSM_AuthMPCDecrypt1Commit(HSM *h, uint8_t *dCommit, uint8_t *eCommit, uint32_t tag, IBE_ciphertext *c[PUNC_ENC_REPL], uint8_t *aesCt, uint8_t *aesCtTag, ShamirShare *pinShare) {
    int rv = ERROR;
    HSM_AUTH_MPC_DECRYPT_1_COMMIT_REQ req;
    HSM_AUTH_MPC_DECRYPT_1_COMMIT_RESP resp;
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
            memcpy(req.treeCts[levels - j - 1], h->cts + (totalTraveled + currIndex) * CT_LEN, CT_LEN);
            ctIndexes[j] = totalTraveled + currIndex;
            totalTraveled += currInterval;
            currInterval /= 2;
            currIndex /= 2;
        }

        IBE_MarshalCt(req.ibeCt, IBE_MSG_LEN, c[i]);
        req.index = indexes[i];
   
        Shamir_MarshalCompressed(req.pinShare, pinShare); 

        memcpy(req.aesCt, aesCt, AES_CT_LEN);
        memcpy(req.aesCtTag, aesCtTag, SHA256_DIGEST_LENGTH);

#ifdef HID
        CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_AUTH_MPC_DECRYPT_1_COMMIT, 0, 0,
                    string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
        memcpy(&resp, resp_str.data(), resp_str.size());
#else
        CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_AUTH_MPC_DECRYPT_1_COMMIT, (uint8_t *)&req,
                    sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
        memcpy(dCommit, resp.dCommit, SHA256_DIGEST_LENGTH);
        memcpy(eCommit, resp.eCommit, SHA256_DIGEST_LENGTH);

        gotPlaintext =  true;
        h->isPunctured[indexes[i]] = true;

        for (int j = 0; j < levels - 1; j++) {
            memcpy(h->cts + (ctIndexes[j] * CT_LEN), resp.newCts[j], CT_LEN);
        }
        //printf("finished ciphertexts %d/%d\n", i, PUNC_ENC_REPL);
    }

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

int HSM_AuthMPCDecrypt1Open(HSM *h, ShamirShare *dShare, ShamirShare *eShare, uint8_t *dOpening, uint8_t *eOpening, uint8_t **dMacs, uint8_t **eMacs, uint8_t **dCommits, uint8_t **eCommits, uint8_t *hsms, uint8_t reconstructIndex) {
    int rv;
    HSM_AUTH_MPC_DECRYPT_1_OPEN_REQ req;
    HSM_AUTH_MPC_DECRYPT_1_OPEN_RESP resp;
    string resp_str;

    pthread_mutex_lock(&h->m);

    for (int i = 0; i < HSM_THRESHOLD_SIZE; i++) {
        memcpy(req.dCommits[i], dCommits[i], SHA256_DIGEST_LENGTH);
        memcpy(req.eCommits[i], eCommits[i], SHA256_DIGEST_LENGTH);
    }
    memcpy(req.hsms, hsms, HSM_GROUP_SIZE);

#ifdef HID
        CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_AUTH_MPC_DECRYPT_1_OPEN, 0, 0,
                    string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
        memcpy(&resp, resp_str.data(), resp_str.size());
#else
        CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_AUTH_MPC_DECRYPT_1_OPEN, (uint8_t *)&req,
                    sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
 
    Shamir_UnmarshalCompressed(resp.dShare, reconstructIndex, dShare);
    Shamir_UnmarshalCompressed(resp.eShare, reconstructIndex, eShare);
    for (int j = 0; j < HSM_GROUP_SIZE; j++) {
        memcpy(dMacs[j], resp.dMacs[j], SHA256_DIGEST_LENGTH);
        memcpy(eMacs[j], resp.eMacs[j], SHA256_DIGEST_LENGTH);
    }
    memcpy(dOpening, resp.dOpening, FIELD_ELEM_LEN);
    memcpy(eOpening, resp.eOpening, FIELD_ELEM_LEN);
cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}


int HSM_AuthMPCDecrypt2Commit(HSM *h, uint8_t *resultCommit, BIGNUM *d, BIGNUM *e, ShamirShare **dShares, ShamirShare **eShares, uint8_t **dOpenings, uint8_t **eOpenings, uint8_t **dMacs, uint8_t **eMacs, uint8_t *hsms) {
    int rv;
    HSM_AUTH_MPC_DECRYPT_2_COMMIT_REQ req;
    HSM_AUTH_MPC_DECRYPT_2_COMMIT_RESP resp;
    string resp_str;

    pthread_mutex_lock(&h->m);
    
    memset(req.d, 0, FIELD_ELEM_LEN);
    BN_bn2bin(d, req.d + FIELD_ELEM_LEN  - BN_num_bytes(d));
    memset(req.e, 0, FIELD_ELEM_LEN);
    BN_bn2bin(e, req.e + FIELD_ELEM_LEN  - BN_num_bytes(e));
    for (int i = 0; i < HSM_THRESHOLD_SIZE; i++)  {
        Shamir_MarshalCompressed(req.dShares[i], dShares[i]);
        Shamir_MarshalCompressed(req.eShares[i], eShares[i]);
        memcpy(req.dOpenings[i], dOpenings[i], FIELD_ELEM_LEN);
        memcpy(req.eOpenings[i], eOpenings[i], FIELD_ELEM_LEN);
        memcpy(req.dMacs[i], dMacs[i], SHA256_DIGEST_LENGTH);
        memcpy(req.eMacs[i], eMacs[i], SHA256_DIGEST_LENGTH);
    }
    memcpy(req.hsms, hsms, HSM_GROUP_SIZE);
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_AUTH_MPC_DECRYPT_2_COMMIT, 0, 0,
                   string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_AUTH_MPC_DECRYPT_2_COMMIT, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
    
    memcpy(resultCommit, resp.resultCommit, SHA256_DIGEST_LENGTH);

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("ERROR IN DECRYPTION\n");
    return rv;
}

int HSM_AuthMPCDecrypt2Open(HSM *h, ShamirShare *resultShare, uint8_t *resultOpening, uint8_t **resultMacs, uint8_t **resultCommits, uint8_t *hsms, uint8_t reconstructIndex) {
    int rv;
    HSM_AUTH_MPC_DECRYPT_2_OPEN_REQ req;
    HSM_AUTH_MPC_DECRYPT_2_OPEN_RESP resp;
    string resp_str;

    pthread_mutex_lock(&h->m);
    
    for (int i = 0; i < HSM_THRESHOLD_SIZE; i++)  {
        memcpy(req.resultCommits[i], resultCommits[i], SHA256_DIGEST_LENGTH);
    }
    memcpy(req.hsms, hsms, HSM_GROUP_SIZE);
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_AUTH_MPC_DECRYPT_2_OPEN, 0, 0,
                   string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_AUTH_MPC_DECRYPT_2_OPEN, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
    
    memcpy(resultOpening, resp.resultOpening, FIELD_ELEM_LEN);
    Shamir_UnmarshalCompressed(resp.resultShare, reconstructIndex, resultShare);
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        memcpy(resultMacs[i], resp.resultMacs[i], SHA256_DIGEST_LENGTH);
    }

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("ERROR IN DECRYPTION\n");
    return rv;
}

int HSM_AuthMPCDecrypt3(HSM *h, ShamirShare *msg, BIGNUM *result, ShamirShare **resultShares, uint8_t **resultOpenings, uint8_t **resultMacs, uint8_t *hsms, uint8_t reconstructIndex) {
    int rv;
    HSM_AUTH_MPC_DECRYPT_3_REQ req;
    HSM_AUTH_MPC_DECRYPT_3_RESP resp;
    string resp_str;

    pthread_mutex_lock(&h->m);
    
    memset(req.result, 0, FIELD_ELEM_LEN);
    BN_bn2bin(result, req.result + FIELD_ELEM_LEN - BN_num_bytes(result));
    for (int i = 0; i < HSM_THRESHOLD_SIZE; i++)  {
        Shamir_MarshalCompressed(req.resultShares[i], resultShares[i]);
        memcpy(req.resultMacs[i], resultMacs[i], SHA256_DIGEST_LENGTH);
        memcpy(req.resultOpenings[i], resultOpenings[i], FIELD_ELEM_LEN);
    }
    memcpy(req.hsms, hsms, HSM_GROUP_SIZE);
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_AUTH_MPC_DECRYPT_3, 0, 0,
                   string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_AUTH_MPC_DECRYPT_3, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
    
    Shamir_UnmarshalCompressed(resp.msg, reconstructIndex, msg);

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("ERROR IN DECRYPTION\n");
    return rv;
}
*/
int HSM_SetMacKeys(HSM *h, uint8_t **macKeys) {
    int rv;
    HSM_SET_MAC_KEYS_REQ req;
    string resp_str;

    pthread_mutex_lock(&h->m);

    for (int i = 0; i < NUM_HSMS; i++) {
        memcpy(req.macKeys[i], macKeys[i], KEY_LEN);
    }
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_SET_MAC_KEYS, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_SET_MAC_KEYS, (uint8_t *)&req,
                sizeof(req), NULL, 0));
#endif
cleanup:
    pthread_mutex_unlock(&h->m);
    return rv;
}

int HSM_SetParams(HSM *h, uint8_t *logPk) {
    int rv;
    HSM_SET_PARAMS_REQ req;
    string resp_str;

    pthread_mutex_lock(&h->m);

    req.groupSize = HSM_GROUP_SIZE;
    req.thresholdSize = HSM_THRESHOLD_SIZE;
    req.chunkSize = CHUNK_SIZE;
    memcpy(req.logPk, logPk, COMPRESSED_PT_SZ);

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_SET_PARAMS, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_SET_PARAMS, (uint8_t *)&req,
                sizeof(req), NULL, 0));
#endif

cleanup:
    pthread_mutex_unlock(&h->m);
    return rv;
}

int HSM_LogProof(HSM *h, ElGamal_ciphertext *c, uint8_t *hsms, LogProof *p) {
    int rv;
    HSM_LOG_PROOF_REQ req;
    HSM_LOG_PROOF_RESP resp;
    string resp_str;

    pthread_mutex_lock(&h->m);

    ElGamal_Marshal(h->params, req.ct, c);
    memcpy(req.hsms, hsms, HSM_MAX_GROUP_SIZE);
    for (int i = 0; i < PROOF_LEVELS; i++) {
        memcpy(req.proof[i], p->merkleProof[i], SHA256_DIGEST_LENGTH);
    }
    memcpy(req.rootSig, p->rootSig, SIG_LEN);
    memcpy(req.opening, p->opening, FIELD_ELEM_LEN);

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_LOG_PROOF, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_LOG_PROOF, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif

    if (resp.result == 0) {
        printf("LOG PROOF FAIL: %d\n", resp.result);
    }

cleanup:
    pthread_mutex_unlock(&h->m);
    return rv;
}

int HSM_Baseline(HSM *h, uint8_t *key, ElGamal_ciphertext *c, uint8_t *aesCt, uint8_t *pinHash) {
    int rv;
    HSM_BASELINE_REQ req;
    HSM_BASELINE_RESP resp;
    string resp_str;

    pthread_mutex_lock(&h->m);

    ElGamal_Marshal(h->params, req.elGamalCt, c);
    memcpy(req.aesCt, aesCt, SHA256_DIGEST_LENGTH + KEY_LEN);
    memcpy(req.pinHash, pinHash, SHA256_DIGEST_LENGTH);

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_BASELINE, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_BASELINE, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif

    memcpy(key, resp.key, KEY_LEN);

cleanup:
    pthread_mutex_unlock(&h->m);
    return rv; 
}

int HSM_MultisigGetPk(HSM *h) {
    int rv;
    HSM_MULTISIG_PK_RESP resp;
    string resp_str;

    pthread_mutex_lock(&h->m);

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_MULTISIG_PK, 0, 0,
                   "", &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_MULTISIG_PK, NULL,
                0, (uint8_t *)&resp, sizeof(resp)));
#endif
    embedded_pairing_bls12_381_g2_unmarshal(&h->multisigPkAffine, &resp.pk, true, true);
    embedded_pairing_bls12_381_g2_from_affine(&h->multisigPk, &h->multisigPkAffine);

    printf("got multisig public key\n");

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("ERROR GETTING MULTISIG PK\n");
    return rv;
}

int HSM_MultisigSign(HSM *h, embedded_pairing_bls12_381_g1_t *sig, uint8_t *msgDigest) {
    int rv;
    HSM_MULTISIG_SIGN_REQ req;
    HSM_MULTISIG_SIGN_RESP resp;
    string resp_str;
    embedded_pairing_bls12_381_g1affine_t sigAffine;

    pthread_mutex_lock(&h->m);
    memcpy(req.msgDigest, msgDigest, SHA256_DIGEST_LENGTH);
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_MULTISIG_SIGN, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_MULTISIG_SIGN, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif

    embedded_pairing_bls12_381_g1_unmarshal(&sigAffine, resp.sig, true, true);
    embedded_pairing_bls12_381_g1_from_affine(sig, &sigAffine);
 
cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("ERROR with multisig sign\n");
    return rv;
}

int HSM_MultisigVerify(HSM *h, embedded_pairing_bls12_381_g1_t *sig, uint8_t *msgDigest) {
    int rv;
    HSM_MULTISIG_VERIFY_REQ req;
    HSM_MULTISIG_VERIFY_RESP resp;
    string resp_str;
    embedded_pairing_bls12_381_g1affine_t sigAffine;

    pthread_mutex_lock(&h->m);
    memcpy(req.msgDigest, msgDigest, SHA256_DIGEST_LENGTH);
    embedded_pairing_bls12_381_g1affine_from_projective(&sigAffine, sig);
    embedded_pairing_bls12_381_g1_marshal(req.sig, &sigAffine, true);
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_MULTISIG_VERIFY, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_MULTISIG_VERIFY, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
    if (resp.correct == 0) {
        printf("Multisig verification FAILED\n");
        rv = ERROR;
    }

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("ERROR with multisig verification\n");
    return rv;
}

int HSM_MultisigSetAggPk(HSM *h, embedded_pairing_bls12_381_g2_t *aggPk) {
    int rv;
    HSM_MULTISIG_AGG_PK_REQ req;
    embedded_pairing_bls12_381_g2affine_t aggPkAffine;
    string resp_str;

    pthread_mutex_lock(&h->m);
    embedded_pairing_bls12_381_g2affine_from_projective(&aggPkAffine, aggPk);
    embedded_pairing_bls12_381_g2_marshal(req.aggPk, &aggPkAffine, true);
#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_MULTISIG_AGG_PK, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_MULTISIG_AGG_PK, (uint8_t *)&req,
                sizeof(req), NULL, 0));
#endif
cleanup:
    pthread_mutex_unlock(&h->m);
    return rv;
}

int HSM_LogEpochVerification(HSM *h, embedded_pairing_bls12_381_g1_t *sig, LogState *state) {
    int rv;
    int i, j, k;

    /* Send Merkle root over start and end digests for each chunk. */
    HSM_LOG_ROOTS_REQ req;
    HSM_LOG_ROOTS_RESP resp;
    memcpy(req.root, state->rootsTree->hash, SHA256_DIGEST_LENGTH);
    string resp_str;
    pthread_mutex_lock(&h->m);
 #ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_LOG_ROOTS, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
    memcpy(&resp, resp_str.data(), resp_str.size());
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_LOG_ROOTS, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif
    pthread_mutex_unlock(&h->m);
/*    printf("queries for: ");
    for (int i = 0; i < NUM_CHUNKS; i++) printf("%d ", resp.queries[i]);
    printf("\n");
*/
    /* Audit proofs for log (lambda * N) chunks */
    for (i = 0; i < NUM_CHUNKS; i++) {
	if (i % 10 == 0) printf("chunk %d/%d\n", i, NUM_CHUNKS);
        int query = resp.queries[i % 23];
//        printf("Starting auditing round %d for chunk %d\n", i, query);
        HSM_LOG_ROOTS_PROOF_REQ rootReq;
        HSM_LOG_ROOTS_PROOF_RESP rootResp;

//        printf("rootsTree ids = (%d, %d, %d)\n", state->rootsTree->leftID, state->rootsTree->midID, state->rootsTree->rightID);
        MerkleProof *rootProofOld = MerkleTree_GetProof(state->rootsTree, (query - 1) * CHUNK_SIZE);
        MerkleProof *rootProofNew = MerkleTree_GetProof(state->rootsTree, query * CHUNK_SIZE);
/*        printf("root tree head: ");
        for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) printf("%02x", state->rootsTree->hash[j]);
        printf("\n");
        printf("old chunk head: ");
        for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) printf("%02x", rootProofOld->leaf[j]);
        printf("\n");
        if (rootProofOld == NULL) printf("old proof is null\n");
        if (rootProofNew == NULL) printf("new proof is null\n"); 
        printf("Generate root proofs, oldLen = %d, newLen = %d\n", rootProofOld->len, rootProofNew->len); */
        for (k = 0; k < rootProofOld->len; k++) {
            //printf("old proof item %d\n", k);
            memcpy(rootReq.rootProofOld[k], rootProofOld->hash[k], SHA256_DIGEST_LENGTH);
            rootReq.idsOld[k] = rootProofOld->ids[k];
        }
        for (k = 0; k < rootProofNew->len; k++) {
            //printf("new proof item %d\n", k);
            memcpy(rootReq.rootProofNew[k], rootProofNew->hash[k], SHA256_DIGEST_LENGTH);
            rootReq.idsNew[k] = rootProofNew->ids[k];
        }
        rootReq.idNew = rootProofNew->id;
        rootReq.lenNew = rootProofNew->len;
        rootReq.idOld = rootProofOld->id;
        rootReq.lenOld = rootProofOld->len;
        printf("ids = %d, %d\n", rootReq.idNew, rootReq.idOld);
        memcpy(rootReq.headOld, rootProofOld->leaf, SHA256_DIGEST_LENGTH);
        memcpy(rootReq.headNew, rootProofNew->leaf, SHA256_DIGEST_LENGTH);
        //printf("Going to send request\n");
        pthread_mutex_lock(&h->m);
#ifdef HID
        CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_LOG_ROOTS_PROOF, 0, 0,
                    string(reinterpret_cast<char*>(&rootReq), sizeof(rootReq)), &resp_str));
        memcpy(&rootResp, resp_str.data(), resp_str.size());
#else
        CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_LOG_ROOTS_PROOF, (uint8_t *)&rootReq,
                    sizeof(rootReq), (uint8_t *)&rootResp, sizeof(rootResp)));
#endif
        pthread_mutex_unlock(&h->m);
        //printf("Ran root proofs\n");
        CHECK_C(rootResp.result == 1);

        for (j = 0; j < CHUNK_SIZE; j++) {
            //printf("Auditing transition %d in round %d (chunk %d)\n", j, i, query);
            HSM_LOG_TRANS_PROOF_REQ proofReq;
            HSM_LOG_TRANS_PROOF_RESP proofResp;
            int subquery = ((query - 1) * CHUNK_SIZE) + j;

            memcpy(proofReq.leafOld1, state->tProofs[subquery].oldProof1->leaf, SHA256_DIGEST_LENGTH);
            memcpy(proofReq.leafOld2, state->tProofs[subquery].oldProof2->leaf, SHA256_DIGEST_LENGTH);
            memcpy(proofReq.leafNew, state->tProofs[subquery].newProof->leaf, SHA256_DIGEST_LENGTH);
            memset(proofReq.leafNew, 0xff, SHA256_DIGEST_LENGTH);
            for (k = 0; k < state->tProofs[subquery].oldProof1->len; k++) {
                memcpy(proofReq.proofOld1[k], state->tProofs[subquery].oldProof1->hash[k], SHA256_DIGEST_LENGTH);
                proofReq.idsOld1[k] = state->tProofs[subquery].oldProof1->ids[k];
            }

            for (k = 0; k < state->tProofs[subquery].oldProof2->len; k++) {
                memcpy(proofReq.proofOld2[k], state->tProofs[subquery].oldProof2->hash[k], SHA256_DIGEST_LENGTH);
                proofReq.idsOld2[k] = state->tProofs[subquery].oldProof2->ids[k];
            }

            for (k = 0; k < state->tProofs[subquery].newProof->len; k++) {
                memcpy(proofReq.proofNew[k], state->tProofs[subquery].newProof->hash[k], SHA256_DIGEST_LENGTH);
                proofReq.idsNew[k] = state->tProofs[subquery].newProof->ids[k];
            }
            proofReq.lenOld1 = state->tProofs[subquery].oldProof1->len;
            proofReq.lenOld2 = state->tProofs[subquery].oldProof2->len;
            proofReq.lenNew = state->tProofs[subquery].newProof->len;
            proofReq.idOld1 = state->tProofs[subquery].oldProof1->id;
            proofReq.idOld2 = state->tProofs[subquery].oldProof2->id;
            proofReq.idNew = state->tProofs[subquery].newProof->id;
            memcpy(proofReq.headOld, state->tProofs[subquery].oldProof1->head, SHA256_DIGEST_LENGTH);
            memcpy(proofReq.headNew, state->tProofs[subquery].newProof->head, SHA256_DIGEST_LENGTH);
            //printf("Going to send request, size = %d\n", sizeof(proofReq));
            pthread_mutex_lock(&h->m);
#ifdef HID
            CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_LOG_TRANS_PROOF, 0, 0,
                    string(reinterpret_cast<char*>(&proofReq), sizeof(proofReq)), &resp_str));
            memcpy(&proofResp, resp_str.data(), resp_str.size());
#else
            CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_LOG_TRANS_PROOF, (uint8_t *)&proofReq,
                    sizeof(proofReq), (uint8_t *)&proofResp, sizeof(proofResp)));
#endif
            //printf("got response\n");
            CHECK_C (proofResp.result == 1);
            pthread_mutex_unlock(&h->m);
        }
    }

    /* Sign log head. */
    CHECK_C (HSM_MultisigSign(h, sig, state->rootsTree->hash));
    
cleanup:
    if (rv == ERROR) printf("Exiting due to ERROR\n");
    return rv;
}
