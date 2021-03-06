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

/* Run puncturable encryption setup where create puncturable encryption tree
 * on host first (ONLY FOR TESTING, NOT SECURE). */
int HSM_TestSetup(HSM *h) {
    int rv = ERROR;
    HSM_TEST_SETUP_REQ req;
    string resp_str;

    pthread_mutex_lock(&h->m);

    PuncEnc_BuildTree(h->params, (uint8_t *)h->cts, req.msk, req.hmacKey, h->mpk);

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_TEST_SETUP, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_TEST_SETUP, (uint8_t *)&req,
                sizeof(req), NULL, 0));
#endif

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("TEST SETUP ERROR\n");
    return rv;
}

/* Run puncturable encryption setup where puncturable encryption tree is
 * passed in as input (ONLY FOR TESTING, NOT SECURE). */
int HSM_TestSetupInput(HSM *h,  uint8_t *cts, uint8_t msk[KEY_LEN], uint8_t hmacKey[KEY_LEN], EC_POINT **mpk) {
    int rv = ERROR;
    HSM_TEST_SETUP_REQ req;
    string resp_str;

    pthread_mutex_lock(&h->m);

    memcpy(h->cts, cts, TREE_SIZE * CT_LEN);
    memcpy(req.msk, msk, KEY_LEN);
    memcpy(req.hmacKey, hmacKey, KEY_LEN);
    h->mpk = mpk;

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_TEST_SETUP, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_TEST_SETUP, (uint8_t *)&req,
                sizeof(req), NULL, 0));
#endif

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("TEST SETUP ERROR\n");
    return rv;
}

/* Retrieve a leaf indexed by index from puncturable encryption tree. */
int HSM_Retrieve(HSM *h, uint32_t index) {
    int rv = ERROR;
    int numLeaves = NUM_LEAVES;
    int levels = LEVELS;
    HSM_RETRIEVE_REQ req;
    HSM_RETRIEVE_REQ req2;
    HSM_RETRIEVE_RESP resp;
    string resp_str;
    uint32_t currIndex = index;
    uint32_t totalTraveled = 0;
    uint32_t currInterval = numLeaves;

    pthread_mutex_lock(&h->m);

    for (int i = 0; i < levels; i++) {
        debug_print("currIndex = %d, totalTraveled = %d, currInterval = %d, will get %d/%d\n", currIndex, totalTraveled, currInterval, totalTraveled + currIndex, TREE_SIZE);
        
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
#endif

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

/* Puncture a leaf in puncturable encryption tree. Should only be called if
 * lock is held for corresponding HSM. */
int puncture_noLock(HSM *h, uint32_t index) {
    int rv = ERROR;
    HSM_PUNCTURE_REQ req;
    HSM_PUNCTURE_RESP resp;
    string resp_str;
    int numLeaves = NUM_LEAVES;
    int keyLevels = KEY_LEVELS;
    uint32_t currIndex = index;
    uint32_t totalTraveled = numLeaves;
    uint32_t currInterval = numLeaves / 2;
    size_t indexes[keyLevels];

    for (int i = 0; i < keyLevels; i++) {
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
        memcpy(h->cts + indexes[i] * CT_LEN, resp.cts[i], CT_LEN);
    }

    h->isPunctured[index] = true;

cleanup:
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

/* Puncture leaf in puncturable encryption tree (called without lock held). */
int HSM_Puncture(HSM *h, uint32_t index) {
    int rv = ERROR;

    pthread_mutex_lock(&h->m);

    CHECK_C (puncture_noLock(h, index));
cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

/* Encrypt to HSM using puncturable encryption scheme (ElGamal encrypt to PUNC_ENC_REPL
 * of the leaves). */
int HSM_Encrypt(HSM *h, uint32_t tag, BIGNUM *msg, ElGamal_ciphertext *c[PUNC_ENC_REPL]) {
    int rv;
    uint32_t indexes[PUNC_ENC_REPL];

    pthread_mutex_lock(&h->m);
    
    CHECK_C (PuncEnc_GetIndexesForTag(h->params, tag, indexes));

    for (int i = 0; i < PUNC_ENC_REPL; i++)  {
        ElGamal_Encrypt(h->params, msg, h->mpk[indexes[i]], NULL, NULL, c[i]);
    }
    pthread_mutex_unlock(&h->m);
cleanup:
    return rv;
}

/* Decrypt on HS using puncturable encryption scheme. Only decrypt using one of the
 * leaves, but puncture all the leaves that can decrypt. */
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

        numLeaves = NUM_LEAVES;
        levels = LEVELS;
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

        ElGamal_Marshal(h->params, req.elGamalCt, c[i]);
        req.index = indexes[i];

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
    }

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

/* Run microbenchmarks on HSM (only for testing). */
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

/* Send and receive long message from HSM (only for testing). */
int HSM_LongMsg(HSM *h) {
    int rv =  ERROR;
    HSM_LONG_REQ req;
    HSM_LONG_RESP resp;
    string resp_str;
    pthread_mutex_lock(&h->m);

    memset(req.buf, 0xff, RESPONSE_BUFFER_SIZE - 16);

#ifdef HID
    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_LONGMSG, 0, 0,
                   string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));
#else
    CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_LONGMSG, (uint8_t *)&req,
                sizeof(req), (uint8_t *)&resp, sizeof(resp)));
#endif

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("LONG MSG ERROR\n");
    return rv;
}

/* Get the ElGamal public key for a HSM. */
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

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("ERROR GETTING ELGAMAL PK\n");
    return rv;
}

/* ElGamal encrypt to a HSM. */
int HSM_ElGamalEncrypt(HSM *h, BIGNUM *msg, ElGamal_ciphertext *c) {
    int rv;
    CHECK_C (ElGamal_Encrypt(h->params, msg, h->elGamalPk, NULL, NULL, c));

cleanup:
    if (rv == ERROR) printf("ERROR IN ENCRYPT\n");
    return rv;
}

/* Ask HSM to ElGamal decrypt a ciphertext. */
int HSM_ElGamalDecrypt(HSM *h, BIGNUM *msg, ElGamal_ciphertext *c) {
    int rv;
    HSM_ELGAMAL_DECRYPT_REQ req;
    HSM_ELGAMAL_DECRYPT_RESP resp;
    string resp_str;

    pthread_mutex_lock(&h->m);
    
    ElGamal_Marshal(h->params, req.ct, c);
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

/* Set system parameters on a HSM: group size, threshold size, and chunk size.. */
int HSM_SetParams(HSM *h, int hsmGroupSize, int hsmThresholdSize, int chunkSize, uint8_t *logPk, uint8_t puncMeasureWithPubKey, uint8_t puncMeasureWithSymKey) {
    int rv;
    HSM_SET_PARAMS_REQ req;
    string resp_str;

    pthread_mutex_lock(&h->m);

    req.groupSize = hsmGroupSize;
    req.thresholdSize = hsmThresholdSize;
    req.chunkSize = chunkSize;
    memcpy(req.logPk, logPk, COMPRESSED_PT_SZ);
    req.puncMeasureWithPubKey = puncMeasureWithPubKey;
    req.puncMeasureWithSymKey = puncMeasureWithSymKey;

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

/* Check a proof that a recovery attempt is logged correctly. */
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
    CHECK_C (resp.result != 0);
cleanup:
    if (rv == ERROR) {
	printf("ERROR with log proof (%d)\n", h->usbDevice->fd);
    }
    pthread_mutex_unlock(&h->m);
    return rv;
}

/* Run the baseline scheme for recovering. */
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
    if (rv == ERROR) printf("ERROR in baseline (hsm)\n");
    pthread_mutex_unlock(&h->m);
    return rv; 
}

/* Get the public key on the HSM for aggregate signatures. */
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

cleanup:
    pthread_mutex_unlock(&h->m);
    if (rv == ERROR) printf("ERROR GETTING MULTISIG PK\n");
    return rv;
}

/* Ask the HSM to sign a digest using an aggregate signature scheme. */
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

/* Verify aggregate signature on HSM. */
int HSM_MultisigVerify(HSM *h, embedded_pairing_bls12_381_g1_t *sig, uint8_t *msgDigest) {
    int rv;
    HSM_MULTISIG_VERIFY_REQ req;
    HSM_MULTISIG_VERIFY_RESP resp;
    string resp_str;
    embedded_pairing_bls12_381_g1affine_t sigAffine;

    pthread_mutex_lock(&h->m);
    memcpy(req.msgDigest, msgDigest, SHA256_DIGEST_LENGTH);
    memset(req.sig, 0, BASEFIELD_SZ_G1);
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

/* Set the aggregate public key used for aggregate signature verification. */
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

/* Run log verification procedure to ensure that log was updated correctly. Run every
 * epoch. Each HSM chooses a number of chunks to verify the transitions for. If all
 * transitions are correct, it signs the log head. The datacenter aggregates signatures
 * and then the HSMs verify the aggregate signatures. */
int HSM_LogEpochVerification(HSM *h, int chunkSize, embedded_pairing_bls12_381_g1_t *sig, LogState *state) {
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
    for (i = 0; i < NUM_CHUNKS; i++) {
	    uint64_t query = ((uint64_t)resp.queries[i]) % NUM_TRANSITIONS;
        HSM_LOG_ROOTS_PROOF_REQ rootReq;
        HSM_LOG_ROOTS_PROOF_RESP rootResp;

        MerkleProof *rootProofOld = MerkleTree_GetProof(state->rootsTree, (query - 1) * chunkSize); 
        MerkleProof *rootProofNew = MerkleTree_GetProof(state->rootsTree, query * chunkSize);
	for (k = 0; k < rootProofOld->len; k++) {
            memcpy(rootReq.rootProofOld[k], rootProofOld->hash[k], SHA256_DIGEST_LENGTH);
            rootReq.idsOld[k] = rootProofOld->ids[k];
        }
        for (k = 0; k < rootProofNew->len; k++) {
            memcpy(rootReq.rootProofNew[k], rootProofNew->hash[k], SHA256_DIGEST_LENGTH);
            rootReq.idsNew[k] = rootProofNew->ids[k];
        }
	    rootReq.idNew = rootProofNew->id;
        rootReq.lenNew = rootProofNew->len;
        rootReq.idOld = rootProofOld->id;
        rootReq.lenOld = rootProofOld->len;
        memcpy(rootReq.headOld, rootProofOld->leaf, SHA256_DIGEST_LENGTH);
        memcpy(rootReq.headNew, rootProofNew->leaf, SHA256_DIGEST_LENGTH);
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
	    CHECK_C(rootResp.result == 1);

	    // Auditing transition j in round i for queried chunk
        for (j = 0; j < chunkSize; j++) {
            HSM_LOG_TRANS_PROOF_REQ proofReq;
            HSM_LOG_TRANS_PROOF_RESP proofResp;
            int subquery = ((query - 1) * chunkSize) + j;

            memcpy(proofReq.leafNew, state->tProofs[subquery].newProof->leaf, SHA256_DIGEST_LENGTH);
            memset(proofReq.leafNew, 0xff, SHA256_DIGEST_LENGTH);
            for (k = 0; k < state->tProofs[subquery].oldProof->len; k++) {
                memcpy(proofReq.proofOld[k], state->tProofs[subquery].oldProof->hash[k], SHA256_DIGEST_LENGTH);
                proofReq.idsOld[k] = state->tProofs[subquery].oldProof->ids[k];
            }

            for (k = 0; k < state->tProofs[subquery].newProof->len; k++) {
                memcpy(proofReq.proofNew[k], state->tProofs[subquery].newProof->hash[k], SHA256_DIGEST_LENGTH);
                proofReq.idsNew[k] = state->tProofs[subquery].newProof->ids[k];
            }
            proofReq.lenOld = state->tProofs[subquery].oldProof->len;
            proofReq.lenNew = state->tProofs[subquery].newProof->len;
            proofReq.id = state->tProofs[subquery].oldProof->id;
            memcpy(proofReq.headOld, state->tProofs[subquery].oldProof->head, SHA256_DIGEST_LENGTH);
            memcpy(proofReq.headNew, state->tProofs[subquery].newProof->head, SHA256_DIGEST_LENGTH);
            pthread_mutex_lock(&h->m);
#ifdef HID
            CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(h->hidDevice, 0, HSM_LOG_TRANS_PROOF, 0, 0,
                    string(reinterpret_cast<char*>(&proofReq), sizeof(proofReq)), &resp_str));
            memcpy(&proofResp, resp_str.data(), resp_str.size());
#else
            CHECK_C (UsbDevice_exchange(h->usbDevice, HSM_LOG_TRANS_PROOF, (uint8_t *)&proofReq,
                    sizeof(proofReq), (uint8_t *)&proofResp, sizeof(proofResp)));
#endif
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
