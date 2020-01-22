#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"
#include "crypto.h"
#include "hsm.h"
#include "ibe.h"
#include "log.h"
#include "punc_enc.h"
#include "u2f.h"

void HSM_Handle(uint8_t msgType, uint8_t *in, uint8_t *out, int *outLen) {
    switch (msgType) {
        case HSM_SETUP: 
            HSM_Setup(out, outLen);
            break;
        case HSM_RETRIEVE:
            HSM_Retrieve((struct hsm_retrieve_request *)(in), out, outLen);
            break;
        case HSM_PUNCTURE:
            HSM_Puncture((struct hsm_puncture_request *)(in), out, outLen);
            break;
        case HSM_DECRYPT:
            HSM_Decrypt((struct hsm_decrypt_request *)(in), out, outLen);
            break;
        case HSM_MPK:
            HSM_GetMpk(out, outLen);
            break;
        case HSM_SMALL_SETUP:
            HSM_SmallSetup(out, outLen);
            break;
        case HSM_AUTH_DECRYPT:
            HSM_AuthDecrypt((struct hsm_auth_decrypt_request *)(in), out, outLen);
            break;
        case HSM_TEST_SETUP:
            HSM_TestSetup((struct hsm_test_setup_request *)(in), out, outLen);
            break;
        case HSM_MICROBENCH:
            HSM_MicroBench(out, outLen);
            break;
        case HSM_LONGMSG:
            HSM_LongMsg((struct hsm_long_request *)(in), out, outLen);
            break;
        case HSM_MAC:
            HSM_Mac((struct hsm_mac_request *)(in), out, outLen);
            break;
        case HSM_GET_NONCE:
            HSM_GetNonce(out, outLen);
            break;
        case HSM_RET_MAC:
            HSM_RetMac((struct hsm_ret_mac_request *)(in), out, outLen);
            break;
        default:
            printf1(TAG_GREEN, "ERROR: Unknown request type %x", msgType);
    }
}

int HSM_GetReqLenFromMsgType(uint8_t msgType) {
    switch (msgType) {
        case HSM_SETUP: 
            return 0;
        case HSM_RETRIEVE:
            return sizeof(struct hsm_retrieve_request);
        case HSM_PUNCTURE:
            return sizeof(struct hsm_puncture_request);
        case HSM_DECRYPT:
            return sizeof(struct hsm_decrypt_request);
        case HSM_MPK:
            return 0;
        case HSM_SMALL_SETUP:
            return 0;
        case HSM_AUTH_DECRYPT:
            return sizeof(struct hsm_auth_decrypt_request);
        case HSM_TEST_SETUP:
            return sizeof(struct hsm_test_setup_request);
        case HSM_MICROBENCH:
            return 0;
        case HSM_LONGMSG:
            return sizeof(struct hsm_long_request);
        case HSM_MAC:
            return sizeof(struct hsm_mac_request);
        case HSM_GET_NONCE:
            return 0;
        case HSM_RET_MAC:
            return sizeof(struct hsm_ret_mac_request);
        default:
            printf1(TAG_GREEN, "ERROR: Unknown request type %x", msgType);
            return 0;
    }
}

int HSM_GetMpk(uint8_t *out, int *outLen) {
    uint8_t mpk[BASEFIELD_SZ_G2];
    printf1(TAG_GREEN, "returning mpk\n");
    uint32_t t1 = millis();
    IBE_MarshalMpk(mpk);
    uint32_t t2 = millis();
    printf1(TAG_GREEN, "return time: %d\n", t2 - t1);
    if (out) {
        memcpy(out, mpk, BASEFIELD_SZ_G2);
        *outLen = BASEFIELD_SZ_G2;
    } else {
        u2f_response_writeback(mpk, BASEFIELD_SZ_G2);
    }
    return U2F_SW_NO_ERROR;
}

int HSM_Setup(uint8_t *out, int *outLen) {
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];
    uint8_t leaves[NUM_SUB_LEAVES][LEAF_LEN];

    PuncEnc_FillLeaves(leaves);
    PuncEnc_BuildSubTree(leaves, cts);

    /* Note that need to actually recurse through tree and set msk correctly. */

    //    PuncEnc_Setup(cts);
    printf1(TAG_GREEN, "finished setup, just need to write back\n");
    //printf("writeback size: %d\n", SUB_TREE_SIZE * CT_LEN);
    if (out) {
        memcpy(out, cts, SUB_TREE_SIZE * CT_LEN);
        *outLen = SUB_TREE_SIZE * CT_LEN;
    } else {
        u2f_response_writeback(cts, SUB_TREE_SIZE * CT_LEN);
    }
    return U2F_SW_NO_ERROR;
}

int HSM_SmallSetup(uint8_t *out, int *outLen) {
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];

    PuncEnc_BuildSmallTree(cts);

    printf1(TAG_GREEN, "finished small setup, just need to write back\n");
    //printf("writeback size: %d\n", SUB_TREE_SIZE * CT_LEN);
    if (out) {
        memcpy(out, cts, SUB_TREE_SIZE * CT_LEN);
        *outLen = SUB_TREE_SIZE * CT_LEN;
    } else {
        u2f_response_writeback(cts, SUB_TREE_SIZE * CT_LEN);
    }
    return U2F_SW_NO_ERROR;
}

int HSM_TestSetup(struct hsm_test_setup_request *req, uint8_t *out, int *outLen) {
    printf1(TAG_GREEN, "running test setup\n");
    PuncEnc_TestSetup(req->msk, req->hmacKey);
    *outLen = 0;
    return U2F_SW_NO_ERROR;
}

int HSM_Retrieve(struct hsm_retrieve_request *req, uint8_t *out, int *outLen) {
    printf1(TAG_GREEN, "retrieving leaf\n");
    uint8_t leaf[CT_LEN];

/*    for (int i = 0;  i < LEVELS; i++) {
        printf("ct[%d/%d]: ", i, LEVELS);
        for (int j = 0; j < CT_LEN;  j++) {
            printf("%x ", req->cts[i][j]);
        }
        printf("\n");
    }*/
    if (PuncEnc_RetrieveLeaf(req->cts, req->index, leaf) == ERROR) {
        memset(leaf, 0, CT_LEN);
    }

    if (out) {
        memcpy(out, leaf, CT_LEN);
        *outLen =  CT_LEN;
    } else {
        u2f_response_writeback(leaf, CT_LEN);
    }

    return U2F_SW_NO_ERROR;
}

int HSM_Puncture(struct hsm_puncture_request *req, uint8_t *out, int *outLen) {
    printf1(TAG_GREEN, "puncturing leaf\n");
    uint8_t newCts[KEY_LEVELS][CT_LEN];

    uint32_t t1 = millis();
    PuncEnc_PunctureLeaf(req->cts, req->index, newCts);
    uint32_t t2 = millis();

    //printf1(TAG_GREEN, "***** actual puncture time: %d ms\n", t2 - t1);

    //printf1(TAG_GREEN, "finished puncturing leaf\n");

    if (out) {
        memcpy(out, newCts, KEY_LEVELS * CT_LEN);
        *outLen = KEY_LEVELS * CT_LEN;
    }  else {
        u2f_response_writeback(newCts, KEY_LEVELS * CT_LEN);
    }

    return U2F_SW_NO_ERROR;
}

int HSM_Decrypt(struct hsm_decrypt_request *req, uint8_t *out, int *outLen) {
    printf1(TAG_GREEN, "starting to decrypt\n");
    uint8_t leaf[CT_LEN];
    embedded_pairing_bls12_381_g2_t U;
    uint8_t V[IBE_MSG_LEN];
    uint8_t W[IBE_MSG_LEN];
    embedded_pairing_bls12_381_g1_t sk;
    uint8_t msg[IBE_MSG_LEN];

    if (PuncEnc_RetrieveLeaf(req->treeCts, req->index, leaf) == ERROR) {
        if (out) {
            memset(out, 0xa, IBE_MSG_LEN);
            *outLen = IBE_MSG_LEN;
        } else {
            printf("Couldn't retrieve leaf\n");
            memset(msg, 0, IBE_MSG_LEN);
            u2f_response_writeback(msg, IBE_MSG_LEN);
        }
        return U2F_SW_NO_ERROR;
    }
    IBE_UnmarshalCt(req->ibeCt, IBE_MSG_LEN, &U, V, W);
    IBE_UnmarshalSk(leaf, &sk);
//    IBE_Extract(req->index, &sk);
    IBE_Decrypt(&sk, &U, V, W, msg, IBE_MSG_LEN);

    printf1(TAG_GREEN, "finished decryption\n");

    if (out) {
        memcpy(out, msg, IBE_MSG_LEN);
        *outLen =  IBE_MSG_LEN;
    } else {
        u2f_response_writeback(msg, IBE_MSG_LEN);
    }

    return U2F_SW_NO_ERROR;
}

int HSM_AuthDecrypt(struct hsm_auth_decrypt_request *req, uint8_t *out, int *outLen) {
    printf1(TAG_GREEN, "starting to decrypt\n");
    uint8_t leaf[CT_LEN];
    embedded_pairing_bls12_381_g2_t U;
    uint8_t V[IBE_MSG_LEN];
    uint8_t W[IBE_MSG_LEN];
    embedded_pairing_bls12_381_g1_t sk;
    uint8_t msg[IBE_MSG_LEN];
    uint8_t newCts[KEY_LEVELS][CT_LEN];

    if (PuncEnc_RetrieveLeaf(req->treeCts, req->index, leaf) == ERROR) {
        printf("Couldn't retrieve leaf\n");
        if (out) {
            memset(msg, 0, IBE_MSG_LEN +  (KEY_LEVELS * CT_LEN));
            *outLen = IBE_MSG_LEN + (KEY_LEVELS * CT_LEN);
        } else {
            memset(msg, 0, IBE_MSG_LEN + (KEY_LEVELS * CT_LEN));
            u2f_response_writeback(msg, IBE_MSG_LEN  + (KEY_LEVELS * CT_LEN));
        }
        return U2F_SW_NO_ERROR;
    }
    IBE_UnmarshalCt(req->ibeCt, IBE_MSG_LEN, &U, V, W);
    IBE_UnmarshalSk(leaf, &sk);
    IBE_Decrypt(&sk, &U, V, W, msg, IBE_MSG_LEN);

    printf1(TAG_GREEN, "finished decryption\n");
    if (memcmp(msg + 32, req->pinHash, SHA256_DIGEST_LEN) != 0) {
        printf("BAD PIN HASH -- WILL NOT DECRYPT\n");
        //memset(msg, 0xaa, IBE_MSG_LEN);
    }  else {
        printf("Pin hash check passed.\n");
    }

    printf1(TAG_GREEN, "going to puncture\n");
    PuncEnc_PunctureLeaf(req->treeCts, req->index, newCts);
    printf1(TAG_GREEN, "finished puncturing leaf\n");

    if (out) {
        memcpy(out, msg, IBE_MSG_LEN);
        memcpy(out + IBE_MSG_LEN, newCts, KEY_LEVELS * CT_LEN);
        *outLen = IBE_MSG_LEN + (KEY_LEVELS * CT_LEN);
    } else {
        u2f_response_writeback(msg, IBE_MSG_LEN);
        u2f_response_writeback(newCts, KEY_LEVELS * CT_LEN);
    }
    printf1(TAG_GREEN, "finished writeback for auth decrypt\n");

    return U2F_SW_NO_ERROR;
}

int HSM_MicroBench(uint8_t *out, int *outLen) {
    printf1(TAG_GREEN, "in microbench\n");
    embedded_pairing_core_bigint_256_t z1;
    embedded_pairing_core_bigint_256_t z2;
    embedded_pairing_bls12_381_g1_t g1_z1;
    embedded_pairing_bls12_381_g1_t g1_z2;
    embedded_pairing_bls12_381_g2_t g2_z1;
    embedded_pairing_bls12_381_g2_t g2_z2;
    embedded_pairing_bls12_381_g1affine_t g1_z1_aff;
    embedded_pairing_bls12_381_g2affine_t g2_z1_aff;
    embedded_pairing_bls12_381_fq12_t res;
    embedded_pairing_bls12_381_fq12_t res2;
    uint8_t key[16];
    uint8_t buf[16];
    uint8_t buf2[16];
    uint8_t key1[32];
    uint8_t key2[32];
    memset(key, 0xff, 16);
    embedded_pairing_bls12_381_zp_random(&z1, ctap_generate_rng);
    uint32_t t1 = millis();
    embedded_pairing_bls12_381_g1_multiply_affine(&g1_z1, embedded_pairing_bls12_381_g1affine_generator, &z1);
    uint32_t t2 = millis();
    embedded_pairing_bls12_381_g2_multiply_affine(&g2_z1, embedded_pairing_bls12_381_g2affine_generator, &z1);
    uint32_t t3 = millis();
    printf1(TAG_GREEN, "got here\n");
    embedded_pairing_bls12_381_g1affine_from_projective(&g1_z1_aff, &g1_z1);
    embedded_pairing_bls12_381_g2affine_from_projective(&g2_z1_aff, &g2_z1);
    uint32_t t4 = millis();
    embedded_pairing_bls12_381_g1_multiply_affine(&g1_z2, &g1_z1_aff, &z2);
    uint32_t t5 = millis();
    embedded_pairing_bls12_381_g2_multiply_affine(&g2_z2, &g2_z1_aff, &z2);
    uint32_t t6 = millis(); 
    embedded_pairing_bls12_381_pairing(&res, &g1_z1, &g2_z1);
    printf1(TAG_GREEN, "did pairing\n");
    uint32_t t7 = millis();
    embedded_pairing_bls12_381_gt_multiply(&res2, &res, &z1);
    uint32_t t8 =  millis();
    embedded_pairing_bls12_381_gt_multiply_random(&res2, &res, &z1, ctap_generate_rng);
    uint32_t t9 = millis();
    crypto_aes256_init(key, NULL);
    uint32_t t10 = millis();
    crypto_aes256_encrypt(buf, 16);
    uint32_t t11 = millis();
    crypto_hmac(key, buf, buf2,  16);
    uint32_t t12 = millis();

    memset(buf, 0xff, 16);
    memset(key1, 0xff, 32);
    //memset(key1, 0xff, 16);
    //memset(key1 + 16, 0, 16);
    memset(key2, 0xff, 32);
    crypto_aes256_init(key1, NULL);
    crypto_aes256_encrypt(buf, 16);
    crypto_aes256_init(key2, NULL);
    crypto_aes256_decrypt(buf, 16);
    if (buf[0] != 0xff) {
        printf("DEC FAILED\n");
    } else {
        printf("decryption matched\n");
    }
    //printf("key len: %d, aes256 = %d, aes128 = %d\n", AES_KEYLEN, AES256, AES128);

    printf1(TAG_GREEN, "g_1^x (generator): %d ms\n", t2 - t1);
    printf1(TAG_GREEN, "g_2^x (generator): %d ms\n", t3 - t2);
    printf1(TAG_GREEN, "g_1^x (not generator): %d ms\n", t5 - t4);
    printf1(TAG_GREEN, "g_2^x (not generator): %d ms\n", t6 - t5);
    printf1(TAG_GREEN, "g_t^x (not generator): %d ms\n", t8 - t7);
    printf1(TAG_GREEN, "g_t^x (random): %d ms\n", t9 - t8);
    printf1(TAG_GREEN, "projective -> affine (both): %d ms\n", t4 - t3);
    printf1(TAG_GREEN, "pairing: %d ms\n", t7 - t6);
    printf1(TAG_GREEN, "aes init: %d ms\n", t10 - t9);
    printf1(TAG_GREEN, "aes encrypt: %d ms\n", t11 - t10);
    printf1(TAG_GREEN, "aes total: %d ms\n", t11 - t9);
    printf1(TAG_GREEN, "hmac: %d ms\n", t12 - t11);

    *outLen = 0;

    return U2F_SW_NO_ERROR;
}

int HSM_LongMsg(struct hsm_long_request *req, uint8_t *out, int *outLen) {
//    uint8_t buf[1024];
    uint8_t buf[CTAP_RESPONSE_BUFFER_SIZE - 16];
    memset(buf, 0xff, CTAP_RESPONSE_BUFFER_SIZE - 16);
    //memset(buf, 0xff, 1024);
    if (out) {
        //memcpy(out, buf, 1024);
        memcpy(out, buf, CTAP_RESPONSE_BUFFER_SIZE - 16);
        //*outLen = 1024;
        *outLen = CTAP_RESPONSE_BUFFER_SIZE - 16;
    } else {
        u2f_response_writeback(buf, CTAP_RESPONSE_BUFFER_SIZE - 16);
    }
    return U2F_SW_NO_ERROR;
}

int HSM_Mac(struct hsm_mac_request *req, uint8_t *out, int *outLen) {
//    uint8_t buf[1024];
    uint8_t mac[SHA256_DIGEST_LEN];
    crypto_hmac(pingKey, mac, req->nonce, NONCE_LEN);
    //memset(buf, 0xff, 1024);
    if (out) {
        //memcpy(out, buf, 1024);
        memcpy(out, mac, SHA256_DIGEST_LEN);
        //*outLen = 1024;
        *outLen = SHA256_DIGEST_LEN;
    } else {
        u2f_response_writeback(mac, SHA256_DIGEST_LEN);
    }
    return U2F_SW_NO_ERROR;
}

int HSM_GetNonce(uint8_t *out, int *outLen) {
//    uint8_t buf[1024];
    uint8_t nonce[NONCE_LEN];
    ctap_generate_rng(nonce, NONCE_LEN);
    //memset(buf, 0xff, 1024);
    if (out) {
        //memcpy(out, buf, 1024);
        memcpy(out, nonce, NONCE_LEN);
        //*outLen = 1024;
        *outLen = NONCE_LEN;
    } else {
        u2f_response_writeback(nonce, NONCE_LEN);
    }
    return U2F_SW_NO_ERROR;
}

int HSM_RetMac(struct hsm_ret_mac_request *req, uint8_t *out, int *outLen) {
//    uint8_t buf[1024];
    //memset(buf, 0xff, 1024);
    if (out) {
        *outLen = 0;
    }
    return U2F_SW_NO_ERROR;
}
