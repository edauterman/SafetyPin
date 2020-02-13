#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"
#include "crypto.h"
#include "elgamal.h"
#include "hsm.h"
#include "ibe.h"
#include "log.h"
#include "log_proof.h"
#include "mpc.h"
#include "punc_enc.h"
#include "u2f.h"
#include "../crypto/cifra/src/modes.h"
#include "../crypto/cifra/src/aes.h"

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
        case HSM_ELGAMAL_PK:
            HSM_ElGamalPk(out, outLen);
            break;
        case HSM_ELGAMAL_DECRYPT:
            HSM_ElGamalDecrypt((struct hsm_elgamal_decrypt_request *)(in), out, outLen);
            break;
        case HSM_AUTH_MPC_DECRYPT_1_COMMIT:
            HSM_AuthMPCDecrypt_1_Commit((struct hsm_auth_mpc_decrypt_1_commit_request *)(in), out, outLen);
            break;
        case HSM_AUTH_MPC_DECRYPT_1_OPEN:
            HSM_AuthMPCDecrypt_1_Open((struct hsm_auth_mpc_decrypt_1_open_request *)(in), out, outLen);
            break;
        case HSM_AUTH_MPC_DECRYPT_2_COMMIT:
            HSM_AuthMPCDecrypt_2_Commit((struct hsm_auth_mpc_decrypt_2_commit_request *)(in), out, outLen);
            break;
        case HSM_AUTH_MPC_DECRYPT_2_OPEN:
            HSM_AuthMPCDecrypt_2_Open((struct hsm_auth_mpc_decrypt_2_open_request *)(in), out, outLen);
            break;
        case HSM_AUTH_MPC_DECRYPT_3:
            HSM_AuthMPCDecrypt_3((struct hsm_auth_mpc_decrypt_3_request *)(in), out, outLen);
            break;
        case HSM_SET_MAC_KEYS:
            HSM_SetMacKeys((struct hsm_set_mac_keys_request *)(in), out, outLen);
            break;
        case HSM_SET_PARAMS:
            HSM_SetParams((struct hsm_set_params_request *)(in), out, outLen);
            break;
        case HSM_LOG_PROOF:
            HSM_LogProof((struct hsm_log_proof_request *)(in), out, outLen);
            break;
        case HSM_BASELINE:
            HSM_Baseline((struct hsm_baseline_request *)(in), out, outLen);
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
        case HSM_ELGAMAL_PK:
            return 0;
        case HSM_ELGAMAL_DECRYPT:
            return sizeof(struct hsm_elgamal_decrypt_request);
        case HSM_AUTH_MPC_DECRYPT_1_OPEN:
            return sizeof(struct hsm_auth_mpc_decrypt_1_open_request);
        case HSM_AUTH_MPC_DECRYPT_1_COMMIT:
            return sizeof(struct hsm_auth_mpc_decrypt_1_commit_request);
        case HSM_AUTH_MPC_DECRYPT_2_OPEN:
            return sizeof(struct hsm_auth_mpc_decrypt_2_open_request);
        case HSM_AUTH_MPC_DECRYPT_2_COMMIT:
            return sizeof(struct hsm_auth_mpc_decrypt_2_commit_request);
        case HSM_AUTH_MPC_DECRYPT_3:
            return sizeof(struct hsm_auth_mpc_decrypt_3_request);
        case HSM_SET_MAC_KEYS:
            return sizeof(struct hsm_set_mac_keys_request);
        case HSM_SET_PARAMS:
            return sizeof(struct hsm_set_params_request);
        case HSM_LOG_PROOF:
            return sizeof(struct hsm_log_proof_request);
        case HSM_BASELINE:
            return sizeof(struct hsm_baseline_request);
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

    printf("before going into small tree\n");

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
    
    IBE_Decrypt(&sk, &U, V, W, msg, IBE_MSG_LEN);

    if (out) {
        memcpy(out, msg, IBE_MSG_LEN);
        *outLen =  IBE_MSG_LEN;
    } else {
        u2f_response_writeback(msg, IBE_MSG_LEN);
    }

    return U2F_SW_NO_ERROR;
}

void ibeDecrypt(struct hsm_auth_decrypt_request *req, uint8_t *leaf, uint8_t *msg) {
    embedded_pairing_bls12_381_g2_t U;
    uint8_t V[IBE_MSG_LEN];
    uint8_t W[IBE_MSG_LEN];
    embedded_pairing_bls12_381_g1_t sk;

    IBE_UnmarshalCt(req->ibeCt, IBE_MSG_LEN, &U, V, W);
    IBE_UnmarshalSk(leaf, &sk);
    //IBE_Extract(req->index, &sk);
    IBE_Decrypt(&sk, &U, V, W, msg, IBE_MSG_LEN);
}

void punctureAndWriteback(struct hsm_auth_decrypt_request *req, uint8_t *msg, uint8_t *out, int*outLen) {
    uint8_t newCts[KEY_LEVELS][CT_LEN];
    PuncEnc_PunctureLeaf(req->treeCts, req->index, newCts);

    if (out) {
        memcpy(out, msg, IBE_MSG_LEN);
        memcpy(out + IBE_MSG_LEN, newCts, KEY_LEVELS * CT_LEN);
        *outLen = IBE_MSG_LEN + (KEY_LEVELS * CT_LEN);
    } else {
        u2f_response_writeback(msg, IBE_MSG_LEN);
        u2f_response_writeback(newCts, KEY_LEVELS * CT_LEN);
    }
    printf1(TAG_GREEN, "finished writeback for auth decrypt\n");


}

int HSM_AuthDecrypt(struct hsm_auth_decrypt_request *req, uint8_t *out, int *outLen) {
    printf1(TAG_GREEN, "starting to decrypt\n");
    uint8_t leaf[CT_LEN];
    uint8_t msg[IBE_MSG_LEN];

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

    ibeDecrypt(req, leaf, msg);

    /*if (memcmp(msg + 32, req->pinHash, SHA256_DIGEST_LEN) != 0) {
        printf("BAD PIN HASH -- WILL NOT DECRYPT\n");
        memset(msg, 0xaa, IBE_MSG_LEN);
    }  else {
        printf("Pin hash check passed.\n");
    }*/

    punctureAndWriteback(req, msg, out, outLen);

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
    /*memset(key, 0xff, 16);
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
    for (int i = 0; i < 100; i++) {
        crypto_aes256_init(key, NULL);
    }
    uint32_t t10 = millis();
    for (int i = 0; i < 100; i++) {
        crypto_aes256_encrypt(buf, 16);
    }
    uint32_t t11 = millis();
    for (int i = 0; i < 100; i++) {
        crypto_hmac(key, buf, buf2,  16);
    }
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
    }*/
    //printf("key len: %d, aes256 = %d, aes128 = %d\n", AES_KEYLEN, AES256, AES128);
    fieldElem x, y;
    ecPoint gx, gy, gz;
    uint8_t ct[66];
    uint8_t pt[33];
    uECC_randInt(x);
    uECC_randInt(y);
    uint32_t t13 = millis();
    uECC_basePointMult(gx, x);
    uint32_t t14 = millis();
    uECC_pointMult(gy, gx,  y);
    uint32_t t15 = millis();
    uECC_bytesToPointCompressed(ct, gx);
    uECC_bytesToPointCompressed(ct + 33, gy);
    uint32_t t16 = millis();
    ElGamal_Decrypt(ct, pt);
    uint32_t t17 = millis();
    uECC_pointAdd(gz, gx, gy);
    uint32_t t18 = millis();
    for (int i = 0; i < 1000; i++) {
        raw_flash_read(ct, 0, 32);
    }
    uint32_t t19 = millis();

    uint8_t sig[64];
    uint8_t pk[33];
    uint8_t msg[32];
    fieldElem r, s;
    uECC_randInt(r);
    uECC_randInt(s);
    uECC_bytesToPointCompressed(pk, gx);
    uECC_fieldElemToBytes(sig, r);
    uECC_fieldElemToBytes(s + 32, s);
    uint32_t t20 = millis();
    uECC_ecdsaVerify(pk, msg, 32, sig);
    uint32_t t21 = millis();

    /*printf1(TAG_GREEN, "g_1^x (generator): %d ms\n", t2 - t1);
    printf1(TAG_GREEN, "g_2^x (generator): %d ms\n", t3 - t2);
    printf1(TAG_GREEN, "g_1^x (not generator): %d ms\n", t5 - t4);
    printf1(TAG_GREEN, "g_2^x (not generator): %d ms\n", t6 - t5);
    printf1(TAG_GREEN, "g_t^x (not generator): %d ms\n", t8 - t7);
    printf1(TAG_GREEN, "g_t^x (random): %d ms\n", t9 - t8);
    printf1(TAG_GREEN, "projective -> affine (both): %d ms\n", t4 - t3);
    printf1(TAG_GREEN, "pairing: %d ms\n", t7 - t6);
    printf1(TAG_GREEN, "aes init (100): %d ms\n", t10 - t9);
    printf1(TAG_GREEN, "aes encrypt (100): %d ms\n", t11 - t10);
    printf1(TAG_GREEN, "hmac (100): %d ms\n", t12 - t11);
    */printf1(TAG_GREEN, "P256 base point mul: %d ms\n", t14 - t13);
    printf1(TAG_GREEN, "P256 point mul: %d ms\n", t15 - t14);
    printf1(TAG_GREEN, "P256 point add: %d ms\n", t18 - t17);
    printf1(TAG_GREEN, "el gamal decrypt: %d ms\n", t17 - t16);
    printf1(TAG_GREEN, "read from flash (100): %d ms\n", t19 - t18);
    printf1(TAG_GREEN, "ecdsa verify: %d ms\n", t21 - t20);

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

int HSM_ElGamalPk(uint8_t *out, int *outLen) {
    uint8_t buf[ELGAMAL_PK_LEN];
    ElGamal_GetPk(buf);
    if (out) {
        memcpy(out, buf, ELGAMAL_PK_LEN);
        *outLen = ELGAMAL_PK_LEN;
    } else {
        u2f_response_writeback(buf, ELGAMAL_PK_LEN);
    }
    return U2F_SW_NO_ERROR;
}

int HSM_ElGamalDecrypt(struct hsm_elgamal_decrypt_request *req, uint8_t *out, int *outLen) {
    uint8_t buf[ELGAMAL_PT_LEN];
    ElGamal_Decrypt(req->ct, buf);
    if (out) {
        memcpy(out, buf, ELGAMAL_PT_LEN);
        *outLen = ELGAMAL_PT_LEN;
    } else {
        u2f_response_writeback(buf, ELGAMAL_PT_LEN);
    }
    return U2F_SW_NO_ERROR;
}

void getMsg(struct hsm_auth_mpc_decrypt_1_commit_request *req, uint8_t *msg, uint8_t *leaf) {
    embedded_pairing_bls12_381_g2_t U;
    uint8_t V[IBE_MSG_LEN];
    uint8_t W[IBE_MSG_LEN];
    embedded_pairing_bls12_381_g1_t sk;

    IBE_UnmarshalCt(req->ibeCt, IBE_MSG_LEN, &U, V, W);
    IBE_UnmarshalSk(leaf, &sk);
    IBE_Decrypt(&sk, &U, V, W, msg, IBE_MSG_LEN);
}

void mpcStep1(struct hsm_auth_mpc_decrypt_1_commit_request *req, uint8_t *msg, uint8_t *out, int *outLen) {
    uint8_t dCommit[SHA256_DIGEST_LEN];
    uint8_t eCommit[SHA256_DIGEST_LEN];
    uint8_t tmpNewCts[KEY_LEVELS][CT_LEN];

    PuncEnc_PunctureLeaf(req->treeCts, req->index, tmpNewCts);
    MPC_Step1_Commit(dCommit, eCommit, msg, req->pinShare, req->aesCt, req->aesCtTag);

    //memset(dMacs, 0xff, HSM_GROUP_SIZE * SHA256_DIGEST_LEN);
    if (out) {
        memcpy(out, tmpNewCts, KEY_LEVELS * CT_LEN);
        memcpy(out + (KEY_LEVELS * CT_LEN), dCommit, SHA256_DIGEST_LEN);
        memcpy(out + (KEY_LEVELS * CT_LEN) + SHA256_DIGEST_LEN, eCommit, SHA256_DIGEST_LEN);
        *outLen = (2 * SHA256_DIGEST_LEN) + (KEY_LEVELS * CT_LEN);
    } else {
        u2f_response_writeback(tmpNewCts, KEY_LEVELS * CT_LEN);
        u2f_response_writeback(dCommit, SHA256_DIGEST_LEN);
        u2f_response_writeback(eCommit, SHA256_DIGEST_LEN);
    }
    //printf1(TAG_GREEN, "finished writeback for auth decrypt\n");
}

int HSM_AuthMPCDecrypt_1_Commit(struct hsm_auth_mpc_decrypt_1_commit_request *req, uint8_t *out, int *outLen) {
    uint8_t leaf[CT_LEN];
    uint8_t msg[IBE_MSG_LEN];

    if (PuncEnc_RetrieveLeaf(req->treeCts, req->index, leaf) == ERROR) {
        printf("Couldn't retrieve leaf\n");
        if (out) {
            memset(out, 0, (2 * SHA256_DIGEST_LEN) + (KEY_LEVELS * CT_LEN));
            *outLen = (2 * SHA256_DIGEST_LEN) + (KEY_LEVELS * CT_LEN);
        }
        return U2F_SW_NO_ERROR;
    }
    getMsg(req, msg, leaf);

    mpcStep1(req, msg, out, outLen);

    return U2F_SW_NO_ERROR;
}

int HSM_AuthMPCDecrypt_1_Open(struct hsm_auth_mpc_decrypt_1_open_request *req, uint8_t *out, int *outLen) {
    uint8_t dShareBuf[FIELD_ELEM_LEN];
    uint8_t eShareBuf[FIELD_ELEM_LEN];
    uint8_t dOpening[FIELD_ELEM_LEN];
    uint8_t eOpening[FIELD_ELEM_LEN];
    uint8_t dMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN];
    uint8_t eMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN];

    MPC_Step1_Open(dShareBuf, eShareBuf, dOpening, eOpening, dMacs, eMacs, req->dCommits, req->eCommits, req->hsms);

    if (out) {
        memcpy(out, dShareBuf, FIELD_ELEM_LEN);
        memcpy(out + FIELD_ELEM_LEN, eShareBuf, FIELD_ELEM_LEN);
        memcpy(out + (2 * FIELD_ELEM_LEN), dOpening, FIELD_ELEM_LEN);
        memcpy(out + (3 * FIELD_ELEM_LEN), eOpening, FIELD_ELEM_LEN);
        memcpy(out + (4 * FIELD_ELEM_LEN), dMacs, HSM_GROUP_SIZE * SHA256_DIGEST_LEN);
        memcpy(out + (4 * FIELD_ELEM_LEN) + (HSM_GROUP_SIZE * SHA256_DIGEST_LEN), eMacs, HSM_GROUP_SIZE * SHA256_DIGEST_LEN);
        *outLen = (4 * FIELD_ELEM_LEN) + (2 * HSM_GROUP_SIZE * SHA256_DIGEST_LEN);
    } else {
        u2f_response_writeback(dShareBuf, FIELD_ELEM_LEN);
        u2f_response_writeback(eShareBuf, FIELD_ELEM_LEN);
        u2f_response_writeback(dOpening, FIELD_ELEM_LEN);
        u2f_response_writeback(eOpening, FIELD_ELEM_LEN);
        u2f_response_writeback(dMacs, HSM_GROUP_SIZE * SHA256_DIGEST_LEN);
        u2f_response_writeback(eMacs, HSM_GROUP_SIZE * SHA256_DIGEST_LEN);
    }
    return U2F_SW_NO_ERROR;
}


int HSM_AuthMPCDecrypt_2_Commit(struct hsm_auth_mpc_decrypt_2_commit_request *req, uint8_t *out, int *outLen) {
    uint8_t resultCommit[SHA256_DIGEST_LEN];
    if (MPC_Step2_Commit(resultCommit, req->d, req->e, req->dShares, req->eShares, req->dOpenings, req->eOpenings, req->dMacs, req->eMacs, req->hsms) != OKAY) {
        //memset(resultCommit, 0, SHA256_DIGEST_LEN);
    }

    if (out) {
        memcpy(out, resultCommit, SHA256_DIGEST_LEN);
        *outLen = SHA256_DIGEST_LEN;
    } else {
        u2f_response_writeback(resultCommit, SHA256_DIGEST_LEN);
    }
    return U2F_SW_NO_ERROR;
}

int HSM_AuthMPCDecrypt_2_Open(struct hsm_auth_mpc_decrypt_2_open_request *req, uint8_t *out, int *outLen) {
    uint8_t resultShareBuf[FIELD_ELEM_LEN];
    uint8_t resultOpening[FIELD_ELEM_LEN];
    uint8_t resultMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN];

    if (MPC_Step2_Open(resultShareBuf, resultOpening, resultMacs, req->resultCommits, req->hsms) != OKAY) {
        //memset(resultShareBuf, 0, FIELD_ELEM_LEN);
    }

    if (out) {
        memcpy(out, resultShareBuf, FIELD_ELEM_LEN);
        memcpy(out + FIELD_ELEM_LEN, resultOpening, FIELD_ELEM_LEN);
        memcpy(out + 2 * FIELD_ELEM_LEN, resultMacs, HSM_GROUP_SIZE * SHA256_DIGEST_LEN);
        *outLen = (2 * FIELD_ELEM_LEN) + (HSM_GROUP_SIZE * SHA256_DIGEST_LEN);
    } else {
        u2f_response_writeback(resultShareBuf, FIELD_ELEM_LEN);
        u2f_response_writeback(resultOpening, FIELD_ELEM_LEN);
        u2f_response_writeback(resultMacs, HSM_GROUP_SIZE * SHA256_DIGEST_LEN);
    }
    return U2F_SW_NO_ERROR;
}

int HSM_AuthMPCDecrypt_3(struct hsm_auth_mpc_decrypt_3_request *req, uint8_t *out, int *outLen) {
    uint8_t msg[FIELD_ELEM_LEN];
    //printf("in mpc step 3\n");
    
    if (MPC_Step3(msg, req->result, req->resultShares, req->resultOpenings, req->resultMacs, req->hsms) != OKAY) {
        printf("ERROR in mpc step 3\n");
        //memset(msg, 0, FIELD_ELEM_LEN);
    }

    //printf("writing back\n");
    if (out) {
        memcpy(out, msg, FIELD_ELEM_LEN);
        *outLen = FIELD_ELEM_LEN;
    } else {
        u2f_response_writeback(msg, FIELD_ELEM_LEN);
    }
    //printf1(TAG_GREEN, "finished writeback for auth decrypt\n");

    return U2F_SW_NO_ERROR;
}

int HSM_SetMacKeys(struct hsm_set_mac_keys_request *req, uint8_t *out, int *outLen) {
    printf1(TAG_GREEN, "calling set mac keys mpc\n");
    MPC_SetMacKeys((uint8_t *)req->macKeys);

    if (out) {
        *outLen = 0;
    }

    return U2F_SW_NO_ERROR;
}

int HSM_SetParams(struct hsm_set_params_request *req, uint8_t *out, int *outLen) {
    printf1(TAG_GREEN, "calling set params\n");
    MPC_SetParams(req->groupSize, req->thresholdSize);
    Log_SetParams(req->logPk, req->groupSize);

    if (out) {
        *outLen = 0;
    }

    return U2F_SW_NO_ERROR;
}

int HSM_LogProof(struct hsm_log_proof_request *req, uint8_t *out, int *outLen) {
    printf1(TAG_GREEN, "calling log proof\n");
    uint8_t resp = Log_Verify(req->ct, req->hsms, req->proof, req->rootSig, req->opening);

    printf("result: %d\n", resp);

    if (out) {
        memcpy(out, resp, 1);
        *outLen = 1;
    } else {
        u2f_response_writeback(resp, 1);
    }
    return U2F_SW_NO_ERROR;
}

int HSM_Baseline(struct hsm_baseline_request *req, uint8_t *out, int *outLen) {
    uint8_t k[33];
    uint8_t kHash[32];
    uint8_t msg[SHA256_DIGEST_LEN + KEY_LEN];
    uint8_t tagTest[SHA256_DIGEST_LEN];
    uint8_t outputKey[KEY_LEN];

    ElGamal_Decrypt(req->elGamalCt, k);

    crypto_sha256_init();
    crypto_sha256_update(k, 33);
    crypto_sha256_final(kHash);

    /* Decrypt aes ciphertext. */
    crypto_aes256_init(kHash, NULL);
    crypto_aes256_decrypt_sep(msg, req->aesCt, SHA256_DIGEST_LEN + KEY_LEN);
    /*printf("going to decrypt\n");
    cf_aes_context ctx;
    cf_aes_init(&ctx, kHash, 32);
    cf_gcm_decrypt(&cf_aes, &ctx, req->aesCt, SHA256_DIGEST_LEN + KEY_LEN, NULL, 0, NULL, 0, req->tag, 32, msg);
*/

    /* Check pin hash and HMAC. */
    if (memcmp(msg, req->pinHash, SHA256_DIGEST_LEN) == 0) {
        memcpy(outputKey, msg + SHA256_DIGEST_LEN, KEY_LEN);
    } else {
        memset(outputKey, 0, KEY_LEN);
    }

    if (out) {
        memcpy(out, outputKey, KEY_LEN);
        *outLen = KEY_LEN;
    } else {
        u2f_response_writeback(outputKey, KEY_LEN);
    }

    return U2F_SW_NO_ERROR;
}
