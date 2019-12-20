#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "hsm.h"
#include "ibe.h"
#include "log.h"
#include "punc_enc.h"
#include "u2f.h"


int HSM_GetMpk() {
    uint8_t mpk[BASEFIELD_SZ_G2];
    printf1(TAG_GREEN, "returning mpk\n");
    IBE_MarshalMpk(mpk);
    u2f_response_writeback(mpk, BASEFIELD_SZ_G2);
    return U2F_SW_NO_ERROR;
}

int HSM_Setup() {
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];
    uint8_t leaves[NUM_SUB_LEAVES][LEAF_LEN];

    PuncEnc_FillLeaves(leaves);
    PuncEnc_BuildSubTree(leaves, cts);

    /* Note that need to actually recurse through tree and set msk correctly. */

    //    PuncEnc_Setup(cts);
    printf1(TAG_GREEN, "finished setup, just need to write back\n");
    //printf("writeback size: %d\n", SUB_TREE_SIZE * CT_LEN);
    u2f_response_writeback(cts, SUB_TREE_SIZE * CT_LEN);
    return U2F_SW_NO_ERROR;
}

int HSM_SmallSetup() {
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];

    PuncEnc_BuildSmallTree(cts);

    printf1(TAG_GREEN, "finished small setup, just need to write back\n");
    //printf("writeback size: %d\n", SUB_TREE_SIZE * CT_LEN);
    u2f_response_writeback(cts, SUB_TREE_SIZE * CT_LEN);
    return U2F_SW_NO_ERROR;
}

int HSM_TestSetup(struct hsm_test_setup_request *req) {
    printf1(TAG_GREEN, "running test setup\n");
    PuncEnc_TestSetup(req->msk, req->hmacKey);
    return U2F_SW_NO_ERROR;
}

int HSM_Retrieve(struct hsm_retrieve_request *req) {
    printf1(TAG_GREEN, "retrieving leaf\n");
    uint8_t leaf[CT_LEN];

    for (int i = 0;  i < LEVELS; i++) {
        printf("ct[%d/%d]: ", i, LEVELS);
        for (int j = 0; j < CT_LEN;  j++) {
            printf("%x ", req->cts[i][j]);
        }
        printf("\n");
    }
    if (PuncEnc_RetrieveLeaf(req->cts, req->index, leaf) == ERROR) {
        memset(leaf, 0, CT_LEN);
    }

    u2f_response_writeback(leaf, CT_LEN);

    return U2F_SW_NO_ERROR;
}

int HSM_Puncture(struct hsm_puncture_request *req) {
    printf1(TAG_GREEN, "puncturing leaf\n");
    uint8_t newCts[KEY_LEVELS][CT_LEN];

    PuncEnc_PunctureLeaf(req->cts, req->index, newCts);

    printf1(TAG_GREEN, "finished puncturing leaf\n");

    u2f_response_writeback(newCts, KEY_LEVELS * CT_LEN);

    return U2F_SW_NO_ERROR;
}

int HSM_Decrypt(struct hsm_decrypt_request *req) {
    printf1(TAG_GREEN, "starting to decrypt\n");
    uint8_t leaf[CT_LEN];
    embedded_pairing_bls12_381_g2_t U;
    uint8_t V[IBE_MSG_LEN];
    uint8_t W[IBE_MSG_LEN];
    embedded_pairing_bls12_381_g1_t sk;
    uint8_t msg[IBE_MSG_LEN];

    if (PuncEnc_RetrieveLeaf(req->treeCts, req->index, leaf) == ERROR) {
        printf("Couldn't retrieve leaf\n");
        memset(msg, 0, IBE_MSG_LEN);
        u2f_response_writeback(msg, IBE_MSG_LEN);
        return U2F_SW_NO_ERROR;
    }
    IBE_UnmarshalCt(req->ibeCt, IBE_MSG_LEN, &U, V, W);
    IBE_UnmarshalSk(leaf, &sk);
//    IBE_Extract(req->index, &sk);
    IBE_Decrypt(&sk, &U, V, W, msg, IBE_MSG_LEN);

    printf1(TAG_GREEN, "finished decryption\n");

    u2f_response_writeback(msg, IBE_MSG_LEN);

    return U2F_SW_NO_ERROR;
}

int HSM_AuthDecrypt(struct hsm_auth_decrypt_request *req) {
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
        memset(msg, 0, IBE_MSG_LEN);
        u2f_response_writeback(msg, IBE_MSG_LEN);
        return U2F_SW_NO_ERROR;
    }
    IBE_UnmarshalCt(req->ibeCt, IBE_MSG_LEN, &U, V, W);
    IBE_UnmarshalSk(leaf, &sk);
    IBE_Decrypt(&sk, &U, V, W, msg, IBE_MSG_LEN);

    printf1(TAG_GREEN, "finished decryption\n");
    if (memcmp(msg + 32, req->pinHash, SHA256_DIGEST_LEN) != 0) {
        printf("BAD PIN HASH -- WILL NOT DECRYPT\n");
        memset(msg, 0xff, IBE_MSG_LEN);
    }  else {
        printf("Pin hash check passed.\n");
    }

    printf1(TAG_GREEN, "going to puncture\n");
    PuncEnc_PunctureLeaf(req->treeCts, req->index, newCts);
    printf1(TAG_GREEN, "finished puncturing leaf\n");

    u2f_response_writeback(msg, IBE_MSG_LEN);
    u2f_response_writeback(newCts, KEY_LEVELS * CT_LEN);

    printf1(TAG_GREEN, "finished writeback for auth decrypt\n");

    return U2F_SW_NO_ERROR;
}

int HSM_MicroBench() {
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
    embedded_pairing_bls12_381_zp_random(&z1, ctap_generate_rng);
    uint32_t t1 = millis();
    embedded_pairing_bls12_381_g1_multiply_affine(&g1_z1, embedded_pairing_bls12_381_g1affine_generator, &z1);
    uint32_t t2 = millis();
    embedded_pairing_bls12_381_g2_multiply_affine(&g2_z1, embedded_pairing_bls12_381_g2affine_generator, &z1);
    uint32_t t3 = millis();
    embedded_pairing_bls12_381_g1affine_from_projective(&g1_z1_aff, &g1_z1);
    embedded_pairing_bls12_381_g2affine_from_projective(&g2_z1_aff, &g2_z1);
    uint32_t t4 = millis();
    embedded_pairing_bls12_381_g1_multiply_affine(&g1_z2, &g1_z1_aff, &z2);
    uint32_t t5 = millis();
    embedded_pairing_bls12_381_g2_multiply_affine(&g2_z2, &g2_z1_aff, &z2);
    uint32_t t6 = millis(); 
    embedded_pairing_bls12_381_pairing(&res, &g1_z1, &g2_z1);
    uint32_t t7 = millis();
    embedded_pairing_bls12_381_gt_multiply(&res2, &res, &z1);
    uint32_t t8 =  millis();

    printf1(TAG_GREEN, "g_1^x (generator): %d ms\n", t2 - t1);
    printf1(TAG_GREEN, "g_2^x (generator): %d ms\n", t3 - t2);
    printf1(TAG_GREEN, "g_1^x (not generator): %d ms\n", t5 - t4);
    printf1(TAG_GREEN, "g_2^x (not generator): %d ms\n", t6 - t5);
    printf1(TAG_GREEN, "g_t^x (not generator): %d ms\n", t8 - t7);
    printf1(TAG_GREEN, "projective -> affine (both): %d ms\n", t4 - t3);
    printf1(TAG_GREEN, "pairing: %d ms\n", t7 - t6);
    return U2F_SW_NO_ERROR;
}
