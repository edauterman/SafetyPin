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

    PuncEnc_RetrieveLeaf(req->cts, req->index, leaf);

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

    PuncEnc_RetrieveLeaf(req->treeCts, req->index, leaf);
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

    PuncEnc_RetrieveLeaf(req->treeCts, req->index, leaf);
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
    
    u2f_response_writeback(msg, IBE_MSG_LEN);

    return U2F_SW_NO_ERROR;
}

