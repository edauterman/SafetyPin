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
    IBE_MarshalMpk(mpk);
    u2f_response_writeback(mpk, BASEFIELD_SZ_G2);
    return U2F_SW_NO_ERROR;
}

int HSM_Setup() {
    printf1(TAG_GREEN, "before declaring array\n");
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];
    uint8_t leaves[NUM_SUB_LEAVES][CT_LEN];
    uint8_t finalKey[KEY_LEN];
    printf1(TAG_GREEN, "declared the array\n");

    PuncEnc_FillLeaves(leaves, 0);
    PuncEnc_BuildSubTree(leaves, cts, finalKey);
    PuncEnc_SetMsk(finalKey);

    /* Note that need to actually recurse through tree and set msk correctly. */

    //    PuncEnc_Setup(cts);
    printf1(TAG_GREEN, "finished setup, just need to write back\n");
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
    IBE_ciphertext c;
    embedded_pairing_bls12_381_g1_t sk;
    uint8_t msg[IBE_MSG_LEN];

    PuncEnc_RetrieveLeaf(req->treeCts, req->index, leaf);
    IBE_UnmarshalCt(req->ibeCt, &c, IBE_MSG_LEN);
    IBE_UnmarshalSk(leaf, &sk);
//    IBE_Extract(req->index, &sk);
    IBE_Decrypt(&sk, &c, msg, IBE_MSG_LEN);

    printf1(TAG_GREEN, "finished decryption\n");

    u2f_response_writeback(msg, IBE_MSG_LEN);

    return U2F_SW_NO_ERROR;
}

