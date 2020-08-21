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
#include "multisig.h"
#include "punc_enc.h"
#include "u2f.h"
#include "../crypto/cifra/src/modes.h"
#include "../crypto/cifra/src/aes.h"

uint8_t PUNC_MEASURE_WITH_PUB_KEY = true;
uint8_t PUNC_MEASURE_WITH_SYM_KEY = true;

void HSM_Handle(uint8_t msgType, uint8_t *in, uint8_t *out, int *outLen) {
    switch (msgType) {
        case HSM_RETRIEVE:
            HSM_Retrieve((struct hsm_retrieve_request *)(in), out, outLen);
            break;
        case HSM_PUNCTURE:
            HSM_Puncture((struct hsm_puncture_request *)(in), out, outLen);
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
        case HSM_ELGAMAL_PK:
            HSM_ElGamalPk(out, outLen);
            break;
        case HSM_ELGAMAL_DECRYPT:
            HSM_ElGamalDecrypt((struct hsm_elgamal_decrypt_request *)(in), out, outLen);
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
        case HSM_MULTISIG_PK:
            HSM_MultisigPk(out, outLen);
            break;
        case HSM_MULTISIG_SIGN:
            HSM_MultisigSign((struct hsm_multisig_sign_request *)(in), out, outLen);
            break;
        case HSM_MULTISIG_VERIFY:
            HSM_MultisigVerify((struct hsm_multisig_verify_request *)(in), out, outLen);
            break;
        case HSM_MULTISIG_AGG_PK:
            HSM_MultisigAggPk((struct hsm_multisig_agg_pk_request *)(in), out, outLen);
            break;
        case HSM_LOG_ROOTS:
            HSM_LogRoots((struct hsm_log_roots_request *)(in), out, outLen);
            break;
        case HSM_LOG_ROOTS_PROOF:
            HSM_LogRootsProof((struct hsm_log_roots_proof_request *)(in), out, outLen);
            break;
        case HSM_LOG_TRANS_PROOF:
            HSM_LogTransProof((struct hsm_log_trans_proof_request *)(in), out, outLen);
            break;
        default:
            printf1(TAG_GREEN, "ERROR: Unknown request type %x", msgType);
    }
}

int HSM_GetReqLenFromMsgType(uint8_t msgType) {
    switch (msgType) {
        case HSM_RETRIEVE:
            return sizeof(struct hsm_retrieve_request);
        case HSM_PUNCTURE:
            return sizeof(struct hsm_puncture_request);
        case HSM_DECRYPT:
            return sizeof(struct hsm_decrypt_request);
        case HSM_AUTH_DECRYPT:
            return sizeof(struct hsm_auth_decrypt_request);
        case HSM_TEST_SETUP:
            return sizeof(struct hsm_test_setup_request);
        case HSM_MICROBENCH:
            return 0;
        case HSM_LONGMSG:
            return sizeof(struct hsm_long_request);
        case HSM_ELGAMAL_PK:
            return 0;
        case HSM_ELGAMAL_DECRYPT:
            return sizeof(struct hsm_elgamal_decrypt_request);
        case HSM_SET_PARAMS:
            return sizeof(struct hsm_set_params_request);
        case HSM_LOG_PROOF:
            return sizeof(struct hsm_log_proof_request);
        case HSM_BASELINE:
            return sizeof(struct hsm_baseline_request);
        case HSM_MULTISIG_PK:
            return 0;
        case HSM_MULTISIG_SIGN:
            return sizeof(struct hsm_multisig_sign_request);
        case HSM_MULTISIG_VERIFY:
            return sizeof(struct hsm_multisig_verify_request);
        case HSM_MULTISIG_AGG_PK:
            return sizeof(struct hsm_multisig_agg_pk_request);
        case HSM_LOG_ROOTS:
            return sizeof(struct hsm_log_roots_request);
        case HSM_LOG_ROOTS_PROOF:
            return sizeof(struct hsm_log_roots_proof_request);
        case HSM_LOG_TRANS_PROOF:
            return sizeof(struct hsm_log_trans_proof_request);
        default:
            printf1(TAG_GREEN, "ERROR: Unknown request type %x", msgType);
            return 0;
    }
}

/* Run test setup by loading puncturable encryption tree built at host. */
int HSM_TestSetup(struct hsm_test_setup_request *req, uint8_t *out, int *outLen) {
    PuncEnc_TestSetup(req->msk, req->hmacKey);
    *outLen = 0;
    return U2F_SW_NO_ERROR;
}

/* Retrieve a leaf from puncturable encryption tree. */
int HSM_Retrieve(struct hsm_retrieve_request *req, uint8_t *out, int *outLen) {
    uint8_t leaf[CT_LEN];

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

/* Puncture a leaf in puncturable encryption tree. */
int HSM_Puncture(struct hsm_puncture_request *req, uint8_t *out, int *outLen) {
    uint8_t newCts[KEY_LEVELS][CT_LEN];

    if (PUNC_MEASURE_WITH_SYM_KEY) {
        PuncEnc_PunctureLeaf(req->cts, req->index, newCts);
    }

    if (out) {
        memcpy(out, newCts, KEY_LEVELS * CT_LEN);
        *outLen = KEY_LEVELS * CT_LEN;
    }  else {
        u2f_response_writeback(newCts, KEY_LEVELS * CT_LEN);
    }

    return U2F_SW_NO_ERROR;
}

void punctureAndWriteback(struct hsm_auth_decrypt_request *req, uint8_t *msg, uint8_t *out, int*outLen) {
    uint8_t newCts[KEY_LEVELS][CT_LEN];
    if (PUNC_MEASURE_WITH_SYM_KEY) {
        PuncEnc_PunctureLeaf(req->treeCts, req->index, newCts);
    }

    if (out) {
        memcpy(out, msg, FIELD_ELEM_LEN);
        memcpy(out + FIELD_ELEM_LEN, newCts, KEY_LEVELS * CT_LEN);
        *outLen = FIELD_ELEM_LEN + (KEY_LEVELS * CT_LEN);
    } else {
        u2f_response_writeback(msg, FIELD_ELEM_LEN);
        u2f_response_writeback(newCts, KEY_LEVELS * CT_LEN);
    }
}

/* Decrypt and puncture corresponding secret key. */
int HSM_AuthDecrypt(struct hsm_auth_decrypt_request *req, uint8_t *out, int *outLen) {
    uint8_t leaf[CT_LEN];
    uint8_t msg[FIELD_ELEM_LEN];

    if (PUNC_MEASURE_WITH_SYM_KEY) {
        if (PuncEnc_RetrieveLeaf(req->treeCts, req->index, leaf) == ERROR) {
            if (out) {
                memset(msg, 0, FIELD_ELEM_LEN +  (KEY_LEVELS * CT_LEN));
                *outLen = FIELD_ELEM_LEN + (KEY_LEVELS * CT_LEN);
            } else {
                memset(msg, 0, FIELD_ELEM_LEN + (KEY_LEVELS * CT_LEN));
                u2f_response_writeback(msg, FIELD_ELEM_LEN  + (KEY_LEVELS * CT_LEN));
            }
            return U2F_SW_NO_ERROR;
        }
    }

    if (PUNC_MEASURE_WITH_PUB_KEY) {
        ElGamal_DecryptWithSk(req->elGamalCt, leaf, msg);
    }

    punctureAndWriteback(req, msg, out, outLen);

    return U2F_SW_NO_ERROR;
}

/* Run any microbenchmarks. */
int HSM_MicroBench(uint8_t *out, int *outLen) {
    /* Fill in with any microbenchmarks. */

    *outLen = 0;

    return U2F_SW_NO_ERROR;
}

/* Receive and send long message (just for testing/measurement). */
int HSM_LongMsg(struct hsm_long_request *req, uint8_t *out, int *outLen) {
    uint8_t buf[CTAP_RESPONSE_BUFFER_SIZE - 16];
    if (out) {
        memcpy(out, buf, CTAP_RESPONSE_BUFFER_SIZE - 16);
        *outLen = CTAP_RESPONSE_BUFFER_SIZE - 16;
    } else {
        u2f_response_writeback(buf, CTAP_RESPONSE_BUFFER_SIZE - 16);
    }
    return U2F_SW_NO_ERROR;
}

/* Return the ElGamal public key. */
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

/* Decrypt ElGamal ciphertext. */
int HSM_ElGamalDecrypt(struct hsm_elgamal_decrypt_request *req, uint8_t *out, int *outLen) {
    uint8_t buf[FIELD_ELEM_LEN];
    ElGamal_Decrypt(req->ct, buf);
    if (out) {
        memcpy(out, buf, FIELD_ELEM_LEN);
        *outLen = FIELD_ELEM_LEN;
    } else {
        u2f_response_writeback(buf, FIELD_ELEM_LEN);
    }
    return U2F_SW_NO_ERROR;
}

/* Set system parameters. */
int HSM_SetParams(struct hsm_set_params_request *req, uint8_t *out, int *outLen) {
    Log_SetParams(req->logPk, req->groupSize, req->chunkSize);
    PUNC_MEASURE_WITH_PUB_KEY = req->puncMeasureWithPubKey;
    PUNC_MEASURE_WITH_SYM_KEY = req->puncMeasureWithSymKey;

    if (out) {
        *outLen = 0;
    }

    return U2F_SW_NO_ERROR;
}

/* Verify proof that recovery attempt is logged. */
int HSM_LogProof(struct hsm_log_proof_request *req, uint8_t *out, int *outLen) {
    uint8_t resp = Log_Verify(req->ct, req->hsms, req->proof, req->rootSig, req->opening);

    if (out) {
        memcpy(out, resp, 1);
        *outLen = 1;
    } else {
        u2f_response_writeback(resp, 1);
    }
    return U2F_SW_NO_ERROR;
}

/* Process request to decrypt (baseline for measurement). */
int HSM_Baseline(struct hsm_baseline_request *req, uint8_t *out, int *outLen) {
    uint8_t k[32];
    uint8_t kHash[32];
    uint8_t msg[SHA256_DIGEST_LEN + KEY_LEN];
    uint8_t tagTest[SHA256_DIGEST_LEN];
    uint8_t outputKey[KEY_LEN];

    ElGamal_Decrypt(req->elGamalCt, k);

    crypto_sha256_init();
    crypto_sha256_update(k, 32);
    crypto_sha256_final(kHash);

    /* Decrypt aes ciphertext. */
    crypto_aes256_init(kHash, NULL);
    crypto_aes256_decrypt_sep(msg, req->aesCt, SHA256_DIGEST_LEN + KEY_LEN);

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

/* Return the public key for aggregate signatures. */
int HSM_MultisigPk(uint8_t *out, int *outLen) {
    uint8_t buf[BASEFIELD_SZ_G2];
    Multisig_GetPk(buf);
    if (out) {
        memcpy(out, buf, BASEFIELD_SZ_G2);
        *outLen = BASEFIELD_SZ_G2;
    } else {
        u2f_response_writeback(buf, BASEFIELD_SZ_G2);
    }
    return U2F_SW_NO_ERROR;
}

/* Sign for aggregate signature scheme. */
int HSM_MultisigSign(struct hsm_multisig_sign_request *req, uint8_t *out, int *outLen) {
    uint8_t buf[BASEFIELD_SZ_G1];
    Multisig_Sign(req->msgDigest, SHA256_DIGEST_LEN, buf);
    if (out) {
        memcpy(out, buf, BASEFIELD_SZ_G1);
        *outLen = BASEFIELD_SZ_G1;
    } else {
        u2f_response_writeback(buf, BASEFIELD_SZ_G1);
    }
    return U2F_SW_NO_ERROR;
}

/* Verify aggregate signature. */
int HSM_MultisigVerify(struct hsm_multisig_verify_request *req, uint8_t *out, int *outLen) {
    uint8_t result = Multisig_Verify(req->msgDigest, SHA256_DIGEST_LEN, req->sig);
    if (out) {
        memcpy(out, &result, 1);
        *outLen = 1;
    } else {
        u2f_response_writeback(&result, 1);
    }
    return U2F_SW_NO_ERROR;
}

/* Set the aggregate public key used for verifying aggreate signatures. */
int HSM_MultisigAggPk(struct hsm_multisig_agg_pk_request *req, uint8_t *out, int *outLen) {
    Multisig_SetAggPk(req->aggPk);
    *outLen = 0;
    return U2F_SW_NO_ERROR;
}

/* Given the new root of the log, choose chunks to query. */
int HSM_LogRoots(struct hsm_log_roots_request *req, uint8_t *out, int *outLen) {
    Log_SetChunkRoot(req->root);
    int queries[NUM_CHUNKS];
    Log_GenChunkQueries(queries);
    if (out) {
        memcpy(out, (uint8_t *)queries, NUM_CHUNKS * sizeof(int));
        *outLen = NUM_CHUNKS * sizeof(int);
    } else {
        u2f_response_writeback((uint8_t *)queries, NUM_CHUNKS * sizeof(int));
    }
    return U2F_SW_NO_ERROR;
}

/* Check proofs that the chunks queried correspond to the root of the log committed to. */
int HSM_LogRootsProof(struct hsm_log_roots_proof_request *req, uint8_t *out, int *outLen) {
    uint8_t resp = Log_CheckChunkRootProof(req->idOld, req->headOld, req->rootProofOld, req->idsOld, req->lenOld);
    resp = resp & Log_CheckChunkRootProof(req->idNew, req->headNew, req->rootProofNew, req->idsNew, req->lenNew);
    if (resp != 0) {
        Log_SetOldChunkHead(req->headOld);
        Log_SetNewChunkHead(req->headNew);
    }
    if (resp == 0) printf("FAIL log roots proof\n");
    if (out) {
        memcpy(out, &resp, 1);
        *outLen = 1;
    } else {
        u2f_response_writeback(&resp, 1);
    }
    return U2F_SW_NO_ERROR;
}

/* Check that a transition within a chunk is valid. */
int HSM_LogTransProof(struct hsm_log_trans_proof_request *req, uint8_t *out, int *outLen) {
    uint8_t resp = Log_CheckTransProof(req->id, req->headOld, req->headNew, req->leafNew, req->proofOld, req->proofNew, req->idsOld, req->idsNew, req->lenOld, req->lenNew);
    if (resp == 0) printf("FAIL\n");
    if (out) {
        memcpy(out, &resp, 1);
        *outLen = 1;
    } else {
        u2f_response_writeback(&resp, 1);
    }
    return U2F_SW_NO_ERROR;

}
