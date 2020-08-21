#ifndef _HSM_H_
#define _HSM_H_

#include <stdint.h>
#include "ctaphid.h"
#include "ibe.h"

#define OKAY 1
#define ERROR 0

#define KEY_LEN 32
#define LEAF_LEN (2 * KEY_LEN)
#define CT_LEN (2 * KEY_LEN + 32) 

#define HSM_GROUP_SIZE 100      // Maximum number of physical HSMs in group (same as HSM_MAX_GROUP_SIZE)
#define NUM_HSMS 100            // Maximum number of physical HSMs total

#define PROOF_LEVELS 30         // Number of levels in proof that recovery attempt is logged
#define NUM_CHUNKS 92           // Number of chunks each HSM should audit for lambda = 128.
#define CHUNK_SIZE 100          // Size of each chunk audited.
#define TOTAL_HSMS 500          // Total number of HSMs theoretically in system
                                // (used to compute amount of log verification work).
#define NUM_TRANSITIONS 65536   // Number of total transitions, NUM_HSMS * CHUNK_SIZE
#define MAX_PROOF_LEVELS 35     // Number of levels in log epoch proofs

// Crypto primitive sizes
#define SIG_LEN (FIELD_ELEM_LEN * 2)
#define AES_CT_LEN FIELD_ELEM_LEN
#define COMPRESSED_PT_SZ 33
#define FIELD_ELEM_LEN 32
#define ELGAMAL_CT_LEN (COMPRESSED_PT_SZ + FIELD_ELEM_LEN)
#define ELGAMAL_PK_LEN COMPRESSED_PT_SZ

// Puncturable encryption
#define NUM_LEAVES 2097152      // Number of leaves in puncturable encryption tree
#define LEVELS 22               // Number of levels in tree, log2(NUM_LEAVES) + 1
#define KEY_LEVELS (LEVELS - 1) // Number of levels containing intermediate keys

// Message opcodes
#define HSM_RETRIEVE        0x71
#define HSM_PUNCTURE        0x72
#define HSM_DECRYPT         0x73
#define HSM_AUTH_DECRYPT    0x76
#define HSM_TEST_SETUP      0x77
#define HSM_MICROBENCH      0x78
#define HSM_LONGMSG         0x79
#define HSM_RESET           0x7d
#define HSM_ELGAMAL_PK      0x7e
#define HSM_ELGAMAL_DECRYPT 0x7f
#define HSM_SET_PARAMS                  0x86
#define HSM_LOG_PROOF                   0x87
#define HSM_BASELINE                    0x88
#define HSM_MULTISIG_PK                 0x89
#define HSM_MULTISIG_SIGN               0x8a
#define HSM_MULTISIG_VERIFY             0x8b
#define HSM_MULTISIG_AGG_PK             0x8c
#define HSM_LOG_TRANS_PROOF             0x8d
#define HSM_LOG_ROOTS                   0x8e
#define HSM_LOG_ROOTS_PROOF             0x8f


struct hsm_retrieve_request {
    uint32_t index;
    uint8_t cts[LEVELS][CT_LEN];
};

struct hsm_puncture_request  {
    uint32_t index;
    uint8_t cts[KEY_LEVELS][CT_LEN];
};

struct hsm_decrypt_request {
    uint32_t index;
    uint8_t treeCts[LEVELS][CT_LEN];
    uint8_t elGamalCt[ELGAMAL_CT_LEN];
};

struct hsm_decrypt_response {
    uint8_t msg[FIELD_ELEM_LEN];
};

struct hsm_auth_decrypt_request {
    uint32_t index;
    uint8_t treeCts[LEVELS][CT_LEN];
    uint8_t elGamalCt[ELGAMAL_CT_LEN];
};

struct hsm_auth_decrypt_response {
    uint8_t msg[FIELD_ELEM_LEN];
    uint8_t newCts[KEY_LEVELS][CT_LEN];
};

struct hsm_test_setup_request {
    uint8_t msk[KEY_LEN];
    uint8_t hmacKey[KEY_LEN];
};

struct hsm_long_request {
    uint8_t buf[CTAP_RESPONSE_BUFFER_SIZE- 16];
};

struct hsm_long_response {
    uint8_t buf[CTAP_RESPONSE_BUFFER_SIZE - 16];
};

struct hsm_elgamal_pk_response {
    uint8_t pk[ELGAMAL_PK_LEN];
};

struct hsm_elgamal_decrypt_request {
    uint8_t ct[ELGAMAL_CT_LEN];
};

struct hsm_elgamal_decrypt_response {
    uint8_t msg[FIELD_ELEM_LEN];
};

struct hsm_baseline_request {
    uint8_t elGamalCt[ELGAMAL_CT_LEN];
    uint8_t aesCt[SHA256_DIGEST_LEN + KEY_LEN];
    uint8_t pinHash[SHA256_DIGEST_LEN];
};

struct hsm_set_params_request {
    uint8_t groupSize;
    uint8_t thresholdSize;
    uint8_t chunkSize;
    uint8_t logPk[COMPRESSED_PT_SZ];
    uint8_t puncMeasureWithPubKey;
    uint8_t puncMeasureWithSymKey;
};

struct hsm_log_proof_request {
    uint8_t ct[ELGAMAL_CT_LEN];
    uint8_t hsms[HSM_GROUP_SIZE];
    uint8_t proof[PROOF_LEVELS][SHA256_DIGEST_LEN];
    uint8_t rootSig[SIG_LEN];
    uint8_t opening[FIELD_ELEM_LEN];
};

struct hsm_multisig_sign_request {
    uint8_t msgDigest[SHA256_DIGEST_LEN];
};

struct hsm_multisig_verify_request {
    uint8_t msgDigest[SHA256_DIGEST_LEN];
    uint8_t sig[BASEFIELD_SZ_G1];
};

struct hsm_multisig_agg_pk_request {
    uint8_t aggPk[BASEFIELD_SZ_G2];
};

struct hsm_log_roots_request {
    uint8_t root[SHA256_DIGEST_LEN];
};

struct hsm_log_trans_proof_request {
    uint8_t headOld[SHA256_DIGEST_LEN];
    uint8_t headNew[SHA256_DIGEST_LEN];
    uint8_t proofOld[MAX_PROOF_LEVELS][SHA256_DIGEST_LEN];
    uint64_t idsOld[MAX_PROOF_LEVELS];
    int lenOld;
    uint8_t proofNew[MAX_PROOF_LEVELS][SHA256_DIGEST_LEN];
    uint8_t leafNew[SHA256_DIGEST_LEN];
    uint64_t idsNew[MAX_PROOF_LEVELS];
    uint64_t id;
    int lenNew;
};

struct hsm_log_roots_proof_request {
    uint8_t headOld[SHA256_DIGEST_LEN];
    uint8_t headNew[SHA256_DIGEST_LEN];
    uint8_t rootProofOld[MAX_PROOF_LEVELS][SHA256_DIGEST_LEN];
    uint8_t rootProofNew[MAX_PROOF_LEVELS][SHA256_DIGEST_LEN];
    uint64_t idsOld[MAX_PROOF_LEVELS];
    uint64_t idsNew[MAX_PROOF_LEVELS];
    uint64_t idNew;
    int lenNew;
    uint64_t idOld;
    int lenOld;
};

uint8_t pingKey[KEY_LEN];

void HSM_Handle(uint8_t msgType, uint8_t *in, uint8_t *out, int *outLen);
int HSM_GetReqLenFromMsgType(uint8_t msgType);

int HSM_GetMpk(uint8_t *out, int *outLen);
int HSM_TestSetup(struct hsm_test_setup_request *req, uint8_t *out, int *outLen);
int HSM_Retrieve(struct hsm_retrieve_request *req, uint8_t *out, int *outLen);
int HSM_Puncture(struct hsm_puncture_request *req, uint8_t *out, int *outLen);
int HSM_AuthDecrypt(struct hsm_auth_decrypt_request *req, uint8_t *out, int *outLen);
int HSM_MicroBench(uint8_t *out, int *outLen);
int HSM_LongMsg(struct hsm_long_request *req, uint8_t *out, int *outLen);
int HSM_ElGamalPk(uint8_t *out, int *outLen);
int HSM_ElGamalDecrypt(struct hsm_elgamal_decrypt_request *req, uint8_t *out, int *outLen);
int HSM_SetParams(struct hsm_set_params_request *req, uint8_t *out, int *outLen);
int HSM_LogProof(struct hsm_log_proof_request *req, uint8_t *out, int *outLen);
int HSM_Baseline(struct hsm_baseline_request *req, uint8_t *out, int *outLen);
int HSM_MultisigPk(uint8_t *out, int *outLen);
int HSM_MultisigSign(struct hsm_multisig_sign_request *req, uint8_t *out, int *outLen);
int HSM_MultisigVerify(struct hsm_multisig_verify_request *req, uint8_t *out, int *outLen);
int HSM_MultisigAggPk(struct hsm_multisig_agg_pk_request *req, uint8_t *out, int *outLen);

int HSM_LogRoots(struct hsm_log_roots_request *req, uint8_t *out, int *outLen);
int HSM_LogRootsProof(struct hsm_log_roots_proof_request *req, uint8_t *out, int *outLen);
int HSM_LogTransProof(struct hsm_log_trans_proof_request *req, uint8_t *out, int *outLen);
#endif
