#ifndef __HSM_H_INCLUDED__
#define __HSM_H_INCLUDED__

#include <openssl/sha.h>
#include <pthread.h>

#include "ibe.h"
#include "bls12_381/bls12_381.h"
#include "log.h"
#include "params.h"
#include "elgamal.h"
#include "merkle_tree.h"
#include "shamir.h"
#include "u2f.h"
#include "usb.h"

#ifdef __cplusplus
extern "C" {
#endif

/* UNCOMMENT TO USE HID CLASS INSTEAD OF CDC. */
//#define HID

// The corresponding constants in datacenter.h must also be updated.
#define NUM_HSMS 1		// Number of physical HSMs
#define HSM_GROUP_SIZE 10	// Number of HSMs to encrypt to
#define HSM_THRESHOLD_SIZE 5	// Number of HSMs that cannot fail
#define TOTAL_HSMS 50000	// Total number of HSMs theoretically in system
				// (used to compute amount of log verification work).

#define HSM_MAX_GROUP_SIZE 100	// Maximum size of HSM_GROUP_SIZE
#define HSM_MAX_THRESHOLD_SIZE  50	// Maximum size of HSM_THRESHOLD_SIZE

// Log
#define NUM_CHUNKS 92   // Number of chunks each HSM should audit for lambda = 128.
#define CHUNK_SIZE  17  // Size of each chunk audited. 

// Puncturable encryption
#define KEY_LEN 32		// Length of key 
#define LEAF_LEN (2 * KEY_LEN)	// Length of leaf in puncturable encryption tree
#define CT_LEN (2 * KEY_LEN + 32)	// Size of ciphertext in puncturable encryption tree
#define PUNC_ENC_REPL 5 	// Number of leaves each puncturable encryption ciphertext hashes to
#define NUM_LEAVES 2097152	// Total number of leaves in puncturable encryption tree
#define LEVELS 22 		// log2(NUM_LEAVES) + 1
#define KEY_LEVELS (LEVELS - 1) // log2(NUM_LEAVES)
#define SUB_TREE_LEVELS 5	// Number of levels in each subtree

#define SUB_TREE_SIZE ((RESPONSE_BUFFER_SIZE / (4 * KEY_LEN)) - 1) // Number of nodes in each subtree
#define TREE_SIZE (NUM_LEAVES * 2 - 1)	// Number of nodes in entire tree
#define NUM_SUB_LEAVES ((SUB_TREE_SIZE + 1) / 2)	// Number of leaves in subtree
#define NUM_INTERMEDIATE_KEYS (NUM_SUB_LEAVES * 2)	// Number of keys stored in each subtree
// Constants for different subtrees for puncturable encryption
#define LEVEL_0 0
#define LEVEL_1 1
#define LEVEL_2 2
#define LEVEL_3 3
#define LEVEL_DONE -1
// Offsets at different levels of puncturable encryption subtrees
#define LEVEL_1_OFFSET ((524288 + 262144 + 131072 + 65536 + 32768) * CT_LEN)
#define LEVEL_2_OFFSET (LEVEL_1_OFFSET + ((16384 + 8192 + 4096 + 2048 + 1024) * CT_LEN))
#define LEVEL_3_OFFSET (LEVEL_1_OFFSET + LEVEL_2_OFFSET +  ((512 + 256 + 128 + 64 + 32) * CT_LEN))
#define LEVEL_1_NUM_LEAVES 16384 
#define LEVEL_2_NUM_LEAVES 512
#define LEVEL_3_NUM_LEAVES 16

// Crypto primitive sizes
#define COMPRESSED_PT_SZ 33
#define FIELD_ELEM_LEN 32
#define ELGAMAL_CT_LEN (COMPRESSED_PT_SZ + FIELD_ELEM_LEN)
#define ELGAMAL_PK_LEN COMPRESSED_PT_SZ
#define AES_CT_LEN FIELD_ELEM_LEN

#define RESPONSE_BUFFER_SIZE 4096	// Confifgured on HSM

// Message opcodes
#define HSM_SETUP           0x70
#define HSM_RETRIEVE        0x71
#define HSM_PUNCTURE        0x72
#define HSM_DECRYPT         0x73
#define HSM_MPK             0x74
#define HSM_SMALL_SETUP     0x75
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

using namespace std;

typedef struct{
    uint8_t mpk[BASEFIELD_SZ_G2];
} HSM_MPK_RESP;

typedef struct{
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];
} HSM_SETUP_RESP;

typedef struct{
    uint32_t index;
    uint8_t cts[LEVELS][CT_LEN];
} HSM_RETRIEVE_REQ;

typedef struct{
    uint8_t leaf[CT_LEN];
} HSM_RETRIEVE_RESP;

typedef struct {
    uint32_t index;
    uint8_t cts[KEY_LEVELS][CT_LEN];
} HSM_PUNCTURE_REQ;

typedef struct {
    uint8_t cts[KEY_LEVELS][CT_LEN];
} HSM_PUNCTURE_RESP;

typedef struct {
    uint32_t index;
    uint8_t treeCts[LEVELS][CT_LEN];
    uint8_t ibeCt[ELGAMAL_CT_LEN];
} HSM_DECRYPT_REQ;

typedef struct {
    uint8_t msg[FIELD_ELEM_LEN];
} HSM_DECRYPT_RESP;

typedef struct {
    uint32_t index;
    uint8_t treeCts[LEVELS][CT_LEN];
    uint8_t elGamalCt[ELGAMAL_CT_LEN];
} HSM_AUTH_DECRYPT_REQ;

typedef struct {
    uint8_t msg[FIELD_ELEM_LEN];
    uint8_t newCts[KEY_LEVELS][CT_LEN];
} HSM_AUTH_DECRYPT_RESP;

typedef struct {
    uint8_t msg[KEY_LEN];
} HSM_AUTH_MPC_DECRYPT_3_RESP;

typedef struct {
    uint8_t msk[KEY_LEN];
    uint8_t hmacKey[KEY_LEN];
} HSM_TEST_SETUP_REQ;

typedef struct {
    //uint8_t buf[1024];
    uint8_t buf[RESPONSE_BUFFER_SIZE  - 16];
} HSM_LONG_REQ;

typedef struct {
    //uint8_t buf[1024];
    uint8_t buf[RESPONSE_BUFFER_SIZE - 16];
} HSM_LONG_RESP;

typedef struct {
    uint8_t pk[ELGAMAL_PK_LEN];
} HSM_ELGAMAL_PK_RESP;

typedef struct {
    uint8_t ct[ELGAMAL_CT_LEN];
} HSM_ELGAMAL_DECRYPT_REQ;

typedef struct {
    uint8_t msg[FIELD_ELEM_LEN];
} HSM_ELGAMAL_DECRYPT_RESP;

typedef struct {
    uint8_t elGamalCt[ELGAMAL_CT_LEN];
    uint8_t aesCt[SHA256_DIGEST_LENGTH + KEY_LEN];
    uint8_t pinHash[SHA256_DIGEST_LENGTH];
} HSM_BASELINE_REQ;

typedef struct {
    uint8_t key[KEY_LEN];
} HSM_BASELINE_RESP;

typedef struct {
    uint8_t groupSize;
    uint8_t thresholdSize;
    uint8_t chunkSize;
    uint8_t logPk[COMPRESSED_PT_SZ];
} HSM_SET_PARAMS_REQ;

typedef struct {
    uint8_t ct[ELGAMAL_CT_LEN];
    uint8_t hsms[HSM_MAX_GROUP_SIZE];
    uint8_t proof[PROOF_LEVELS][SHA256_DIGEST_LENGTH];
    uint8_t rootSig[SIG_LEN];
    uint8_t opening[FIELD_ELEM_LEN];
} HSM_LOG_PROOF_REQ;

typedef struct {
    uint8_t result;
} HSM_LOG_PROOF_RESP;

typedef struct {
    uint8_t pk[BASEFIELD_SZ_G2];
} HSM_MULTISIG_PK_RESP;

typedef struct {
    uint8_t msgDigest[SHA256_DIGEST_LENGTH];
} HSM_MULTISIG_SIGN_REQ;

typedef struct {
    uint8_t sig[BASEFIELD_SZ_G1];
} HSM_MULTISIG_SIGN_RESP;

typedef struct {
    uint8_t msgDigest[SHA256_DIGEST_LENGTH];
    uint8_t sig[BASEFIELD_SZ_G1];
} HSM_MULTISIG_VERIFY_REQ;

typedef struct {
    uint8_t correct;
} HSM_MULTISIG_VERIFY_RESP;

typedef struct {
    uint8_t aggPk[BASEFIELD_SZ_G2];
} HSM_MULTISIG_AGG_PK_REQ;

typedef struct {
    uint8_t root[SHA256_DIGEST_LENGTH];
} HSM_LOG_ROOTS_REQ;

typedef struct {
    int queries[NUM_CHUNKS];
} HSM_LOG_ROOTS_RESP;

typedef struct {
    uint8_t headOld[SHA256_DIGEST_LENGTH];
    uint8_t headNew[SHA256_DIGEST_LENGTH];
    uint8_t proofOld[MAX_PROOF_LEVELS][SHA256_DIGEST_LENGTH];
    uint64_t idsOld[MAX_PROOF_LEVELS];
    int lenOld;
    uint8_t proofNew[MAX_PROOF_LEVELS][SHA256_DIGEST_LENGTH];
    uint8_t leafNew[SHA256_DIGEST_LENGTH];
    uint64_t idsNew[MAX_PROOF_LEVELS];
    uint64_t id;
    int lenNew;
} HSM_LOG_TRANS_PROOF_REQ;

typedef struct {
    uint8_t result;
} HSM_LOG_TRANS_PROOF_RESP;

typedef struct {
    uint8_t headOld[SHA256_DIGEST_LENGTH];
    uint8_t headNew[SHA256_DIGEST_LENGTH];
    uint8_t rootProofOld[MAX_PROOF_LEVELS][SHA256_DIGEST_LENGTH];
    uint8_t rootProofNew[MAX_PROOF_LEVELS][SHA256_DIGEST_LENGTH];
    uint64_t idsOld[MAX_PROOF_LEVELS];
    uint64_t idsNew[MAX_PROOF_LEVELS];
    uint64_t idNew;
    int lenNew;
    uint64_t idOld;
    int lenOld;
} HSM_LOG_ROOTS_PROOF_REQ;

typedef struct {
    uint8_t result;
} HSM_LOG_ROOTS_PROOF_RESP;

/* ---------------------------------- */

typedef struct {
    struct U2Fob *hidDevice;
    UsbDevice *usbDevice;
    Params *params;
    uint8_t cts[TREE_SIZE * CT_LEN];
    bool isPunctured[NUM_LEAVES];
    EC_POINT **mpk;
    EC_POINT *elGamalPk;
    pthread_mutex_t m;
    uint8_t id;
    embedded_pairing_bls12_381_g2affine_t multisigPkAffine;
    embedded_pairing_bls12_381_g2_t multisigPk;
} HSM;

HSM *HSM_new();
void HSM_free(HSM *h);

/* Setup */
int HSM_GetMpk(HSM *h);
int HSM_Setup(HSM *h);
int HSM_SmallSetup(HSM *h);
int HSM_TestSetup(HSM *h);
int HSM_TestSetupInput(HSM *h,  uint8_t *cts, uint8_t msk[KEY_LEN], uint8_t hmacKey[KEY_LEN], EC_POINT **mpk);
int HSM_SetParams(HSM *h, uint8_t *logPk);

/* Testing tree. */
int HSM_Retrieve(HSM *h, uint32_t index);
int HSM_Puncture(HSM *h, uint32_t index);

/* Encryption/decryption. Decrypt only for testing. Only use AuthDecrypt. */
int HSM_Encrypt(HSM *h, uint32_t tag, BIGNUM *msg, ElGamal_ciphertext *c[PUNC_ENC_REPL]);
int HSM_AuthDecrypt(HSM *h, uint32_t tag, ElGamal_ciphertext *c[PUNC_ENC_REPL], BIGNUM *msg);

int HSM_ElGamalGetPk(HSM *h);
int HSM_ElGamalEncrypt(HSM *h, BIGNUM *msg, ElGamal_ciphertext *c);
int HSM_ElGamalDecrypt(HSM *h, BIGNUM *msg, ElGamal_ciphertext *c);

int HSM_LogProof(HSM *h, ElGamal_ciphertext *c, uint8_t *hsms, LogProof *p);

/* Run microbenchmarks. */
int HSM_MicroBench(HSM *h);
int HSM_LongMsg(HSM *h);
int HSM_Mac(HSM *h1, HSM *h2, uint8_t *nonce, uint8_t *mac);

int HSM_Baseline(HSM *h, uint8_t *key, ElGamal_ciphertext *c, uint8_t *aesCt, uint8_t *pinHash);

int HSM_MultisigGetPk(HSM *h);
int HSM_MultisigSign(HSM *h, embedded_pairing_bls12_381_g1_t *sig, uint8_t *msgDigest);
int HSM_MultisigVerify(HSM *h, embedded_pairing_bls12_381_g1_t *sig, uint8_t *msgDigest);
int HSM_MultisigSetAggPk(HSM *h, embedded_pairing_bls12_381_g2_t *aggPk);

int HSM_LogEpochVerification(HSM *h, embedded_pairing_bls12_381_g1_t *sig, LogState *state);
#ifdef __cplusplus
}
#endif

#endif  // __DET2F_H_INCLUDED__
