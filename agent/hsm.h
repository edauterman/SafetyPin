#ifndef __HSM_H_INCLUDED__
#define __HSM_H_INCLUDED__

#include <openssl/sha.h>
#include <pthread.h>

#include "ibe.h"
#include "bls12_381/bls12_381.h"
#include "log.h"
#include "params.h"
#include "elgamal.h"
#include "shamir.h"
#include "u2f.h"
#include "usb.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HID

#define NUM_HSMS 1
#define HSM_GROUP_SIZE 1
//#define HSM_GROUP_SIZE 5
#define HSM_THRESHOLD_SIZE 1

//#define HSM_MAX_GROUP_SIZE 3
//#define HSM_MAX_GROUP_SIZE 6
#define HSM_MAX_GROUP_SIZE 100
//#define HSM_MAX_THRESHOLD_SIZE 1 
//#define HSM_MAX_THRESHOLD_SIZE 2
#define HSM_MAX_THRESHOLD_SIZE  50

#define KEY_LEN 32
#define LEAF_LEN (2 * KEY_LEN)
#define CT_LEN (2 * KEY_LEN + 32)

#define COMPRESSED_PT_SZ 33
#define FIELD_ELEM_LEN 32
#define ELGAMAL_CT_LEN (COMPRESSED_PT_SZ + FIELD_ELEM_LEN)
//#define ELGAMAL_PT_LEN COMPRESSED_PT_SZ
#define ELGAMAL_PK_LEN COMPRESSED_PT_SZ

//#define PUNC_ENC_REPL 80
#define PUNC_ENC_REPL 5
#define NUM_ATTEMPTS 1

#define AES_CT_LEN FIELD_ELEM_LEN

#define RESPONSE_BUFFER_SIZE 4096

#define NUM_LEAVES 524288
//#define NUM_LEAVES 16384
//#define NUM_LEAVES NUM_SUB_LEAVES
//#define NUM_LEAVES 256
#define LEVELS 20 // log2(NUM_LEAVES) + 1
//#define LEVELS 15 // log2(NUM_LEAVES) + 1
#define KEY_LEVELS (LEVELS - 1) // log2(NUM_LEAVES) + 1
#define SUB_TREE_LEVELS 5
//#define LEVELS 16 // log2(NUM_LEAVES)

#define SUB_TREE_SIZE ((RESPONSE_BUFFER_SIZE / (4 * KEY_LEN)) - 1)
#define TREE_SIZE (NUM_LEAVES * 2 - 1)
#define NUM_SUB_LEAVES ((SUB_TREE_SIZE + 1) / 2)
#define NUM_INTERMEDIATE_KEYS (NUM_SUB_LEAVES * 2)

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
#define HSM_MAC             0x7a
#define HSM_GET_NONCE       0x7b
#define HSM_RET_MAC         0x7c
#define HSM_RESET           0x7d
#define HSM_ELGAMAL_PK      0x7e
#define HSM_ELGAMAL_DECRYPT 0x7f
#define HSM_AUTH_MPC_DECRYPT_1_COMMIT   0x80
#define HSM_AUTH_MPC_DECRYPT_1_OPEN     0x81
#define HSM_AUTH_MPC_DECRYPT_2_COMMIT   0x82
#define HSM_AUTH_MPC_DECRYPT_2_OPEN     0x83
#define HSM_AUTH_MPC_DECRYPT_3          0x84
#define HSM_SET_MAC_KEYS                0x85
#define HSM_SET_PARAMS                  0x86
#define HSM_LOG_PROOF                   0x87
#define HSM_BASELINE                    0x88

#define LEVEL_0 0
#define LEVEL_1 1
#define LEVEL_2 2
#define LEVEL_3 3
#define LEVEL_DONE -1

#define LEVEL_1_OFFSET ((524288 + 262144 + 131072 + 65536 + 32768) * CT_LEN)
#define LEVEL_2_OFFSET (LEVEL_1_OFFSET + ((16384 + 8192 + 4096 + 2048 + 1024) * CT_LEN))
#define LEVEL_3_OFFSET (LEVEL_1_OFFSET + LEVEL_2_OFFSET +  ((512 + 256 + 128 + 64 + 32) * CT_LEN))
#define LEVEL_1_NUM_LEAVES 16384 
#define LEVEL_2_NUM_LEAVES 512
//#define LEVEL_1_NUM_LEAVES 1024 
#define LEVEL_3_NUM_LEAVES 16
//#define LEVEL_2_NUM_LEAVES 32

#define NONCE_LEN 16 

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
    //uint16_t index;
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
    uint8_t ibeCt[IBE_CT_LEN];
} HSM_DECRYPT_REQ;

typedef struct {
    uint8_t msg[IBE_MSG_LEN];
} HSM_DECRYPT_RESP;

typedef struct {
    uint32_t index;
    uint8_t treeCts[LEVELS][CT_LEN];
    uint8_t ibeCt[IBE_CT_LEN];
} HSM_AUTH_DECRYPT_REQ;

typedef struct {
    uint8_t msg[IBE_MSG_LEN];
    uint8_t newCts[KEY_LEVELS][CT_LEN];
} HSM_AUTH_DECRYPT_RESP;

typedef struct {
    uint8_t macKeys[100][KEY_LEN];
} HSM_SET_MAC_KEYS_REQ;

typedef struct {
    uint32_t index;
    uint8_t treeCts[LEVELS][CT_LEN];
    uint8_t ibeCt[IBE_CT_LEN];
    uint8_t aesCt[AES_CT_LEN];
    uint8_t aesCtTag[SHA256_DIGEST_LENGTH];
    uint8_t pinShare[FIELD_ELEM_LEN];
} HSM_AUTH_MPC_DECRYPT_1_COMMIT_REQ;

typedef struct {
    uint8_t newCts[KEY_LEVELS][CT_LEN];
    uint8_t dCommit[SHA256_DIGEST_LENGTH];
    uint8_t eCommit[SHA256_DIGEST_LENGTH];
} HSM_AUTH_MPC_DECRYPT_1_COMMIT_RESP;

typedef struct {
    uint8_t dCommits[HSM_MAX_THRESHOLD_SIZE][SHA256_DIGEST_LENGTH];
    uint8_t eCommits[HSM_MAX_THRESHOLD_SIZE][SHA256_DIGEST_LENGTH];
    uint8_t hsms[HSM_MAX_GROUP_SIZE];
} HSM_AUTH_MPC_DECRYPT_1_OPEN_REQ;

typedef struct {
    uint8_t dShare[FIELD_ELEM_LEN];
    uint8_t eShare[FIELD_ELEM_LEN];
    uint8_t dOpening[FIELD_ELEM_LEN];
    uint8_t eOpening[FIELD_ELEM_LEN];
    uint8_t dMacs[HSM_MAX_GROUP_SIZE][SHA256_DIGEST_LENGTH];
    uint8_t eMacs[HSM_MAX_GROUP_SIZE][SHA256_DIGEST_LENGTH];
} HSM_AUTH_MPC_DECRYPT_1_OPEN_RESP;

typedef struct {
    uint8_t d[FIELD_ELEM_LEN];
    uint8_t e[FIELD_ELEM_LEN];
    uint8_t dShares[HSM_MAX_THRESHOLD_SIZE][FIELD_ELEM_LEN];
    uint8_t eShares[HSM_MAX_THRESHOLD_SIZE][FIELD_ELEM_LEN];
    uint8_t dOpenings[HSM_MAX_THRESHOLD_SIZE][FIELD_ELEM_LEN];
    uint8_t eOpenings[HSM_MAX_THRESHOLD_SIZE][FIELD_ELEM_LEN];
    uint8_t dMacs[HSM_MAX_THRESHOLD_SIZE][SHA256_DIGEST_LENGTH];
    uint8_t eMacs[HSM_MAX_THRESHOLD_SIZE][SHA256_DIGEST_LENGTH];
    uint8_t hsms[HSM_MAX_GROUP_SIZE];
} HSM_AUTH_MPC_DECRYPT_2_COMMIT_REQ;

typedef struct {
    uint8_t resultCommit[SHA256_DIGEST_LENGTH];
} HSM_AUTH_MPC_DECRYPT_2_COMMIT_RESP;

typedef struct {
    uint8_t resultCommits[HSM_MAX_THRESHOLD_SIZE][SHA256_DIGEST_LENGTH];
    uint8_t hsms[HSM_MAX_GROUP_SIZE];
} HSM_AUTH_MPC_DECRYPT_2_OPEN_REQ;

typedef struct {
    uint8_t resultShare[FIELD_ELEM_LEN];
    uint8_t resultOpening[FIELD_ELEM_LEN];
    uint8_t resultMacs[HSM_MAX_GROUP_SIZE][SHA256_DIGEST_LENGTH];
} HSM_AUTH_MPC_DECRYPT_2_OPEN_RESP;

typedef struct {
    uint8_t result[FIELD_ELEM_LEN];
    uint8_t resultShares[HSM_MAX_THRESHOLD_SIZE][FIELD_ELEM_LEN];
    uint8_t resultOpenings[HSM_MAX_THRESHOLD_SIZE][FIELD_ELEM_LEN];
    uint8_t resultMacs[HSM_MAX_THRESHOLD_SIZE][SHA256_DIGEST_LENGTH];
    uint8_t hsms[HSM_MAX_GROUP_SIZE];
} HSM_AUTH_MPC_DECRYPT_3_REQ;

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
    uint8_t nonce[NONCE_LEN];
} HSM_MAC_REQ;

typedef struct {
    uint8_t mac[SHA256_DIGEST_LENGTH];
} HSM_MAC_RESP;

typedef struct {
    uint8_t nonce[NONCE_LEN];
} HSM_GET_NONCE_RESP;

typedef struct {
    uint8_t mac[SHA256_DIGEST_LENGTH];
} HSM_RET_MAC_REQ;

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



/* ---------------------------------- */

typedef struct {
    struct U2Fob *hidDevice;
    UsbDevice *usbDevice;
    Params *params;
    uint8_t cts[TREE_SIZE * CT_LEN];
    //uint8_t cts[TREE_SIZE][CT_LEN];
    bool isPunctured[NUM_LEAVES];
    embedded_pairing_bls12_381_g2_t mpk;
    EC_POINT *elGamalPk;
    pthread_mutex_t m;
    uint8_t id;
} HSM;

HSM *HSM_new();
void HSM_free(HSM *h);

/* Setup */
int HSM_GetMpk(HSM *h);
int HSM_Setup(HSM *h);
int HSM_SmallSetup(HSM *h);
int HSM_TestSetup(HSM *h);
int HSM_TestSetupInput(HSM *h,  uint8_t *cts, uint8_t msk[KEY_LEN], uint8_t hmacKey[KEY_LEN], embedded_pairing_bls12_381_g2_t *mpk);
int HSM_SetMacKeys(HSM *h, uint8_t **macKeys);
int HSM_SetParams(HSM *h, uint8_t *logPk);

/* Testing tree. */
int HSM_Retrieve(HSM *h, uint32_t index);
int HSM_Puncture(HSM *h, uint32_t index);

/* Encryption/decryption. Decrypt only for testing. Only use AuthDecrypt. */
int HSM_Encrypt(HSM *h, uint32_t tag, uint8_t *msg, int msgLen, IBE_ciphertext *c[PUNC_ENC_REPL]);
int HSM_Decrypt(HSM *h, uint32_t tag, IBE_ciphertext *c[PUNC_ENC_REPL], uint8_t *msg, int msgLen);
int HSM_AuthDecrypt(HSM *h, uint32_t tag, IBE_ciphertext *c[PUNC_ENC_REPL], uint8_t msg[IBE_MSG_LEN]);

int HSM_ElGamalGetPk(HSM *h);
int HSM_ElGamalEncrypt(HSM *h, BIGNUM *msg, ElGamal_ciphertext *c);
int HSM_ElGamalDecrypt(HSM *h, BIGNUM *msg, ElGamal_ciphertext *c);

int HSM_AuthMPCDecrypt1Commit(HSM *h, uint8_t *dCommit, uint8_t *eCommit, uint32_t tag, IBE_ciphertext *c[PUNC_ENC_REPL], uint8_t *aesCt, uint8_t *aesCtTag, ShamirShare *pinShare);
int HSM_AuthMPCDecrypt1Open(HSM *h, ShamirShare *dShare, ShamirShare *eShare, uint8_t *dOpening, uint8_t *eOpening, uint8_t **dMacs, uint8_t **eMacs, uint8_t **dCommits, uint8_t **eCommits, uint8_t *hsms, uint8_t reconstructIndex);
int HSM_AuthMPCDecrypt2Commit(HSM *h, uint8_t *resultCommit, BIGNUM *d, BIGNUM *e, ShamirShare **dShares, ShamirShare **eShares, uint8_t **dOpenings, uint8_t **eOpenings, uint8_t **dMacs, uint8_t **eMacs, uint8_t *hsms);
int HSM_AuthMPCDecrypt2Open(HSM *h, ShamirShare *resultShare, uint8_t *resultOpening, uint8_t **resultMacs, uint8_t **resultCommits, uint8_t *hsms, uint8_t reconstructIndex);
int HSM_AuthMPCDecrypt3(HSM *h, ShamirShare *msg, BIGNUM *result, ShamirShare **resultShares, uint8_t **resultOpenings, uint8_t **resultMacs, uint8_t *hsms, uint8_t reconstructIndex);

int HSM_LogProof(HSM *h, ElGamal_ciphertext *c, uint8_t *hsms, LogProof *p);

/* Run microbenchmarks. */
int HSM_MicroBench(HSM *h);
int HSM_LongMsg(HSM *h);
int HSM_Mac(HSM *h1, HSM *h2, uint8_t *nonce, uint8_t *mac);

int HSM_Baseline(HSM *h, uint8_t *key, ElGamal_ciphertext *c, uint8_t *aesCt, uint8_t *pinHash);
#ifdef __cplusplus
}
#endif

#endif  // __DET2F_H_INCLUDED__
