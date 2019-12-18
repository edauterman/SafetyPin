#ifndef __HSM_H_INCLUDED__
#define __HSM_H_INCLUDED__

#include <openssl/sha.h>
#include <pthread.h>

#include "ibe.h"
#include "bls12_381/bls12_381.h"
#include "params.h"
#include "u2f.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEY_LEN 32
#define LEAF_LEN (2 * KEY_LEN)
#define CT_LEN (2 * KEY_LEN + 32)

#define PUNC_ENC_REPL 3 

#define RESPONSE_BUFFER_SIZE 4096

#define NUM_LEAVES 16384
//#define NUM_LEAVES NUM_SUB_LEAVES
//#define NUM_LEAVES 256
#define LEVELS 15 // log2(NUM_LEAVES) + 1
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

#define LEVEL_0 0
#define LEVEL_1 1
#define LEVEL_2 2
#define LEVEL_DONE -1

#define LEVEL_1_OFFSET ((16384 + 8192 + 4096 + 2048 + 1024) * CT_LEN)
#define LEVEL_2_OFFSET (LEVEL_1_OFFSET + ((512 + 256 + 128 + 64 + 32) * CT_LEN))
#define LEVEL_1_NUM_LEAVES 512
//#define LEVEL_1_NUM_LEAVES 1024 
#define LEVEL_2_NUM_LEAVES 16
//#define LEVEL_2_NUM_LEAVES 32

using namespace std;

typedef struct{
    uint8_t mpk[BASEFIELD_SZ_G2];
} HSM_MPK_RESP;

typedef struct{
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];
} HSM_SETUP_RESP;

typedef struct{
    uint16_t index;
    uint8_t cts[LEVELS][CT_LEN];
    //uint16_t index;
} HSM_RETRIEVE_REQ;

typedef struct{
    uint8_t leaf[CT_LEN];
} HSM_RETRIEVE_RESP;

typedef struct {
    uint16_t index;
    uint8_t cts[KEY_LEVELS][CT_LEN];
} HSM_PUNCTURE_REQ;

typedef struct {
    uint8_t cts[KEY_LEVELS][CT_LEN];
} HSM_PUNCTURE_RESP;

typedef struct {
    uint16_t index;
    uint8_t treeCts[LEVELS][CT_LEN];
    uint8_t ibeCt[IBE_CT_LEN];
} HSM_DECRYPT_REQ;

typedef struct {
    uint8_t msg[IBE_MSG_LEN];
} HSM_DECRYPT_RESP;

typedef struct {
    uint16_t index;
    uint8_t treeCts[LEVELS][CT_LEN];
    uint8_t ibeCt[IBE_CT_LEN];
    uint8_t pinHash[SHA256_DIGEST_LENGTH];
} HSM_AUTH_DECRYPT_REQ;

typedef struct {
    uint8_t msg[IBE_MSG_LEN];
    uint8_t newCts[KEY_LEVELS][CT_LEN];
} HSM_AUTH_DECRYPT_RESP;

typedef struct {
    uint8_t msk[KEY_LEN];
    uint8_t hmacKey[KEY_LEN];
} HSM_TEST_SETUP_REQ;

/* ---------------------------------- */

typedef struct {
    struct U2Fob *device;
    Params *params;
    uint8_t cts[TREE_SIZE][CT_LEN];
    embedded_pairing_bls12_381_g2_t mpk;
    pthread_mutex_t m;
} HSM;

HSM *HSM_new();
void HSM_free(HSM *h);

/* Setup */
int HSM_GetMpk(HSM *h);
int HSM_Setup(HSM *h);
int HSM_SmallSetup(HSM *h);
int HSM_TestSetup(HSM *h);

/* Testing tree. */
int HSM_Retrieve(HSM *h, uint16_t index);
int HSM_Puncture(HSM *h, uint16_t index);

/* Encryption/decryption. Decrypt only for testing. Only use AuthDecrypt. */
int HSM_Encrypt(HSM *h, uint16_t tag, uint8_t *msg, int msgLen, IBE_ciphertext *c[PUNC_ENC_REPL]);
int HSM_Decrypt(HSM *h, uint16_t tag, IBE_ciphertext *c[PUNC_ENC_REPL], uint8_t *msg, int msgLen);
int HSM_AuthDecrypt(HSM *h, uint16_t tag, IBE_ciphertext *c[PUNC_ENC_REPL], uint8_t *msg, int msgLen, uint8_t *pinHash);

#ifdef __cplusplus
}
#endif

#endif  // __DET2F_H_INCLUDED__
