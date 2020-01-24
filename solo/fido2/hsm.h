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

#define COMPRESSED_PT_SZ 33
#define ELGAMAL_CT_LEN (2 * COMPRESSED_PT_SZ)
#define ELGAMAL_PT_LEN COMPRESSED_PT_SZ
#define ELGAMAL_PK_LEN COMPRESSED_PT_SZ

#define NUM_LEAVES 524288
//#define NUM_LEAVES 16384 
//#define NUM_LEAVES 65536 
//#define NUM_LEAVES NUM_SUB_LEAVES
//#define LEVELS 5    //log2(NUM_LEAVES) + 1
#define LEVELS 20    //log2(NUM_LEAVES) + 1
//#define LEVELS 15    //log2(NUM_LEAVES) + 1
#define KEY_LEVELS (LEVELS - 1)
#define SUB_TREE_LEVELS 5
// SUB_TREE_SIZE before had CT_LEN instead of 4 * KEY_LEN, but then CT_LEN changed to have tag
#define SUB_TREE_SIZE ((CTAP_RESPONSE_BUFFER_SIZE / (4 * KEY_LEN)) - 1)
#define NUM_SUB_LEAVES ((SUB_TREE_SIZE + 1) / 2)
#define NUM_INTERMEDIATE_KEYS (NUM_SUB_LEAVES * 2) 

#define NONCE_LEN 16 

#define LEVEL_0 0
#define LEVEL_1 1
#define LEVEL_2 2
#define LEVEL_3 3

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

struct hsm_mpk {
    uint8_t mpk[BASEFIELD_SZ_G2];
};

struct hsm_setup {
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];
};

struct hsm_retrieve_request {
    uint32_t index;
    uint8_t cts[LEVELS][CT_LEN];
    //uint16_t index;
};

struct hsm_puncture_request  {
    uint32_t index;
    uint8_t cts[KEY_LEVELS][CT_LEN];
};

struct hsm_decrypt_request {
    uint32_t index;
    uint8_t treeCts[LEVELS][CT_LEN];
    uint8_t ibeCt[IBE_CT_LEN];
};

struct hsm_decrypt_response {
    uint8_t msg[IBE_MSG_LEN];
};

struct hsm_auth_decrypt_request {
    uint32_t index;
    uint8_t treeCts[LEVELS][CT_LEN];
    uint8_t ibeCt[IBE_CT_LEN];
    uint8_t pinHash[SHA256_DIGEST_LEN];
};

struct hsm_auth_decrypt_response {
    uint8_t msg[IBE_MSG_LEN];
    uint8_t newCts[KEY_LEVELS][CT_LEN];
};

struct hsm_test_setup_request {
    uint8_t msk[KEY_LEN];
    uint8_t hmacKey[KEY_LEN];
};

struct hsm_long_request {
//    uint8_t buf[1024];
    uint8_t buf[CTAP_RESPONSE_BUFFER_SIZE- 16];
};

struct hsm_long_response {
//    uint8_t buf[1024];
    uint8_t buf[CTAP_RESPONSE_BUFFER_SIZE - 16];
};

struct hsm_mac_request {
    uint8_t nonce[NONCE_LEN];
};

struct hsm_mac_response {
    uint8_t mac[SHA256_DIGEST_LEN];
};

struct hsm_get_nonce_response {
    uint8_t nonce[NONCE_LEN];
};

struct hsm_ret_mac_request {
    uint8_t mac[SHA256_DIGEST_LEN];
};

struct hsm_elgamal_pk_response {
    uint8_t pk[ELGAMAL_PK_LEN];
};

struct hsm_elgamal_decrypt_request {
    uint8_t ct[ELGAMAL_CT_LEN];
};

struct hsm_elgamal_decrypt_response {
    uint8_t msg[ELGAMAL_PT_LEN];
};

uint8_t pingKey[KEY_LEN];

void HSM_Handle(uint8_t msgType, uint8_t *in, uint8_t *out, int *outLen);
int HSM_GetReqLenFromMsgType(uint8_t msgType);

int HSM_GetMpk(uint8_t *out, int *outLen);
int HSM_Setup(uint8_t *out, int *outLen);
int HSM_SmallSetup(uint8_t *out, int *outLen);
int HSM_TestSetup(struct hsm_test_setup_request *req, uint8_t *out, int *outLen);
int HSM_Retrieve(struct hsm_retrieve_request *req, uint8_t *out, int *outLen);
int HSM_Puncture(struct hsm_puncture_request *req, uint8_t *out, int *outLen);
int HSM_Decrypt(struct hsm_decrypt_request *req, uint8_t *out, int *outLen);
int HSM_AuthDecrypt(struct hsm_auth_decrypt_request *req, uint8_t *out, int *outLen);
int HSM_MicroBench(uint8_t *out, int *outLen);
int HSM_LongMsg(struct hsm_long_request *req, uint8_t *out, int *outLen);
int HSM_Mac(struct hsm_mac_request *req, uint8_t *out, int *outLen);
int HSM_GetNonce(uint8_t *out, int *outLen);
int HSM_RetMac(struct hsm_ret_mac_request *req, uint8_t *out, int *outLen);
int HSM_ElGamalPk(uint8_t *out, int *outLen);
int HSM_ElGamalDecrypt(struct hsm_elgamal_decrypt_request *req, uint8_t *out, int *outLen);
#endif
