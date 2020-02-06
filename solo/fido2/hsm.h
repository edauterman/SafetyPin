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

//#define HSM_GROUP_SIZE 3
//#define HSM_GROUP_SIZE 6
#define HSM_GROUP_SIZE 100
//#define HSM_THRESHOLD_SIZE 1
//#define HSM_THRESHOLD_SIZE 2
#define HSM_THRESHOLD_SIZE 34 
#define NUM_HSMS 1
//#define NUM_HSMS 100

#define NUM_ATTEMPTS 1

#define AES_CT_LEN ((3 * FIELD_ELEM_LEN) + (3 * NUM_ATTEMPTS * FIELD_ELEM_LEN))

#define COMPRESSED_PT_SZ 33
#define FIELD_ELEM_LEN 32
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
#define HSM_AUTH_MPC_DECRYPT_1_COMMIT   0x80
#define HSM_AUTH_MPC_DECRYPT_1_OPEN     0x81
#define HSM_AUTH_MPC_DECRYPT_2_COMMIT   0x82
#define HSM_AUTH_MPC_DECRYPT_2_OPEN     0x83
#define HSM_AUTH_MPC_DECRYPT_3          0x84
#define HSM_SET_MAC_KEYS                0x85
#define HSM_SET_PARAMS                  0x86

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

struct hsm_set_mac_keys_request {
    uint8_t macKeys[100][KEY_LEN];
};

struct hsm_auth_mpc_decrypt_1_commit_request {
    uint32_t index;
    uint8_t treeCts[LEVELS][CT_LEN];
    uint8_t ibeCt[IBE_CT_LEN];
    uint8_t aesCt[AES_CT_LEN];
    uint8_t aesCtTag[SHA256_DIGEST_LEN];
    uint8_t pinShare[FIELD_ELEM_LEN];
};

struct hsm_auth_mpc_decrypt_1_open_request {
    uint8_t dCommits[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN];
    uint8_t eCommits[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN];
    uint8_t hsms[HSM_GROUP_SIZE];
};

struct hsm_auth_mpc_decrypt_2_commit_request {
    uint8_t d[FIELD_ELEM_LEN];
    uint8_t e[FIELD_ELEM_LEN];
    uint8_t dShares[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN];
    uint8_t eShares[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN];
    uint8_t dOpenings[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN];
    uint8_t eOpenings[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN];
    uint8_t dMacs[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN];
    uint8_t eMacs[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN];
    uint8_t hsms[HSM_GROUP_SIZE];
};

struct hsm_auth_mpc_decrypt_2_open_request {
    uint8_t resultCommits[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN];
    uint8_t hsms[HSM_GROUP_SIZE];
};

struct hsm_auth_mpc_decrypt_3_request {
    uint8_t result[FIELD_ELEM_LEN];
    uint8_t resultShares[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN];
    uint8_t resultOpenings[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN];
    uint8_t resultMacs[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN];
    uint8_t hsms[HSM_GROUP_SIZE];
};

struct hsm_set_params_request {
    uint8_t groupSize;
    uint8_t thresholdSize;
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
int HSM_SetMacKeys(struct hsm_set_mac_keys_request *req, uint8_t *out, int *outLen);
int HSM_AuthMPCDecrypt_1(struct hsm_auth_mpc_decrypt_1_request *req, uint8_t *out, int *outLen);
int HSM_AuthMPCDecrypt_2(struct hsm_auth_mpc_decrypt_2_request *req, uint8_t *out, int *outLen);
int HSM_AuthMPCDecrypt_3(struct hsm_auth_mpc_decrypt_3_request *req, uint8_t *out, int *outLen);

#endif
