#ifndef _HSM_H_
#define _HSM_H_

#include <stdint.h>
#include "ctaphid.h"
#include "ibe.h"

#define KEY_LEN 32
#define CT_LEN 64

#define NUM_LEAVES NUM_SUB_LEAVES
#define LEVELS 6    //log2(NUM_LEAVES) + 1
#define KEY_LEVELS (LEVELS - 1)
#define SUB_TREE_SIZE ((CTAP_RESPONSE_BUFFER_SIZE / CT_LEN) - 1)
#define NUM_SUB_LEAVES ((SUB_TREE_SIZE + 1) / 2)

#define HSM_SETUP    0x70
#define HSM_RETRIEVE 0x71
#define HSM_PUNCTURE 0x72
#define HSM_DECRYPT  0x73
#define HSM_MPK      0x74

struct hsm_mpk {
    uint8_t mpk[BASEFIELD_SZ_G2];
};

struct hsm_setup {
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];
};

struct hsm_retrieve_request {
    uint16_t index;
    uint8_t cts[LEVELS][CT_LEN];
    //uint16_t index;
};

struct hsm_puncture_request  {
    uint16_t index;
    uint8_t cts[KEY_LEVELS][CT_LEN];
};

struct hsm_decrypt_request {
    uint16_t index;
    uint8_t treeCts[KEY_LEVELS][CT_LEN];
    uint8_t ibeCt[IBE_CT_LEN];
};

struct hsm_decrypt_response {
    uint8_t msg[IBE_MSG_LEN];
};

int HSM_GetMpk();
int HSM_Setup();
int HSM_Retrieve(struct hsm_retrieve_request *req);
int HSM_Puncture(struct hsm_puncture_request *req);
int HSM_Decrypt(struct hsm_decrypt_request *req);

#endif
