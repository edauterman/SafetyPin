#ifndef _HSM_H_
#define _HSM_H_

#include <stdint.h>
#include "ctaphid.h"

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

int HSM_Setup();
int HSM_Retrieve(struct hsm_retrieve_request *req);
int HSM_Puncture(struct hsm_puncture_request *req);

#endif
