#ifndef _DATACENTER_H
#define _DATACENTER_H

#include "elgamal_shamir.h"
#include "hsm.h"
#include "params.h"
#include "punc_enc.h"

#define NUM_HSMS 1
#define HSM_GROUP_SIZE 3
//#define HSM_GROUP_SIZE 5
#define HSM_THRESHOLD_SIZE 1
//#define HSM_THRESHOLD_SIZE 3
#define PIN_LEN 10

typedef struct {
    HSM *hsms[NUM_HSMS];
} Datacenter;

typedef struct {
    IBE_ciphertext *recoveryCts[HSM_GROUP_SIZE][PUNC_ENC_REPL];
    BIGNUM *r;
    BIGNUM *s;
//    IBE_ciphertext *saltCts[HSM_GROUP_SIZE][PUNC_ENC_REPL];
    uint8_t iv[AES256_IV_LEN];
    uint8_t ct[HSM_GROUP_SIZE * PUNC_ENC_REPL * IBE_CT_LEN];
    ElGamalCtShare *elGamalCts[HSM_GROUP_SIZE];
    uint8_t aesCts[HSM_GROUP_SIZE][AES_CT_LEN];
    uint8_t aesCtTags[HSM_GROUP_SIZE][SHA256_DIGEST_LENGTH];
} RecoveryCiphertext;

RecoveryCiphertext *RecoveryCiphertext_new(Params *params);
void RecoveryCiphertext_free(RecoveryCiphertext *c);

Datacenter *Datacenter_new();
void Datacenter_free(Datacenter *d);

int Datacenter_VirtualSetup(Datacenter *d);

int Datacenter_Save(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, BIGNUM *pin, RecoveryCiphertext *c);
#endif