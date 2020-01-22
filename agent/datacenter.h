#ifndef _DATACENTER_H
#define _DATACENTER_H

#include "hsm.h"
#include "params.h"
#include "punc_enc.h"

#define NUM_HSMS 1 
#define HSM_GROUP_SIZE 1
//#define HSM_GROUP_SIZE 5
#define HSM_THRESHOLD_SIZE 1
//#define HSM_THRESHOLD_SIZE 3
#define PIN_LEN 10

typedef struct {
    HSM *hsms[NUM_HSMS];
} Datacenter;

typedef struct {
    IBE_ciphertext *recoveryCts[HSM_GROUP_SIZE][PUNC_ENC_REPL];
    BIGNUM *s;
    IBE_ciphertext *saltCts[HSM_GROUP_SIZE][PUNC_ENC_REPL];
} RecoveryCiphertext;

RecoveryCiphertext *RecoveryCiphertext_new();
void RecoveryCiphertext_free(RecoveryCiphertext *c);

Datacenter *Datacenter_new();
void Datacenter_free(Datacenter *d);
int Datacenter_init(Datacenter *d);

int Datacenter_Setup(Datacenter *d);
int Datacenter_SmallSetup(Datacenter *d);
int Datacenter_TestSetup(Datacenter *d);
int Datacenter_Save(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, uint8_t pin[PIN_LEN], RecoveryCiphertext *c);
int Datacenter_Recover(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, uint8_t pin[PIN_LEN], RecoveryCiphertext *c);
#endif
