#ifndef _DATACENTER_H
#define _DATACENTER_H

#include "elgamal_shamir.h"
#include "hsm.h"
#include "params.h"
#include "punc_enc.h"

typedef struct {
    int numHsms;
    int hsmGroupSize;
    int hsmThresholdSize;
    int chunkSize;
    HSM **hsms;
    uint8_t puncMeasureWithPubKey;
    uint8_t puncMeasureWithSymKey;
} Datacenter;

typedef struct {
    ElGamal_ciphertext ***recoveryCts;
    BIGNUM *r;
    BIGNUM *s;
    uint8_t iv[AES256_IV_LEN];
    uint8_t *ct;
    LocationHidingCt *locationHidingCt;
    uint8_t **aesCts;
    uint8_t **aesCtTags;
} RecoveryCiphertext;

RecoveryCiphertext *RecoveryCiphertext_new(Params *params, int hsmGroupSize);
void RecoveryCiphertext_free(RecoveryCiphertext *c, int hsmGroupSize);

Datacenter *Datacenter_new(int numHsms, int hsmGroupSize, int chunkSize);
void Datacenter_free(Datacenter *d);
int Datacenter_init(Datacenter *d);

int Datacenter_TestSetup(Datacenter *d);
int Datacenter_VirtualSetup(Datacenter *d);

void Datacenter_SetPuncMeasureParams(Datacenter *d, uint8_t puncMeasureWithPubKey, uint8_t puncMeasureWithSymKey);

int Datacenter_Save(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, BIGNUM *pin, RecoveryCiphertext *c);
int Datacenter_GenerateLogProofs(Datacenter *d, Params *params, LogProof **logProofs, BIGNUM *pin, RecoveryCiphertext *c);
int Datacenter_Recover(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, BIGNUM *pin, RecoveryCiphertext *c, LogProof **logProofs);

int Datacenter_LogEpochVerification(Datacenter *d, LogState *state);
#endif
