#ifndef _LOG_H_
#define _LOG_H_

#include <openssl/sha.h>
#include "elgamal.h"

#define PROOF_LEVELS 30
#define SIG_LEN 64

typedef struct {
    uint8_t merkleProof[PROOF_LEVELS][SHA256_DIGEST_LENGTH];
    uint8_t opening[32];
    uint8_t rootSig[SIG_LEN];
} LogProof;

LogProof *LogProof_new();
void LogProof_free(LogProof *p);

int Log_Init(Params *params, uint8_t *logPk);
int Log_Prove(Params *params, LogProof *p, ElGamal_ciphertext *c, uint8_t *hsms);

#endif
