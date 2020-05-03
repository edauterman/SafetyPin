#ifndef _LOG_H_
#define _LOG_H_

#include <openssl/sha.h>
#include "elgamal.h"

#define PROOF_LEVELS 30
#define PROOF_LEAVES  536870912
#define ROOT_PROOF_LEVELS 16
#define ROOT_PROOF_LEAVES 65536
#define SIG_LEN 64

typedef struct {
    uint8_t merkleProof[PROOF_LEVELS][SHA256_DIGEST_LENGTH];
    uint8_t opening[32];
    uint8_t rootSig[SIG_LEN];
} LogProof;

typedef struct {
    uint8_t nodes[PROOF_LEVELS][PROOF_LEAVES][SHA256_DIGEST_LENGTH];
} MerkleTree;

typedef struct {
    uint8_t nodes[ROOT_PROOF_LEVELS][ROOT_PROOF_LEAVES][SHA256_DIGEST_LENGTH];
} RootMerkleTree;

typedef struct {
    uint8_t rootP[ROOT_PROOF_LEVELS][SHA256_DIGEST_LENGTH];
} LogRootProof;

typedef struct {
    uint8_t oldRoot[SHA256_DIGEST_LENGTH];
    uint8_t newRoot[SHA256_DIGEST_LENGTH];
    uint8_t firstOldLeaf[SHA256_DIGEST_LENGTH];
    uint8_t secondOldLeaf[SHA256_DIGEST_LENGTH];
    uint8_t newLeaf[SHA256_DIGEST_LENGTH];
    uint8_t firstOldP[PROOF_LEVELS][SHA256_DIGEST_LENGTH];
    uint8_t secondOldP[PROOF_LEVELS][SHA256_DIGEST_LENGTH];
    uint8_t newP[PROOF_LEVELS][SHA256_DIGEST_LENGTH];
} LogTransProof;

LogProof *LogProof_new();
void LogProof_free(LogProof *p);

int Log_Init(Params *params);
int Log_GetPk(Params *params, uint8_t *logPk);
int Log_Prove(Params *params, LogProof *p, ElGamal_ciphertext *c, uint8_t *hsms);
int Log_CreateMerkleTree(MerkleTree *t);
int Log_CreateRootMerkleTree(RootMerkleTree *t, uint8_t *leafValue);
int Log_GenerateRootProof(LogRootProof *p, RootMerkleTree *tRoot, int index);
int Log_GenerateSingleTransitionProof(LogTransProof *p, MerkleTree *tOld, MerkleTree *tNew, int index);

#endif
