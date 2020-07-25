#ifndef _LOG_H_
#define _LOG_H_

#include <openssl/sha.h>
#include "elgamal.h"
#include "merkle_tree.h"
//#include "hsm.h"

#define PROOF_LEVELS 30
#define PROOF_LEAVES  536870912
#define NUM_USERS  131072
//#define NUM_USERS  536870912
#define ROOT_PROOF_LEVELS 16
#define ROOT_PROOF_LEAVES 65536
#define SIG_LEN 64
#define NUM_TRANSITIONS 65535   // should be TOTAL_HSMS * CHUNK_SIZE

typedef struct {
    uint8_t merkleProof[PROOF_LEVELS][SHA256_DIGEST_LENGTH];
    uint8_t opening[32];
    uint8_t rootSig[SIG_LEN];
} LogProof;

typedef struct {
    MerkleProof *oldProof;
    MerkleProof *newProof;
    int id; 
} TransitionProof;

typedef struct {
    Node *rootsTree;
    TransitionProof tProofs[NUM_TRANSITIONS];
} LogState;

LogProof *LogProof_new();
void LogProof_free(LogProof *p);

int Log_Init(Params *params);
int Log_GetPk(Params *params, uint8_t *logPk);
int Log_Prove(Params *params, LogProof *p, ElGamal_ciphertext *c, uint8_t *hsms);

LogState *Log_RunSetup();

#endif
