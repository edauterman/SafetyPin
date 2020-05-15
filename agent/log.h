#ifndef _LOG_H_
#define _LOG_H_

#include <openssl/sha.h>
#include "elgamal.h"
#include "merkle_tree.h"
//#include "hsm.h"

#define PROOF_LEVELS 30
#define PROOF_LEAVES  536870912
//#define NUM_USERS  1073741824
//#define NUM_USERS  131072
#define NUM_USERS 268435456
//#define NUM_USERS 67108864 
//#define NUM_USERS  268435456
//#define NUM_USERS  536870912
#define ROOT_PROOF_LEVELS 16
#define ROOT_PROOF_LEAVES 65536
#define SIG_LEN 64
#define NUM_TRANSITIONS 1048576   // should be TOTAL_HSMS * CHUNK_SIZE
//#define NUM_TRANSITIONS 4194303   // should be TOTAL_HSMS * CHUNK_SIZE

typedef struct {
    uint8_t merkleProof[PROOF_LEVELS][SHA256_DIGEST_LENGTH];
    uint8_t opening[32];
    uint8_t rootSig[SIG_LEN];
} LogProof;

typedef struct {
    MerkleProof *oldProof1;
    MerkleProof *oldProof2;
    MerkleProof *newProof;
    int id; 
} TransitionProof;

typedef struct {
    Node *rootsTree;
    TransitionProof tProofs[NUM_TRANSITIONS];
} LogState;

/*
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
*/

LogProof *LogProof_new();
void LogProof_free(LogProof *p);

int Log_Init(Params *params);
int Log_GetPk(Params *params, uint8_t *logPk);
int Log_Prove(Params *params, LogProof *p, ElGamal_ciphertext *c, uint8_t *hsms);

LogState *Log_RunSetup();

/*int Log_CreateMerkleTree(MerkleTree *t);
int Log_CreateRootMerkleTree(RootMerkleTree *t, uint8_t *leafValue);
int Log_GenerateRootProof(LogRootProof *p, RootMerkleTree *tRoot, int index);
int Log_GenerateSingleTransitionProof(LogTransProof *p, MerkleTree *tOld, MerkleTree *tNew, int index);
*/
#endif
