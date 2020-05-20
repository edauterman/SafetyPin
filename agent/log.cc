#include <stdlib.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "common.h"
#include "elgamal.h"
#include "log.h"
#include "hsm.h"
#include "params.h"
#include "merkle_tree.h"

EC_KEY *logKey;

LogProof *LogProof_new() {
    return (LogProof *)malloc(sizeof(LogProof));
}

void LogProof_free(LogProof *p) {
    free(p);
}

int Log_Init(Params *params) {
    int rv;

    CHECK_A (logKey = EC_KEY_new());
    CHECK_C (EC_KEY_set_group(logKey, params->group));
    CHECK_C (EC_KEY_generate_key(logKey));

cleanup:
    return rv;
}

int Log_GetPk(Params *params, uint8_t *logPk) {
    int rv;
    const EC_POINT *pk;

    pk = EC_KEY_get0_public_key(logKey);
    Params_pointToBytes(params, logPk, pk);

cleanup:
    return rv;
}

int Log_Prove(Params *params, LogProof *p, ElGamal_ciphertext *c, uint8_t *hsms) {
    int rv;
    uint8_t curr[SHA256_DIGEST_LENGTH];
    uint8_t buf[ELGAMAL_CT_LEN];
    unsigned int sigLen;
    EVP_MD_CTX *mdctx = NULL;
    const BIGNUM *r;
    const BIGNUM *s;
    ECDSA_SIG *sig = NULL;

    CHECK_C (RAND_bytes(p->opening, FIELD_ELEM_LEN));
    ElGamal_Marshal(params, buf, c);

    CHECK_A (mdctx = EVP_MD_CTX_create());
    CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
    CHECK_C (EVP_DigestUpdate(mdctx, buf, ELGAMAL_CT_LEN));
    CHECK_C (EVP_DigestUpdate(mdctx, hsms, HSM_GROUP_SIZE));
    CHECK_C (EVP_DigestUpdate(mdctx, p->opening, FIELD_ELEM_LEN));
    CHECK_C (EVP_DigestFinal_ex(mdctx, curr, NULL));

    for (int i = 0; i < PROOF_LEVELS; i++) {
        /* Choose neighbor. */
        CHECK_C (RAND_bytes(p->merkleProof[i], SHA256_DIGEST_LENGTH));
        /* Calculate parent. */
        CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
        CHECK_C (EVP_DigestUpdate(mdctx, curr, SHA256_DIGEST_LENGTH));
        CHECK_C (EVP_DigestUpdate(mdctx, p->merkleProof[i], SHA256_DIGEST_LENGTH));
        CHECK_C (EVP_DigestFinal_ex(mdctx, curr, NULL));
    }

    CHECK_A (sig = ECDSA_do_sign(curr, SHA256_DIGEST_LENGTH, logKey));
    //ECDSA_SIG_get0(sig, &r, &s);
    memset(p->rootSig, 0, 2 * FIELD_ELEM_LEN);
    //BN_bn2bin(r, p->rootSig + FIELD_ELEM_LEN - BN_num_bytes(r));
    //BN_bn2bin(s, p->rootSig + 2 * FIELD_ELEM_LEN - BN_num_bytes(s));
    BN_bn2bin(sig->r, p->rootSig + FIELD_ELEM_LEN - BN_num_bytes(sig->r));
    BN_bn2bin(sig->s, p->rootSig + 2 * FIELD_ELEM_LEN - BN_num_bytes(sig->s));

cleanup:
    if (mdctx) EVP_MD_CTX_destroy(mdctx);
    return rv;
}

LogState *Log_RunSetup() {
    LogState *state = (LogState *)malloc(sizeof(LogState));

    uint8_t **leafValues = (uint8_t **)malloc(NUM_USERS * sizeof(uint8_t *));
    uint64_t *leafIds = (uint64_t *)malloc(NUM_USERS * sizeof(uint64_t));
    uint8_t **rootHashes = (uint8_t **)malloc((NUM_TRANSITIONS + 1) * sizeof(uint8_t *));
    uint64_t *rootIds = (uint64_t *)malloc((NUM_TRANSITIONS + 1) * sizeof(uint64_t));
    for (uint64_t i = 0; i < NUM_USERS; i++) {
        leafValues[i] = (uint8_t *)malloc(SHA256_DIGEST_LENGTH);
        memset(leafValues[i], 0xff, SHA256_DIGEST_LENGTH);
        leafIds[i] = i;
    }
    printf("Going to start creating Merkle tree\n");
    Node *head = MerkleTree_CreateTree(leafIds, leafValues, NUM_USERS);
    rootHashes[0] = (uint8_t *)malloc(SHA256_DIGEST_LENGTH);
    memcpy(rootHashes[0], head->hash, SHA256_DIGEST_LENGTH);
    rootIds[0] = 0;

    for (uint64_t i = 0; i < NUM_TRANSITIONS; i++) {
        uint64_t id = i + NUM_USERS;
        state->tProofs[i].id = id;
        state->tProofs[i].oldProof = MerkleTree_GetEmptyProof(head, id);
        MerkleTree_InsertLeaf(head, id, leafValues[0]);
        state->tProofs[i].newProof = MerkleTree_GetProof(head, id);
        rootHashes[i+1] = (uint8_t *)malloc(SHA256_DIGEST_LENGTH);
        rootIds[i+1] = i+1;
        printf("root ids = %ld\n", rootIds[i]);
        memcpy(rootHashes[i+1], head->hash, SHA256_DIGEST_LENGTH);
    }

    state->rootsTree = MerkleTree_CreateTree(rootIds, rootHashes, NUM_TRANSITIONS + 1);
    printf("rootsTree ids = (%ld, %ld, %ld)\n", state->rootsTree->leftID, state->rootsTree->midID, state->rootsTree->rightID);
    printf("rootHashes[0] = ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", rootHashes[0][i]);
    printf("\n");
    printf("head for proof 0 = ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", state->tProofs[0].oldProof->head[i]);
    printf("\n");
    return state;
}
/*
int Log_CreateMerkleTree(MerkleTree *t) {
    int rv;
    EVP_MD_CTX *mdctx = NULL;

    mdctx = EVP_MD_CTX_create();

    for (int i = 0; i < PROOF_LEAVES; i++) {
        RAND_bytes(t->nodes[0][i], SHA256_DIGEST_LENGTH);
    }
    int numLeaves = PROOF_LEAVES;
    for (int i = 1; i < PROOF_LEVELS; i++) {
        for (int j = 0; j < numLeaves; j++) {
            CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
            CHECK_C (EVP_DigestUpdate(mdctx, t->nodes[i-1][j], SHA256_DIGEST_LENGTH));
            CHECK_C (EVP_DigestUpdate(mdctx, t->nodes[i-1][j+1], SHA256_DIGEST_LENGTH));
            CHECK_C (EVP_DigestUpdate(mdctx, t->nodes[i][j/2], SHA256_DIGEST_LENGTH));
        }
    }

cleanup:
    if (mdctx) EVP_MD_CTX_destroy(mdctx);
    return rv;
}

int Log_CreateRootMerkleTree(RootMerkleTree *t, uint8_t *leafValue) {
    int rv;
    EVP_MD_CTX *mdctx = NULL;

    mdctx = EVP_MD_CTX_create();

    for (int i = 0; i < ROOT_PROOF_LEAVES; i++) {
        memcpy(t->nodes[0][i], leafValue, SHA256_DIGEST_LENGTH);
    }
    int numLeaves = ROOT_PROOF_LEAVES;
    for (int i = 1; i < ROOT_PROOF_LEVELS; i++) {
        for (int j = 0; j < numLeaves; j++) {
            CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
            CHECK_C (EVP_DigestUpdate(mdctx, t->nodes[i-1][j], SHA256_DIGEST_LENGTH));
            CHECK_C (EVP_DigestUpdate(mdctx, t->nodes[i-1][j+1], SHA256_DIGEST_LENGTH));
            CHECK_C (EVP_DigestUpdate(mdctx, t->nodes[i][j/2], SHA256_DIGEST_LENGTH));
        }
    }

cleanup:
    if (mdctx) EVP_MD_CTX_destroy(mdctx);
    return rv;
}

int Log_GenerateRootProof(LogRootProof *p, RootMerkleTree *tRoot, int index) {
    int rv;
  
    int currIndex = index;
    for (int i = 0; i < ROOT_PROOF_LEVELS; i++) {
        if (currIndex % 2 == 0) {
            memcpy(p->rootP[i], tRoot->nodes[i][currIndex+1], SHA256_DIGEST_LENGTH);
        } else {
            memcpy(p->rootP[i], tRoot->nodes[i][currIndex-1], SHA256_DIGEST_LENGTH);
        }
        currIndex /= 2;
    }
}

int Log_GenerateSingleTransitionProof(LogTransProof *p, MerkleTree *tOld, MerkleTree *tNew, int index) {
    int rv;
  
    /* Proof for index in old tree. */ 
/*    int currIndex = index;
    memcpy(p->firstOldLeaf, tOld->nodes[0][currIndex], SHA256_DIGEST_LENGTH);
    for (int i = 0; i < PROOF_LEVELS; i++) {
        if (currIndex % 2 == 0) {
            memcpy(p->firstOldP[i], tOld->nodes[i][currIndex+1], SHA256_DIGEST_LENGTH);
        } else {
            memcpy(p->firstOldP[i], tOld->nodes[i][currIndex-1], SHA256_DIGEST_LENGTH);
        }
        currIndex /= 2;
    }

    /* Proof for index in old tree. */ 
/*    currIndex = index + 1;
    memcpy(p->secondOldLeaf, tOld->nodes[0][currIndex], SHA256_DIGEST_LENGTH);
    for (int i = 0; i < PROOF_LEVELS; i++) {
        if (currIndex % 2 == 0) {
            memcpy(p->secondOldP[i], tOld->nodes[i][currIndex+1], SHA256_DIGEST_LENGTH);
        } else {
            memcpy(p->secondOldP[i], tOld->nodes[i][currIndex-1], SHA256_DIGEST_LENGTH);
        }
        currIndex /= 2;
    }

    /* Proof for index in old tree. */ 
/*    currIndex = index;
    memcpy(p->newLeaf, tNew->nodes[0][currIndex], SHA256_DIGEST_LENGTH);
    for (int i = 0; i < PROOF_LEVELS; i++) {
        if (currIndex % 2 == 0) {
            memcpy(p->newP[i], tNew->nodes[i][currIndex+1], SHA256_DIGEST_LENGTH);
        } else {
            memcpy(p->newP[i], tNew->nodes[i][currIndex-1], SHA256_DIGEST_LENGTH);
        }
        currIndex /= 2;
    }

    memcpy(p->oldRoot, tOld->nodes[PROOF_LEVELS - 1][0], SHA256_DIGEST_LENGTH);
    memcpy(p->newRoot, tNew->nodes[PROOF_LEVELS - 1][0], SHA256_DIGEST_LENGTH);

cleanup:
    return rv;
}*/
