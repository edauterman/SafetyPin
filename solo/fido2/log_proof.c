#include <stdlib.h>

#include "hsm.h"
#include "log_proof.h"
#include "uECC.h"

uint8_t logPk[COMPRESSED_PT_SZ];
int groupSize;
uint8_t root[SHA256_DIGEST_LEN];
uint8_t chunkRoot[SHA256_DIGEST_LEN];
uint8_t oldChunkHead[SHA256_DIGEST_LEN];
uint8_t newChunkHead[SHA256_DIGEST_LEN];
int queries[2*NUM_CHUNKS];
int ctr;
int subCtr;
int chunkSize;

void Log_SetParams(uint8_t logPk_in[COMPRESSED_PT_SZ], int groupSize_in, int chunkSize_in) {
    memcpy(logPk, logPk_in, COMPRESSED_PT_SZ);
    groupSize = groupSize_in;
    chunkSize = chunkSize_in;
    ctr = 0;
    subCtr = 0;
}

int Log_Verify(uint8_t ct[ELGAMAL_CT_LEN], uint8_t hsms[HSM_GROUP_SIZE], uint8_t proof[PROOF_LEVELS][SHA256_DIGEST_LEN], uint8_t rootSig[SIG_LEN], uint8_t opening[FIELD_ELEM_LEN]) {
    uint8_t curr[SHA256_DIGEST_LEN];

    /* Verify Merkle proof */
    crypto_sha256_init();
    crypto_sha256_update(ct, ELGAMAL_CT_LEN);
    crypto_sha256_update(hsms, groupSize);
    crypto_sha256_update(opening, FIELD_ELEM_LEN);
    crypto_sha256_final(curr);

    for (int i = 0; i < PROOF_LEVELS; i++) {
        crypto_sha256_init(); 
        crypto_sha256_update(curr, SHA256_DIGEST_LEN);
        crypto_sha256_update(proof[i], SHA256_DIGEST_LEN);
        crypto_sha256_final(curr);
    }

//    return (memcmp(curr, root, SHA256_DIGEST_LEN) == 0);
    return (uECC_ecdsaVerify(logPk, curr, SHA256_DIGEST_LEN, rootSig) == 1) ? OKAY : ERROR;
}

int Log_SetChunkRoot(uint8_t *chunkRootIn) {
    memcpy(chunkRoot, chunkRootIn, SHA256_DIGEST_LEN);
}

void Log_SetOldChunkHead(uint8_t head[SHA256_DIGEST_LEN]) {
    memcpy(oldChunkHead, head, SHA256_DIGEST_LEN);
}

void Log_SetNewChunkHead(uint8_t head[SHA256_DIGEST_LEN]) {
    memcpy(newChunkHead, head, SHA256_DIGEST_LEN);
}

int Log_GenChunkQueries (int *queriesOut) {
    for (int i = 0; i < NUM_CHUNKS; i++) {
        /*ctap_generate_rng(queries[2*i], sizeof(int));
        queries[2*i] = queries[2*i] % (TOTAL_HSMS - 1);*/
        queries[2*i] = i % (TOTAL_HSMS - 1);
        queries[2*i+1] = queries[2*i] + 1;
        queriesOut[i]  = queries[2*i+1];
    }
    ctr = 0;
}


int Log_CheckChunkRootProof (uint64_t id, uint8_t head[SHA256_DIGEST_LEN], uint8_t proof[MAX_PROOF_LEVELS][SHA256_DIGEST_LEN], uint64_t ids[MAX_PROOF_LEVELS], int len) {
    uint8_t curr[SHA256_DIGEST_LEN];

    memcpy(curr, head, SHA256_DIGEST_LEN);

    int currIndex = queries[ctr];
    for (int i = len - 1; i >= 0; i--) {
        crypto_sha256_init();
        //if (currIndex % 2 == 0) {
        if (id <= ids[i]) {
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
            crypto_sha256_update(proof[i], SHA256_DIGEST_LEN);
        } else {
            crypto_sha256_update(proof[i], SHA256_DIGEST_LEN);
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
        }
        crypto_sha256_update((uint8_t *)&ids[i], sizeof(uint64_t));
        crypto_sha256_final(curr);
    }
    ctr++;

    return (memcmp(curr, chunkRoot, SHA256_DIGEST_LEN) ==  0);
}

int Log_CheckTransProof(uint64_t id, uint8_t headOld[SHA256_DIGEST_LEN], uint8_t headNew[SHA256_DIGEST_LEN], uint8_t leaf[SHA256_DIGEST_LEN], uint8_t proofOld[MAX_PROOF_LEVELS][SHA256_DIGEST_LEN], uint8_t proofNew[MAX_PROOF_LEVELS][SHA256_DIGEST_LEN], uint64_t idsOld[MAX_PROOF_LEVELS], uint64_t idsNew[MAX_PROOF_LEVELS], int lenOld, int lenNew) {

    uint8_t curr[SHA256_DIGEST_LEN];

    /* Verify Merkle proof for old head */
    memset(curr, 0, SHA256_DIGEST_LEN);

    for (int i = lenOld - 1; i >= 0; i--) {
        crypto_sha256_init();
        if (id <= idsOld[i]) {
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
            crypto_sha256_update(proofOld[i], SHA256_DIGEST_LEN);
        } else {
            crypto_sha256_update(proofOld[i], SHA256_DIGEST_LEN);
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
        }
        crypto_sha256_update((uint8_t *)&idsOld[i], sizeof(uint64_t));
        crypto_sha256_final(curr);
    }

    if (memcmp(curr, headOld, SHA256_DIGEST_LEN) != 0) return ERROR;

    /* Verify Merkle proof for new head */
    memcpy(curr, leaf, SHA256_DIGEST_LEN);

    for (int i = lenNew - 1; i >= 0; i--) {
        crypto_sha256_init();
        if (id <= idsNew[i]) {
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
            crypto_sha256_update(proofNew[i], SHA256_DIGEST_LEN);
        } else {
            crypto_sha256_update(proofNew[i], SHA256_DIGEST_LEN);
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
        }
        crypto_sha256_update((uint8_t *)&idsNew[i], sizeof(uint64_t));
        crypto_sha256_final(curr);
    }

    /* Check proofs match */
    for (int i = lenOld - 1; i >= 0; i--) {
        if (memcmp(proofOld[i], proofNew[i], SHA256_DIGEST_LEN) != 0) return ERROR;
    }

    if (memcmp(curr, headNew, SHA256_DIGEST_LEN) != 0) return ERROR;

    subCtr++;
    if (subCtr == 1) {
        if (memcmp(headOld, oldChunkHead, SHA256_DIGEST_LEN != 0)) return ERROR;
    }
    if (subCtr == chunkSize) {
        if (memcmp(headNew, newChunkHead, SHA256_DIGEST_LEN != 0)) return ERROR;
        subCtr = 0;
    }

    return OKAY;
} 
