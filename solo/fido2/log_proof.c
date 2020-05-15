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

int Log_Verify(uint8_t ct[ELGAMAL_CT_LEN], uint8_t hsms[HSM_GROUP_SIZE], uint8_t proof[PROOF_LEVELS][SHA256_DIGEST_LEN], uint8_t root[SHA256_DIGEST_LEN], uint8_t opening[FIELD_ELEM_LEN]) {
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

    return (memcmp(curr, root, SHA256_DIGEST_LEN) == 0);
    //    return (uECC_ecdsaVerify(logPk, curr, SHA256_DIGEST_LEN, rootSig) == 1) ? OKAY : ERROR;
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


int Log_CheckChunkRootProof (int id, uint8_t head[SHA256_DIGEST_LEN], uint8_t proof[MAX_PROOF_LEVELS][SHA256_DIGEST_LEN], int ids[MAX_PROOF_LEVELS], int len) {
    uint8_t curr[SHA256_DIGEST_LEN];

    memcpy(curr, head, SHA256_DIGEST_LEN);

    int currIndex = queries[ctr];
    for (int i = len - 1; i >= 0; i--) {
        crypto_sha256_init();
        //if (currIndex % 2 == 0) {
        if (id < ids[i]) {
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
            crypto_sha256_update(proof[i], SHA256_DIGEST_LEN);
        } else {
            crypto_sha256_update(proof[i], SHA256_DIGEST_LEN);
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
        }
        crypto_sha256_update((uint8_t *)&ids[i], sizeof(int));
        crypto_sha256_final(curr);
    }
    ctr++;

    return (memcmp(curr, chunkRoot, SHA256_DIGEST_LEN) ==  0);
}

int Log_CheckTransProof(int id, uint8_t head[SHA256_DIGEST_LEN], uint8_t leaf[SHA256_DIGEST_LEN], uint8_t proof[MAX_PROOF_LEVELS][SHA256_DIGEST_LEN], int ids[MAX_PROOF_LEVELS], int len) {
    uint8_t curr[SHA256_DIGEST_LEN];

    /* Verify Merkle proof */
    memcpy(curr, leaf, SHA256_DIGEST_LEN);

    for (int i = len - 1; i >= 0; i--) {
        crypto_sha256_init();
        if (id < ids[i]) {
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
            crypto_sha256_update(proof[i], SHA256_DIGEST_LEN);
        } else {
            crypto_sha256_update(proof[i], SHA256_DIGEST_LEN);
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
        }
        crypto_sha256_update((uint8_t *)&ids[i], sizeof(int));
        crypto_sha256_final(curr);
    }

    /*printf("computed head: ");
    for (int i = 0; i < SHA256_DIGEST_LEN; i++) printf("%02x", curr[i]);
    printf("\n");
*/



    subCtr++;
    if (subCtr == 1) {
        if (memcmp(head, oldChunkHead, SHA256_DIGEST_LEN != 0)) return ERROR;
    }
    if (subCtr == 3 * chunkSize) {
        if (memcmp(head, newChunkHead, SHA256_DIGEST_LEN != 0)) return ERROR;
        subCtr = 0;
    }

    return (memcmp(curr, head, SHA256_DIGEST_LEN) == 0);
} 
