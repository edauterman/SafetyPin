#include <stdlib.h>

#include "hsm.h"
#include "log_proof.h"
#include "uECC.h"

uint8_t logPk[COMPRESSED_PT_SZ];
int groupSize;
uint8_t root[SHA256_DIGEST_LEN];
uint8_t chunkRoot[SHA256_DIGEST_LEN];
int queries[NUM_CHUNKS];
int ctr;

void Log_SetParams(uint8_t logPk_in[COMPRESSED_PT_SZ], int groupSize_in) {
    memcpy(logPk, logPk_in, COMPRESSED_PT_SZ);
    groupSize = groupSize_in;
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

int Log_GenChunkQueries (int *queriesOut) {
    for (int i = 0; i < NUM_CHUNKS; i++) {
        ctap_generate_rng(queries[i], sizeof(int));
        queries[i] = queries[i] % TOTAL_HSMS;
        queriesOut[i]  = queries[i];
    }
    ctr = 0;
}

int Log_CheckChunkRootProof (uint8_t oldHead[SHA256_DIGEST_LEN], uint8_t newHead[SHA256_DIGEST_LEN], uint8_t proof[ROOT_PROOF_LEVELS][SHA256_DIGEST_LEN]) {
    uint8_t curr[SHA256_DIGEST_LEN];
    uint8_t heads[2 * SHA256_DIGEST_LEN];

    memcpy(heads, oldHead, SHA256_DIGEST_LEN);
    memcpy(heads + SHA256_DIGEST_LEN, newHead, SHA256_DIGEST_LEN);
    hashToLength(heads, 2 * SHA256_DIGEST_LEN, curr, SHA256_DIGEST_LEN);
    
    int currIndex = queries[ctr];
    for (int i = 0; i < ROOT_PROOF_LEVELS; i++) {
        crypto_sha256_init();
        if (currIndex % 2 == 0) {
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
            crypto_sha256_update(proof[i], SHA256_DIGEST_LEN);
        } else {
            crypto_sha256_update(proof[i], SHA256_DIGEST_LEN);
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
        }
        crypto_sha256_final(curr);
        currIndex /= 2;
    }
    ctr++;

    return (memcmp(curr, chunkRoot, SHA256_DIGEST_LEN) ==  0);
}

int Log_CheckTransProof(uint8_t head[SHA256_DIGEST_LEN], uint8_t leaf[SHA256_DIGEST_LEN], uint8_t proof[PROOF_LEVELS][SHA256_DIGEST_LEN], int index) {
    uint8_t curr[SHA256_DIGEST_LEN];

    /* Verify Merkle proof */
    memcpy(curr, leaf, SHA256_DIGEST_LEN);

    int currIndex = index;
    for (int i = 0; i < ROOT_PROOF_LEVELS; i++) {
        crypto_sha256_init();
        if (currIndex % 2 == 0) {
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
            crypto_sha256_update(proof[i], SHA256_DIGEST_LEN);
        } else {
            crypto_sha256_update(proof[i], SHA256_DIGEST_LEN);
            crypto_sha256_update(curr, SHA256_DIGEST_LEN);
        }
        crypto_sha256_final(curr);
        currIndex /= 2;
    }
 
    return (memcmp(curr, root, SHA256_DIGEST_LEN) == 0);
} 
