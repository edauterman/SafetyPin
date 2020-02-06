#include <stdlib.h>

#include "hsm.h"
#include "log_proof.h"
#include "uECC.h"

uint8_t logPk[COMPRESSED_PT_SZ];
int groupSize;

void Log_SetParams(uint8_t logPk_in[COMPRESSED_PT_SZ], int groupSize_in) {
    memcpy(logPk, logPk_in, COMPRESSED_PT_SZ);
    groupSize = groupSize_in;
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

    return (uECC_ecdsaVerify(logPk, curr, SHA256_DIGEST_LEN, rootSig) == 1) ? OKAY : ERROR;
}
