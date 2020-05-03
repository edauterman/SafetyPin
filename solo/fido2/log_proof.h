#ifndef _LOG_PROOF_H_
#define _LOG_PROOF_H_

#include "hsm.h"

void Log_SetParams(uint8_t logPk_in[COMPRESSED_PT_SZ], int groupSize);
int Log_Verify(uint8_t ct[ELGAMAL_CT_LEN], uint8_t hsms[HSM_GROUP_SIZE], uint8_t proof[PROOF_LEVELS][SHA256_DIGEST_LEN], uint8_t rootSig[SIG_LEN], uint8_t opening[FIELD_ELEM_LEN]);

int Log_SetChunkRoot(uint8_t *chunkRootIn);
int Log_GenChunkQueries (int *queries);

int Log_CheckChunkRootProof (uint8_t oldHead[SHA256_DIGEST_LEN], uint8_t newHead[SHA256_DIGEST_LEN], uint8_t proof[ROOT_PROOF_LEVELS][SHA256_DIGEST_LEN]);
int Log_CheckTransProof(uint8_t head[SHA256_DIGEST_LEN], uint8_t leaf[SHA256_DIGEST_LEN], uint8_t proof[PROOF_LEVELS][SHA256_DIGEST_LEN], int index);

#endif
