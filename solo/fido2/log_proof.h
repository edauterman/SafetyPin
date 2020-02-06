#ifndef _LOG_PROOF_H_
#define _LOG_PROOF_H_

#include "hsm.h"

void Log_SetParams(uint8_t logPk_in[COMPRESSED_PT_SZ], int groupSize);
int Log_Verify(uint8_t ct[ELGAMAL_CT_LEN], uint8_t hsms[HSM_GROUP_SIZE], uint8_t proof[PROOF_LEVELS][SHA256_DIGEST_LEN], uint8_t rootSig[SIG_LEN], uint8_t opening[FIELD_ELEM_LEN]);

#endif
