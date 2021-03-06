#ifndef __PUNC_ENC_H_INCLUDED__
#define __PUNC_ENC_H_INCLUDED__

#include <openssl/ec.h>
#include "bls12_381/bls12_381.h"
#include "hsm.h"
#include "params.h"

void PuncEnc_BuildTree(Params *params, uint8_t *cts, uint8_t msk[KEY_LEN],  uint8_t hmacKey[KEY_LEN], EC_POINT **mpk);
int PuncEnc_GetIndexesForTag(Params *params, uint32_t tag, uint32_t indexes[PUNC_ENC_REPL]);

#endif
