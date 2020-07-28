#ifndef _PUNC_ENC_H_
#define _PUNC_ENC_H

#include "hsm.h"

void PuncEnc_Init();
void PuncEnc_TestSetup(uint8_t newMsk[KEY_LEN], uint8_t newHmacKey[KEY_LEN]);
int PuncEnc_RetrieveLeaf(uint8_t cts[LEVELS][CT_LEN], uint32_t index, uint8_t leaf[CT_LEN]);
void PuncEnc_PunctureLeaf(uint8_t oldCts[KEY_LEVELS][CT_LEN], uint32_t index, uint8_t newCts[KEY_LEVELS][CT_LEN]);

void crypto_hmac(uint8_t *key, uint8_t *out, uint8_t *in, int inLen);
void crypto_aes256_encrypt_sep(uint8_t *out, uint8_t *in, int length);
void crypto_aes256_decrypt_sep(uint8_t *out, uint8_t *in, int length);

#endif
