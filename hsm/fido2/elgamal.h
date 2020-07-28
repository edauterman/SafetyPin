#ifndef _EL_GAMAL_H
#define _EL_GAMAL_H

#include "uECC.h"

void ElGamal_Init();
void ElGamal_GetPk(uint8_t *pk);
void ElGamal_Decrypt(uint8_t *ct, uint8_t *msg);
void ElGamal_DecryptWithSk(uint8_t *ct, uint8_t *skBuf, uint8_t *msg);

#endif
