#ifndef _MULTISIG_H
#define _MULTISIG_H

#include "bls12_381/bls12_381.h"

void Multisig_Setup();
void Multisig_GetPk(uint8_t *pkBuf);
void Multisig_SetAggPk(uint8_t *aggPkBuf);
void Multisig_Sign(uint8_t *msg, int msgLen, uint8_t *sig);
uint8_t Multisig_Verify(uint8_t *msg, int msgLen, uint8_t *sig);

#endif
