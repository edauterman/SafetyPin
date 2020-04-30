#ifndef _MULTISIG_H
#define _MULTISIG_H

#include "bls12_381/bls12_381.h"

#include "params.h"

void Multisig_Setup(embedded_pairing_core_bigint_256_t *sk, embedded_pairing_bls12_381_g2_t *pk);
void Multisig_Sign(embedded_pairing_core_bigint_256_t *sk, uint8_t *msg, int msgLen, embedded_pairing_bls12_381_g1_t *sig);
bool Multisig_Verify(embedded_pairing_bls12_381_g2_t *pk, uint8_t *msg, int msgLen, embedded_pairing_bls12_381_g1_t *sig);
void Multisig_AggPks(embedded_pairing_bls12_381_g2_t *pkList, int len, embedded_pairing_bls12_381_g2_t *aggPk);

#endif
