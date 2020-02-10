#ifndef _BASELINE_H_
#define _BASELINE_H_

#include "hsm.h"
#include "elgamal.h"

int Baseline_Save(HSM *h, ElGamal_ciphertext *elGamalCt, uint8_t *aesCt, uint8_t *pinHash, uint8_t *key);

#endif
