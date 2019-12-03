#ifndef _IBE_H
#define _IBE_H

#include "bls12_381/bls12_381.h"

#define BASEFIELD_SZ 48

void IBE_Setup();
void IBE_Extract(uint16_t index, embedded_pairing_bls12_381_g1_t *sk);

#endif
