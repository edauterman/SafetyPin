#ifndef __MPC_H__
#define __MPC_H__

#include "params.h"
#include "shamir.h"

int MPC_generateBeaverTripleShares(Params *params, ShamirShare *a[NUM_ATTEMPTS][HSM_GROUP_SIZE], ShamirShare *b[NUM_ATTEMPTS][HSM_GROUP_SIZE], ShamirShare *c[NUM_ATTEMPTS][HSM_GROUP_SIZE], BIGNUM **x);

#endif
