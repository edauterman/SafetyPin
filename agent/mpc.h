#ifndef __MPC_H__
#define __MPC_H__

#include "params.h"
#include "shamir.h"

int MPC_generateBeaverTripleShares(Params *params, ShamirShare **a, ShamirShare **b, ShamirShare **c, BIGNUM **x);

#endif
