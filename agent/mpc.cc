#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>

#include "common.h"
#include "hsm.h"
#include "mpc.h"
#include "params.h"
#include "shamir.h"

int MPC_generateBeaverTripleShares(Params *params, ShamirShare **a, ShamirShare **b, ShamirShare **c, BIGNUM **x) {
    int rv = ERROR;
    BIGNUM *a_raw;
    BIGNUM *b_raw;
    BIGNUM *c_raw;

    /* Sample a,b,c such that ab = c */
    CHECK_C (BN_rand_range(a_raw, params->order));
    CHECK_C (BN_rand_range(b_raw, params->order));
    CHECK_C (BN_mod_mul(c_raw, a_raw, b_raw, params->order, params->bn_ctx));

    /* Share a,b,c */
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, a_raw, params->order, a, x));
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, b_raw, params->order, b, x));
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, c_raw, params->order, c, x));

cleanup:
    if (a_raw) BN_free(a_raw);
    if (b_raw) BN_free(b_raw);
    if (c_raw) BN_free(c_raw);
    return rv;
}
