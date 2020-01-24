#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "common.h"
#include "elgamal.h"
#include "params.h"

ElGamal_ciphertext *ElGamalCiphertext_new(Params *params) {
    int rv;
    ElGamal_ciphertext *c;

    CHECK_A (c = (ElGamal_ciphertext *)malloc(sizeof(ElGamal_ciphertext)));
    CHECK_A (c->R = EC_POINT_new(params->group));
    CHECK_A (c->C = EC_POINT_new(params->group));
cleanup:
    if (rv == ERROR) {
        ElGamalCiphertext_free(c);
        return NULL;
    }
    return c;
}

void ElGamalCiphertext_free(ElGamal_ciphertext *c) {
    if (c && c->R) EC_POINT_free(c->R);
    if (c && c->C) EC_POINT_free(c->C);
    if (c) free(c);
}

/* 66 bytes */
void ElGamal_Marshal(Params *params, uint8_t *bytes, ElGamal_ciphertext *c) {
    Params_pointToBytes(params, bytes, c->R);
    Params_pointToBytes(params, bytes + 33, c->C);
}

/* 66 bytes */
void ElGamal_Unmarshal(Params *params, uint8_t *bytes, ElGamal_ciphertext *c) {
    Params_bytesToPoint(params, bytes, c->R);
    Params_bytesToPoint(params, bytes + 33, c->C);
}

int ElGamal_Encrypt(Params *params, EC_POINT *msg, EC_POINT *pk, ElGamal_ciphertext *c) {
    int rv;
    BIGNUM *r;
    EC_POINT *tmp;

    CHECK_A (r = BN_new());
    CHECK_A (tmp = EC_POINT_new(params->group));

    //CHECK_C (BN_rand(r, BN_num_bits(params->order), 0, 0));
    CHECK_C (BN_rand_range(r, params->order));
    CHECK_C (EC_POINT_mul(params->group, c->R, r, NULL, NULL, params->bn_ctx));
    CHECK_C (EC_POINT_mul(params->group, tmp, NULL, pk, r, params->bn_ctx));
    CHECK_C (EC_POINT_add(params->group, c->C, tmp, msg, params->bn_ctx));

    printf("R compressed: %s\n", EC_POINT_point2hex(params->group, c->R, POINT_CONVERSION_COMPRESSED, params->bn_ctx));
    printf("C compressed: %s\n", EC_POINT_point2hex(params->group, c->C, POINT_CONVERSION_COMPRESSED, params->bn_ctx));
    printf("R: %s\n", EC_POINT_point2hex(params->group, c->R, POINT_CONVERSION_UNCOMPRESSED, params->bn_ctx));
    printf("C: %s\n", EC_POINT_point2hex(params->group, c->C, POINT_CONVERSION_UNCOMPRESSED, params->bn_ctx));
    printf("pk: %s\n", EC_POINT_point2hex(params->group, pk, POINT_CONVERSION_UNCOMPRESSED, params->bn_ctx));

cleanup:
    if (r) BN_free(r);
    return rv;
}

int ElGamal_Decrypt(Params *params, EC_POINT *msg, BIGNUM *sk, ElGamal_ciphertext *c) {
    int rv;
    BIGNUM *skInv;
    EC_POINT *tmp;

    CHECK_A (skInv = BN_new());
    CHECK_A (tmp = EC_POINT_new(params->group));

    BN_mod_sub(skInv, params->order, sk, params->order, params->bn_ctx);
    CHECK_C (EC_POINT_mul(params->group, tmp, NULL, c->R, skInv, params->bn_ctx));
    CHECK_C (EC_POINT_add(params->group, msg, c->C, tmp, params->bn_ctx));

cleanup:
    if (skInv) BN_free(skInv);
    if (tmp) EC_POINT_free(tmp);
}
