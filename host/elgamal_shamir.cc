#include <stdlib.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <algorithm>
#include <string.h>

#include "common.h"
#include "hsm.h"
#include "params.h"
#include "shamir.h"
#include "elgamal.h"
#include "elgamal_shamir.h"

/* Location-hiding encryption scheme using hashed ElGamal. 
 * Encrypt a message under a key k, then ElGamal encrypt shares of k
 * under different public keys.
 * To decrypt, need decryptions of each share of k to reassemble k
 * and recover the original message. */

using namespace std;

LocationHidingCt *LocationHidingCt_new(Params *params, int n) {
    int rv;
    LocationHidingCt *c = NULL;

    CHECK_A (c = (LocationHidingCt *)malloc(sizeof(LocationHidingCt)));

    CHECK_A (c->R = EC_POINT_new(params->group));

    CHECK_A (c->shares = (ElGamalCtShare **)malloc(n * sizeof(ElGamalCtShare *)));
    for (int i = 0; i < n; i++) {
        CHECK_A (c->shares[i] = ElGamalCtShare_new(params));
    }

cleanup:
    if (rv == OKAY) return c;
    LocationHidingCt_free(c, n);
    return NULL;
}

void LocationHidingCt_free(LocationHidingCt *c, int n) {
    for (int i = 0; i < n; i++) {
        if (c->shares[i]) ElGamalCtShare_free(c->shares[i]);
    }
    if (c->shares) free(c->shares);
    if (c->R) EC_POINT_free(c->R);
    if (c) free(c);
}

ElGamalCtShare *ElGamalCtShare_new(Params *params) {
    int rv;
    ElGamalCtShare *share = NULL;
    
    CHECK_A (share = (ElGamalCtShare *)malloc(sizeof(ElGamalCtShare)));
    CHECK_A (share->ct = ElGamalCiphertext_new(params));
    CHECK_A (share->x = BN_new());

cleanup:
    if (rv == OKAY) return share;
    ElGamalCtShare_free(share);
    return NULL;
}

void ElGamalCtShare_free(ElGamalCtShare *share) {
    if (share && share->ct) ElGamalCiphertext_free(share->ct);
    if (share && share->x) BN_free(share->x);
    if (share) free(share);
}

/* Create shares by choosing a transport key k, splitting it into (t,n)-shares,
 * encrypting share k_i to pk_i, and then encrypting msg with k. opt_x is used
 * to optionally set the x-value of the Shamir shares of k (otherwise, a simple
 * counter will be used). */
int ElGamalShamir_CreateShares(Params *params, int t, int n, uint8_t *msg, EC_POINT **pks, LocationHidingCt *ct, BIGNUM **opt_x) {
    int rv;
    ShamirShare **shamirShares = NULL;
    BIGNUM *r = NULL;
    BIGNUM *k = NULL;
    EVP_CIPHER_CTX *ctx;
    int bytesFilled = 0;
    uint8_t kBuf[FIELD_ELEM_LEN];
    memset(kBuf, 0, FIELD_ELEM_LEN);

    CHECK_A (shamirShares = (ShamirShare **)malloc(n * sizeof(ShamirShare *)));
    for (int i = 0; i < n; i++) {
        CHECK_A (shamirShares[i] = ShamirShare_new());
    }
    CHECK_A (r = BN_new());
    CHECK_A (k = BN_new());
    CHECK_C (BN_rand_range(r, params->order));
    CHECK_C (BN_rand_range(k, params->order));

    CHECK_C (EC_POINT_mul(params->group, ct->R, r, NULL, NULL, params->bn_ctx));

    CHECK_C (Shamir_CreateShares(t, n, k, params->order, shamirShares, opt_x));


    for (int i = 0; i < n; i++) {
        CHECK_A (ct->shares[i]->x = BN_dup(shamirShares[i]->x));
        CHECK_C (ElGamal_Encrypt(params, shamirShares[i]->y, pks[i], r, ct->R, ct->shares[i]->ct)); 
    }

    BN_bn2bin(k, kBuf + FIELD_ELEM_LEN - BN_num_bytes(k));
    CHECK_A (ctx = EVP_CIPHER_CTX_new());
    CHECK_C (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, kBuf, NULL));
    CHECK_C (EVP_EncryptUpdate(ctx, ct->aesCt, &bytesFilled, msg, FIELD_ELEM_LEN));

cleanup:
    for (int i = 0; i < n; i++) {
        if (shamirShares && shamirShares[i]) ShamirShare_free(shamirShares[i]);
    }
    if (shamirShares) free(shamirShares);
    if (k) BN_free(k);
    if (r) BN_free(r);
    return rv;
}

/* Given all the shares of transport key k and a location-hiding ciphertext, reassemble
 * k and use k to decrypt the original message. */
int ElGamalShamir_ReconstructShares(Params *params, int t, int n, LocationHidingCt *ct, ShamirShare **shares, uint8_t *msg) {
    int rv;
    BIGNUM *k = NULL;
    uint8_t kBuf[FIELD_ELEM_LEN];
    EVP_CIPHER_CTX *ctx;
    int bytesFilled = 0;

    CHECK_A (k = BN_new());

    CHECK_C (Shamir_ReconstructShares(t, n, shares, params->order, k));

    BN_bn2bin(k, kBuf + FIELD_ELEM_LEN - BN_num_bytes(k));
    CHECK_A (ctx = EVP_CIPHER_CTX_new());
    CHECK_C (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, kBuf, NULL));
    CHECK_C (EVP_DecryptUpdate(ctx, msg, &bytesFilled, ct->aesCt, FIELD_ELEM_LEN));

cleanup:
    if (k) BN_free(k);
    return rv;
}

