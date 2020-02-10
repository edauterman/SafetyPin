#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "common.h"
#include "elgamal.h"
#include "hsm.h"
#include "params.h"

int Baseline_Save(HSM *h, ElGamal_ciphertext *elGamalCt, uint8_t *aesCt, uint8_t *pinHash, uint8_t *key) {
    int rv;
    uint8_t buf[SHA256_DIGEST_LENGTH + KEY_LEN];
    EC_POINT *k;
    BIGNUM  *x;
    uint8_t kOutBuf[33];
    uint8_t kHashBuf[AES256_KEY_LEN];
    EVP_CIPHER_CTX *ctx;
    int bytesFilled;
    EVP_MD_CTX *mdctx;

    CHECK_A (x = BN_new());
    CHECK_A (k = EC_POINT_new(h->params->group));
    CHECK_C (BN_rand_range(x, h->params->order));
    EC_POINT_mul(h->params->group, k, x, NULL, NULL, h->params->bn_ctx);
    HSM_ElGamalEncrypt(h, k, elGamalCt);

    Params_pointToBytes(h->params, kOutBuf, k);

    CHECK_A (mdctx = EVP_MD_CTX_create());
    CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
    CHECK_C (EVP_DigestUpdate(mdctx, kOutBuf, 33));
    CHECK_C (EVP_DigestFinal_ex(mdctx, kHashBuf, NULL));

    memcpy(buf, pinHash, SHA256_DIGEST_LENGTH);
    memcpy(buf + SHA256_DIGEST_LENGTH, key, KEY_LEN);
   
    CHECK_A (ctx = EVP_CIPHER_CTX_new());
    CHECK_C (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, kHashBuf, NULL));
    CHECK_C (EVP_EncryptUpdate(ctx, aesCt, &bytesFilled, buf, SHA256_DIGEST_LENGTH +  KEY_LEN));
cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (mdctx) EVP_MD_CTX_destroy(mdctx);
    if (k) EC_POINT_free(k);
    if (x) BN_free(x);
    return rv;
}
