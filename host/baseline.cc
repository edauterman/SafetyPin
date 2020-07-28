#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "common.h"
#include "elgamal.h"
#include "hsm.h"
#include "params.h"

/* Baseline scheme ElGamal encrypts the key to a HSM and then encrypts the result with
 * the user's PIN. */

int Baseline_Init(HSM *h) {
    int rv;

    CHECK_C (HSM_ElGamalGetPk(h));

cleanup:
    return rv;
}

int Baseline_Save(HSM *h, ElGamal_ciphertext *elGamalCt, uint8_t *aesCt, uint8_t *pinHash, uint8_t *key) {
    int rv;
    uint8_t buf[SHA256_DIGEST_LENGTH + KEY_LEN];
    BIGNUM  *k;
    uint8_t kOutBuf[32];
    uint8_t kHashBuf[AES256_KEY_LEN];
    EVP_CIPHER_CTX *ctx;
    int bytesFilled;
    EVP_MD_CTX *mdctx;

    CHECK_A (k = BN_new());
    CHECK_C (BN_rand_range(k, h->params->order));
    HSM_ElGamalEncrypt(h, k, elGamalCt);

    BN_bn2bin(k, kOutBuf + 32 - BN_num_bytes(k));

    CHECK_A (mdctx = EVP_MD_CTX_create());
    CHECK_C (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL));
    CHECK_C (EVP_DigestUpdate(mdctx, kOutBuf, 32));
    CHECK_C (EVP_DigestFinal_ex(mdctx, kHashBuf, NULL));

    memcpy(buf, pinHash, SHA256_DIGEST_LENGTH);
    memcpy(buf + SHA256_DIGEST_LENGTH, key, KEY_LEN);
   
    CHECK_A (ctx = EVP_CIPHER_CTX_new());
    CHECK_C (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, kHashBuf, NULL));
    CHECK_C (EVP_EncryptUpdate(ctx, aesCt, &bytesFilled, buf, SHA256_DIGEST_LENGTH +  KEY_LEN));
cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (mdctx) EVP_MD_CTX_destroy(mdctx);
    if (k) BN_free(k);
    return rv;
}

int Baseline_Recover(HSM *h, uint8_t *key, ElGamal_ciphertext *elGamalCt, uint8_t *aesCt, uint8_t *pinHash) {
    int rv;
    CHECK_C (HSM_Baseline(h, key, elGamalCt, aesCt, pinHash));

cleanup:
    return rv;
}
