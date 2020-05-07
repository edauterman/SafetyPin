/*
 * Copyright (c) 2018, Henry Corrigan-Gibbs
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "common.h"
#include "params.h"
#include "datacenter.h"

int min(int a, int b); 

inline int min (int a, int b) {
  return (a < b) ? a : b;
}

Params *Params_new() 
{
    int rv = ERROR;

    Params *params = NULL;
    CHECK_A (params = (Params *)malloc(sizeof(Params)));
    CHECK_A (params->prime = BN_new());
    CHECK_A (params->base_prime = BN_new());
    CHECK_A (params->numHsms = BN_new());
    CHECK_A (params->numLeaves = BN_new());
    CHECK_A (params->order = BN_new());
    CHECK_A (params->bn_ctx = BN_CTX_new());

    char numHsmsBuf[4];
    printf("NUM_HSMS: %d\n", NUM_HSMS);
    sprintf(numHsmsBuf, "%d", NUM_HSMS);
    BN_dec2bn(&params->numHsms, numHsmsBuf);

    char numLeavesBuf[4];
    printf("NUM_LEAVES: %d\n", NUM_LEAVES);
    sprintf(numLeavesBuf, "%d", NUM_LEAVES);
    BN_dec2bn(&params->numLeaves, numLeavesBuf);

    // TODO: delete this, using order instead of prime now 
    BN_hex2bn(&params->prime, "EC35D1D9CD0BEC4A13186ED1DDFE0CF3");

    CHECK_A (params->group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    CHECK_C (EC_GROUP_get_order(params->group, params->order, params->bn_ctx));

    CHECK_C (EC_GROUP_get_curve_GFp (params->group, params->base_prime, NULL, NULL, params->bn_ctx));

    printf("finished params\n");
cleanup:
    if (rv == ERROR) {
        Params_free(params);
        return NULL;
    }
    return params;
}

void Params_free(Params *params) {
    BN_free(params->prime);
    BN_free(params->base_prime);
    BN_free(params->numHsms);
    BN_free(params->numLeaves);
    BN_CTX_free(params->bn_ctx);
    BN_free(params->order);
    EC_GROUP_free(params->group);
    free(params);
}

/*
 * Use SHA-256 to hash the string in `bytes_in`
 * with the integer given in `counter`.
 */
static int
hash_once (EVP_MD_CTX *mdctx, uint8_t *bytes_out, 
    const uint8_t *bytes_in, int inlen, uint16_t counter) 
{
  int rv = ERROR;
  CHECK_C (EVP_DigestInit_ex (mdctx, EVP_sha256 (), NULL));
  CHECK_C (EVP_DigestUpdate (mdctx, &counter, sizeof counter));
  CHECK_C (EVP_DigestUpdate (mdctx, bytes_in, inlen));
  CHECK_C (EVP_DigestFinal_ex (mdctx, bytes_out, NULL));

cleanup:
  return rv;
}

/*
 * Output a string of pseudorandom bytes by hashing a 
 * counter with the bytestring provided:
 *    Hash(0|bytes_in) | Hash(1|bytes_in) | ... 
 */
int
hash_to_bytes (uint8_t *bytes_out, int outlen,
    const uint8_t *bytes_in, int inlen)
{
  int rv = ERROR;
  uint16_t counter = 0;
  uint8_t buf[SHA256_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx = NULL; 
  int bytes_filled = 0;

  CHECK_A (mdctx = EVP_MD_CTX_create());

  do {
    const int to_copy = min (SHA256_DIGEST_LENGTH, outlen - bytes_filled);
    CHECK_C (hash_once (mdctx, buf, bytes_in, inlen, counter));
    memcpy (bytes_out + bytes_filled, buf, to_copy);
    
    counter++;
    bytes_filled += SHA256_DIGEST_LENGTH;
  } while (bytes_filled < outlen);

cleanup:

  if (mdctx) EVP_MD_CTX_destroy (mdctx);
  return rv;
}

/* aadLen must be <= 16 */
/* bytesIn, aadLen = 16, outLen = 32 */
int aesGcmEncrypt(const void *key, const uint8_t *pt, int ptLen,
        uint8_t *iv, uint8_t *tag, uint8_t *ct) {
    int rv = ERROR;
    int bytesFilled = 0;
    EVP_CIPHER_CTX *ctx;
    int len;

    CHECK_C (RAND_bytes(iv, IV_LEN));

    CHECK_A (ctx = EVP_CIPHER_CTX_new());
    CHECK_C (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL));
    CHECK_C (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL));
    CHECK_C (EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char *)key, iv));
    CHECK_C (EVP_EncryptUpdate(ctx, ct, &bytesFilled, pt, ptLen));
    len = bytesFilled;
    printf("len = %d, in len = %d\n", len, ptLen);
    CHECK_C (EVP_EncryptFinal_ex(ctx, ct + len, &bytesFilled));
    CHECK_C (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag));
cleanup:
    if (rv != OKAY) printf("NOT OK ENCRYPT\n");
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return rv;
}

int aesGcmDecrypt(const void *key, uint8_t *pt,
        const uint8_t *iv, const uint8_t *tag,
        const uint8_t *ct, int ctLen) {
    int rv = ERROR;
    int bytesFilled = 0;
    EVP_CIPHER_CTX *ctx;

    CHECK_A (ctx = EVP_CIPHER_CTX_new());
    CHECK_C (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL));
    CHECK_C (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL));
    CHECK_C (EVP_DecryptInit_ex(ctx, NULL, NULL, (const unsigned char *)key, iv));
    CHECK_C (EVP_DecryptUpdate(ctx, pt, &bytesFilled, ct, ctLen));
    printf("bytes filled = %d, wanted %d\n", bytesFilled, ctLen);
    CHECK_C (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag));
    CHECK_C (EVP_DecryptFinal_ex(ctx, pt + bytesFilled, &bytesFilled));

cleanup:
    if (rv != OKAY) printf("NOT OK DECRYPT\n");
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return rv;
}

/* aadLen must be <= 16 */
/* bytesIn, aadLen = 16, outLen = 32 */
int aesEncrypt(const void *key, const uint8_t *pt, int ptLen,
        uint8_t *iv, uint8_t *ct) {
    int rv = ERROR;
    int bytesFilled = 0;
    EVP_CIPHER_CTX *ctx;
    int len;

    CHECK_C (RAND_bytes(iv, AES256_IV_LEN));

    CHECK_A (ctx = EVP_CIPHER_CTX_new());
    CHECK_C (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, (const uint8_t *)key, iv));
    CHECK_C (EVP_EncryptUpdate(ctx, ct, &bytesFilled, pt, ptLen));
    len = bytesFilled;
    CHECK_C (EVP_EncryptFinal_ex(ctx, ct + len, &bytesFilled));
cleanup:
    if (rv != OKAY) printf("NOT OK ENCRYPT\n");
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return rv;
}

int aesDecrypt(const void *key, uint8_t *pt,
        const uint8_t *iv,
        const uint8_t *ct, int ctLen) {
    int rv = ERROR;
    int bytesFilled = 0;
    EVP_CIPHER_CTX *ctx;

    CHECK_A (ctx = EVP_CIPHER_CTX_new());
    CHECK_C (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, (const uint8_t *)key, iv));
    CHECK_C (EVP_DecryptUpdate(ctx, pt, &bytesFilled, ct, ctLen));
    CHECK_C (EVP_DecryptFinal_ex(ctx, pt + bytesFilled, &bytesFilled));

cleanup:
    if (rv != OKAY) printf("NOT OK DECRYPT\n");
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return rv;
}



/* 33 bytes */
void Params_bytesToPoint(Params *params, const uint8_t *bytes, EC_POINT *pt) {
    EC_POINT_oct2point(params->group, pt, bytes, 33, params->bn_ctx);
}

/* 33 bytes */
void Params_pointToBytes(Params *params, uint8_t *bytes, const EC_POINT *pt) {
    EC_POINT_point2oct(params->group, pt, POINT_CONVERSION_COMPRESSED, bytes, 33, params->bn_ctx);
}

int intsToBignums(BIGNUM **bns, uint8_t *ints, int len) {
    int rv;
    for (int i = 0; i < len; i++) {
        CHECK_A (bns[i] = BN_bin2bn(&ints[i], 1, NULL));
    }
cleanup:
    return rv;
}

void hmac(uint8_t *key,  uint8_t *out, uint8_t *in, int inLen) {
    uint8_t keyBuf[64];
    uint8_t keyPadBuf[64];
    uint8_t outBuf[32];
    memset(keyBuf, 0, 64);
    memcpy(keyBuf, key, KEY_LEN);
    for (int i = 0; i < 64; i++) {
        keyPadBuf[i] = keyBuf[i] ^ 0x36;
    }
    memset(outBuf, 0, 32);
    memset(out, 0, 32);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, keyPadBuf, 64);
    EVP_DigestUpdate(mdctx,  in, inLen);
    EVP_DigestFinal_ex(mdctx, outBuf, NULL);
    for (int i = 0; i < 64; i++) {
        keyPadBuf[i] = keyBuf[i] ^ 0x5c;
    }
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, keyPadBuf, 64);
    EVP_DigestUpdate(mdctx, outBuf, 32);
    EVP_DigestFinal_ex(mdctx, out, NULL);
}

static int 
hash_to_int_max (Params *p, BIGNUM *exp, 
    const BIGNUM *max, const uint8_t *str, int strlen)
{
  int rv = ERROR;

  int nbytes = BN_num_bytes (max);
  uint8_t bytes_out[nbytes];

  CHECK_C (hash_to_bytes (bytes_out, nbytes, str, strlen));
  CHECK_A (BN_bin2bn (bytes_out, SHA256_DIGEST_LENGTH, exp));
  CHECK_C (BN_mod (exp, exp, p->order, p->bn_ctx));

cleanup:
  return rv;
}

/* Hash to EC point. */
int
Params_hashToPoint (Params *p, EC_POINT *point,
    const uint8_t *str, int strlen)
{
  int rv = ERROR;
  BIGNUM *x = NULL;
  int y_bit = 0;
  CHECK_A (point);    // point should already be allocated with EC_POINT_new()
  CHECK_A (x = BN_new());

  // Hash string into an x coordinate
  CHECK_C (hash_to_int_max (p, x, p->base_prime, str, strlen));

  // TODO: To be completely correct, we should also derive the y_bit
  // from the hash of the input string.
  while (true) {
    // This will fail if there is not solution to the curve equation
    // with this x.
    if (EC_POINT_set_compressed_coordinates_GFp(p->group, point, x, y_bit, p->bn_ctx))
      break;

    // If we fail to hash successfully, try again.
    //   - Increment x coordinate.
    //   - Flip the y bit.
    CHECK_C (BN_add_word (x, 1));
    CHECK_C (BN_mod (x, x, p->base_prime, p->bn_ctx));
    y_bit = (y_bit + 1) % 2;
  }

cleanup:
  if (x) BN_clear_free (x);
  return rv;
}
