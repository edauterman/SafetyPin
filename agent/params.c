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
#include <openssl/sha.h>

#include "common.h"
#include "params.h"

int min(int a, int b); 

inline int min (int a, int b) {
  return (a < b) ? a : b;
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

    CHECK_C (RAND_bytes(iv, IV_LEN));

    CHECK_A (ctx = EVP_CIPHER_CTX_new());
    CHECK_C (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
    CHECK_C (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL));
    CHECK_C (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));
    CHECK_C (EVP_EncryptUpdate(ctx, ct, &bytesFilled, pt, ptLen));
    int len = bytesFilled;
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
    CHECK_C (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
    CHECK_C (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL));
    CHECK_C (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv));
    CHECK_C (EVP_DecryptUpdate(ctx, pt, &bytesFilled, ct, ctLen));
    CHECK_C (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag));
    CHECK_C (EVP_DecryptFinal_ex(ctx, pt + bytesFilled, &bytesFilled));

cleanup:
    if (rv != OKAY) printf("NOT OK DECRYPT\n");
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return rv;
}
