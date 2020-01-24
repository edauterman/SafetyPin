#ifndef _PARAMS_H
#define _PARAMS_H

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

#include <openssl/ec.h>

#ifdef __cplusplus
extern "C"{
#endif

#define IV_LEN 16
#define TAG_LEN 16
#define AES128_KEY_LEN 16 

typedef struct {
    BIGNUM *prime;
    BIGNUM *numHsms;
    BIGNUM *numLeaves;
    BN_CTX *bn_ctx;
    EC_GROUP *group;
    BIGNUM *order;
} Params;

Params *Params_new();
void Params_free(Params *params);

void Params_bytesToPoint(Params *params, const uint8_t *bytes, EC_POINT *pt);
void Params_pointToBytes(Params *params, uint8_t *bytes, const EC_POINT *pt);

int hash_to_bytes (uint8_t *bytes_out, int outlen,
    const uint8_t *bytes_in, int inlen);
int aesGcmEncrypt(const void *key, const uint8_t *pt, int ptLen, uint8_t *iv, uint8_t *tag, uint8_t *ct);
int aesGcmDecrypt(const void *key, uint8_t *pt, const uint8_t *iv, const uint8_t *tag, const uint8_t *ct, int ctLen);

#ifdef __cplusplus
}
#endif
#endif
