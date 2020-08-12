#ifndef _PARAMS_H
#define _PARAMS_H

#include <openssl/ec.h>

#ifdef __cplusplus
extern "C"{
#endif

#define IV_LEN 16
#define TAG_LEN 16
#define AES128_KEY_LEN 16 

#define AES256_KEY_LEN 32
#define AES256_IV_LEN 32

typedef struct {
    BIGNUM *base_prime;
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

int aesEncrypt(const void *key, const uint8_t *pt, int ptLen, uint8_t *iv, uint8_t *ct);
int aesDecrypt(const void *key, uint8_t *pt, const uint8_t *iv, const uint8_t *ct, int ctLen);

int intsToBignums(BIGNUM **bns, uint8_t *ints, int len);

void hmac(uint8_t *key,  uint8_t *out, uint8_t *in, int inLen);

#ifdef __cplusplus
}
#endif
#endif
