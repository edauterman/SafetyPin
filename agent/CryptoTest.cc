// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

#include "hsm.h"
#include "params.h"
#include "ibe.h"
#include "common.h"
#include "shamir.h"

using namespace std;

void IBETest() {
  printf("----- IBE TEST ----- \n");
  embedded_pairing_core_bigint_256_t msk;
  embedded_pairing_bls12_381_g2_t mpk;
  embedded_pairing_bls12_381_g1_t sk;
  uint8_t msg[IBE_MSG_LEN];
  uint8_t msg_test[IBE_MSG_LEN];
  IBE_ciphertext *c = IBE_ciphertext_new(IBE_MSG_LEN);
  memset(msg, 0xff, IBE_MSG_LEN);

  IBE_Setup(&msk, &mpk);
  IBE_Extract(&msk, 1, &sk);
  IBE_Encrypt(&mpk, 1, msg, IBE_MSG_LEN, c);
  IBE_Decrypt(&sk, c, msg_test, IBE_MSG_LEN);

  if (memcmp(msg, msg_test, IBE_MSG_LEN) != 0) {
    printf("Decryption did not return correct plaintext: ");
    for (int i = 0; i < IBE_MSG_LEN; i++) {
        printf("%x ", msg_test[i]);
    }
    printf("\n");
  } else {
    printf("Decryption successful.\n");
  }

  IBE_ciphertext_free(c);
}

void ShamirTest() {
    int rv = ERROR;
    int t = 5;
    int n = 7;
    BIGNUM *prime = NULL;
    BIGNUM *secret = NULL;
    BIGNUM *secret_test = NULL;
    ShamirShare *shares[n];
    Params *params;

    printf("----- SHAMIR SECRET SHARING TEST -----\n");

    CHECK_A (prime = BN_new());
    CHECK_A (secret = BN_new());
    CHECK_A (secret_test = BN_new());
    CHECK_A (params = Params_new());
    
    for (int i = 0; i < n; i++) {
        CHECK_A (shares[i] = ShamirShare_new());
    }

    BN_hex2bn(&prime, "CC71BAE525F36E3D3EB843232F9101BD");
//    BN_hex2bn(&prime, "EC35D1D9CD0BEC4A13186ED1DDFE0CF3");
    CHECK_C (BN_rand_range(secret, prime));

    CHECK_C (Shamir_CreateShares(t, n, secret, prime, shares));
    CHECK_C (Shamir_ValidateShares(t, n, shares, prime));
    CHECK_C (Shamir_ReconstructShares(t, n, shares, prime, secret_test));
    
    CHECK_C (Shamir_CreateShares(1, 2, secret, prime, shares));
    CHECK_C (Shamir_ValidateShares(t, n, shares, prime) == ERROR);

    if (BN_cmp(secret, secret_test) != 0) {
        printf("Shamir secret sharing FAILED\n");
        printf("secret: %s\n", BN_bn2hex(secret));
        printf("reconstructed secret: %s\n", BN_bn2hex(secret_test));
    } else {
        printf("Shamir secret sharing successful.\n");
    }

cleanup:
    if (rv == ERROR) printf("FAILED Shamir secret sharing tests\n");
    BN_free(prime);
    BN_free(secret);
    BN_free(secret_test);
    for (int i = 0; i < n; i++) {
        ShamirShare_free(shares[i]);
    }
}

void AESGCMTest() {
    printf("----- AES GCM TEST -----\n");
    int rv;
    uint8_t pt[128];
    uint8_t ptTest[128];
    uint8_t ct[128];
    uint8_t key[AES128_KEY_LEN];
    uint8_t tag[TAG_LEN];
    uint8_t iv[IV_LEN];

    CHECK_C (RAND_bytes(iv, IV_LEN));
    CHECK_C (RAND_bytes(key, AES128_KEY_LEN));
    CHECK_C (RAND_bytes(pt, 128));

    CHECK_C (aesGcmEncrypt(key, pt, 128, iv, tag, ct));
    CHECK_C (aesGcmDecrypt(key, ptTest, iv, tag, ct, 128));

cleanup:
    if (memcmp(pt, ptTest, 128) != 0) {
        printf("AES GCM FAILED\n");
    } else  {
        printf("AES GCM successful.\n");
    }
}

void scratch() {
    Params *params =  Params_new();
    BIGNUM *x1 = BN_new();
    EC_POINT *gx1 = EC_POINT_new(params->group);
    BN_hex2bn(&x1, "6c59500ba1ee237e64059fd28ee5654f816d91a59cdae23581fab6f5852f794d");
    EC_POINT_mul(params->group, gx1, NULL, EC_GROUP_get0_generator(params->group), x1, params->bn_ctx);
    //EC_POINT_mul(params->group, gx, x, NULL, NULL, params->bn_ctx);
    printf("gx1: %s\n", EC_POINT_point2hex(params->group, gx1, POINT_CONVERSION_UNCOMPRESSED, params->bn_ctx));


    BIGNUM *x2 = BN_new();
    EC_POINT *gx2 = EC_POINT_new(params->group);
    BN_hex2bn(&x2, "38e58a25f01feb8911b12f4b8cb192d0f175079b881c5eed647c106013e78956");
    EC_POINT_mul(params->group, gx2, NULL, EC_GROUP_get0_generator(params->group), x2, params->bn_ctx);
    //EC_POINT_mul(params->group, gx, x, NULL, NULL, params->bn_ctx);
    printf("gx2: %s\n", EC_POINT_point2hex(params->group, gx2, POINT_CONVERSION_UNCOMPRESSED, params->bn_ctx));
 
    EC_POINT *gx3 = EC_POINT_new(params->group);
    EC_POINT_add(params->group, gx3, gx1, gx2, params->bn_ctx);
    printf("gx3: %s\n", EC_POINT_point2hex(params->group, gx3, POINT_CONVERSION_UNCOMPRESSED, params->bn_ctx));

    const EC_POINT *g = EC_GROUP_get0_generator(params->group);
    printf("g: %s\n", EC_POINT_point2hex(params->group, g, POINT_CONVERSION_UNCOMPRESSED, params->bn_ctx));
}

int main(int argc, char *argv[]) {
  IBETest();
  ShamirTest();
  AESGCMTest();
  scratch();
  return 0;
}
