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
#include "elgamal.h"
#include "elgamal_shamir.h"
#include "params.h"
#include "ibe.h"
#include "common.h"
#include "multisig.h"
#include "merkle_tree.h"
#include "shamir.h"

using namespace std;

void IBETest() {
  printf("----- IBE TEST ----- \n");
  embedded_pairing_core_bigint_256_t msk;
  embedded_pairing_bls12_381_g2_t mpk;
  embedded_pairing_bls12_381_g1_t sk;
  uint8_t msg[IBE_MSG_LEN];
  uint8_t msg_test[IBE_MSG_LEN];
  uint8_t cBuf[IBE_CT_LEN];
  IBE_ciphertext *c = IBE_ciphertext_new(IBE_MSG_LEN);
  IBE_ciphertext *cTest = IBE_ciphertext_new(IBE_MSG_LEN);
  memset(msg, 0xff, IBE_MSG_LEN);

  IBE_Setup(&msk, &mpk);
  IBE_Extract(&msk, 1, &sk);
  IBE_Encrypt(&mpk, 1, msg, IBE_MSG_LEN, c);
  IBE_Decrypt(&sk, c, msg_test, IBE_MSG_LEN);

  IBE_MarshalCt(cBuf, IBE_MSG_LEN, c);
  IBE_UnmarshalCt(cBuf, IBE_MSG_LEN, cTest);
  IBE_Decrypt(&sk, cTest, msg_test, IBE_MSG_LEN);

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
    int t = 2;
    int n = 6;
    BIGNUM *prime = NULL;
    BIGNUM *secret = NULL;
    BIGNUM *secret_test = NULL;
    ShamirShare *shares[n];
    ShamirShare *sharesOut[2 * t];
    uint8_t order[2 * t];
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

    CHECK_C (Shamir_CreateShares(t, n, secret, prime, shares, NULL));
    CHECK_C (Shamir_ValidateShares(t, n, shares, prime));
    CHECK_C (Shamir_ReconstructShares(t, n, shares, prime, secret_test));
    if (BN_cmp(secret, secret_test) != 0) {
        printf("Shamir secret sharing FAILED\n");
        printf("secret: %s\n", BN_bn2hex(secret));
        printf("reconstructed secret: %s\n", BN_bn2hex(secret_test));
    } else {
        printf("Shamir secret sharing successful: %s\n", BN_bn2hex(secret_test));
    }
    
    CHECK_C (Shamir_ReconstructSharesWithValidation(t, n, shares, prime, secret_test));
    //printf("before find valid shares\n");
    CHECK_C (Shamir_FindValidShares(t, n, shares, sharesOut, order, prime, secret_test));
    printf("after find valid shares\n");
    printf("order of valid shares: "); 
    for (int i = 0; i < 2 * t; i++) {
        printf("%d ", order[i]);
    }
    printf("\n");

    CHECK_C (Shamir_CreateShares(1, 2, secret, prime, shares, NULL));
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
    int rv;
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

    BIGNUM *sk = BN_new();
    BIGNUM *skInv = BN_new();
    BN_hex2bn(&sk, "61b28db14fc7ca83ff4a26982f5ae16ffecaaf52087db27a57b55bc115971603");
    BN_mod_inverse(skInv, sk, params->order, params->bn_ctx);
    printf("skInv: %s\n", BN_bn2hex(skInv));

    BIGNUM *d = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *prod = BN_new();
    BN_hex2bn(&d, "55896b2bc2b79802bbd3de223d5c6d1239f15b7a6d9682e6d4bd0bbb8c7a90bf");
    BN_hex2bn(&b, "fc57d5c233b49444fd122c62341b7f4cb52e31043be2a4a23560f2616a4429f9");
    BN_mod_mul(prod, d, b, params->order, params->bn_ctx);
    printf("prod: %s\n", BN_bn2hex(prod));

    ShamirShare *testShares[2];
    BIGNUM  *testVal = BN_new();
    uint8_t x = 1;
    testShares[0] = ShamirShare_new();
    testShares[0]->x = BN_bin2bn(&x, 1, NULL);
    BN_hex2bn(&testShares[0]->y, "B458030068030000B45803004C580300A510020884000000F8660020");
    x = 2;
    testShares[1] = ShamirShare_new();
    testShares[1]->x = BN_bin2bn(&x, 1, NULL);
    BN_hex2bn(&testShares[1]->y, "C3BF00205A3C0300680300005A3C0300503C0300A510020884000000F8660020");
    Shamir_ReconstructShares(2, 2, testShares, params->order, testVal);
    printf("testVal: %s\n", BN_bn2hex(testVal));
 

    ShamirShare *aShares[6];
    ShamirShare *bShares[6];
    ShamirShare *cShares[6];
    ShamirShare *dShares[6];
    ShamirShare *eShares[6];
    ShamirShare *resultShares[6];
    ShamirShare *rShares[6];
    ShamirShare *savePinShares[6];
    ShamirShare *recoverPinShares[6];
    ShamirShare *pinDiffShares[6];
    BIGNUM *result = BN_new();
    //BIGNUM *tmp1 = BN_new();
    //BIGNUM *tmp2 = BN_new();
    //BIGNUM *inv = BN_new();
    //BIGNUM *d = BN_new();
    BIGNUM *e = BN_new();
    uint8_t two = 2;
    BIGNUM *threshold = BN_bin2bn(&two, 1, NULL);
    BN_zero(result);
    for (uint8_t i = 0; i < 6; i++) {
        uint8_t j = i + 1;
        aShares[i] = ShamirShare_new();
        aShares[i]->x = BN_bin2bn(&j, 1, NULL);
        bShares[i] = ShamirShare_new();
        bShares[i]->x = BN_bin2bn(&j, 1, NULL);
        cShares[i] = ShamirShare_new();
        cShares[i]->x = BN_bin2bn(&j, 1, NULL);
        dShares[i] = ShamirShare_new();
        dShares[i]->x = BN_bin2bn(&j, 1, NULL);
        eShares[i] = ShamirShare_new();
        eShares[i]->x = BN_bin2bn(&j, 1, NULL);
        resultShares[i] = ShamirShare_new();
        resultShares[i]->x = BN_bin2bn(&j, 1, NULL);
        rShares[i] = ShamirShare_new();
        rShares[i]->x = BN_bin2bn(&j, 1, NULL);
        savePinShares[i] = ShamirShare_new();
        savePinShares[i]->x = BN_bin2bn(&j, 1, NULL);
        recoverPinShares[i] = ShamirShare_new();
        recoverPinShares[i]->x = BN_bin2bn(&j, 1, NULL);
        pinDiffShares[i] = ShamirShare_new();
        pinDiffShares[i]->x = BN_bin2bn(&j, 1, NULL);
    }
    BN_hex2bn(&aShares[0]->y, "8262CDA786E5B79F7AC0637D7D9FD6B1DD6660DF80797F02549947267017721F");
    BN_hex2bn(&aShares[1]->y, "4A389F47226B783C471B720EB135CA7E59287DF807728ED8EEF1FC3AAFACCE9C");
    BN_hex2bn(&aShares[2]->y, "120E70E6BDF138D91376809FE4CBBE4AD4EA9B108E6B9EAF894AB14EEF422B19");
    BN_hex2bn(&aShares[3]->y, "D9E442865976F975DFD18F311861B2160B5B950FC4AD4EC1E375C4EFFF0DC8D7");
    BN_hex2bn(&aShares[4]->y, "A1BA1425F4FCBA12AC2C9DC24BF7A5E2871DB2284BA65E987DCE7A043EA32554");
    BN_hex2bn(&aShares[5]->y, "698FE5C590827AAF7887AC537F8D99AF02DFCF40D29F6E6F18272F187E3881D1");

    BN_hex2bn(&bShares[0]->y, "3C625C9EA5152D5FA2DD9419CD0C8E2C69FB3B1893162243BC2B61B0F4742D17");
    BN_hex2bn(&bShares[1]->y, "AA65200C7946B05ACEF23F3E5D0F8B420CD373FB69C969603D5BF68F1F4CD25C");
    BN_hex2bn(&bShares[2]->y, "1867E37A4D783355FB06EA62ED128858F4FCCFF791341040FEBA2CE079EF3660");
    BN_hex2bn(&bShares[3]->y, "866AA6E821A9B651271B95877D15856E97D508DA67E7575D7FEAC1BEA4C7DBA5");
    BN_hex2bn(&bShares[4]->y, "F46D6A55F5DB394C533040AC0D1882843AAD41BD3E9A9E7A011B569CCFA080EA");
    BN_hex2bn(&bShares[5]->y, "62702DC3CA0CBC477F44EBD09D1B7F9B22D69DB96605455AC2798CEE2A42E4EE");

    BN_hex2bn(&cShares[0]->y, "C94099869B660EF5CC71CFB5726F9B0207B5754273D673D3035085025C9B2B89");
    BN_hex2bn(&cShares[1]->y, "14B668AD4EA2A0527078C9DFD41BB4FAA993066C5845723DCF0D538C8B74BF3E");
    BN_hex2bn(&cShares[2]->y, "602C37D401DF31AF147FC40A35C7CEF2061F747CEBFD10E45A9C80A38A849434");
    BN_hex2bn(&cShares[3]->y, "ABA206FAB51BC30BB886BE349773E8E962ABE28D7FB4AF8AE62BADBA8994692A");
    BN_hex2bn(&cShares[4]->y, "F717D621685854685C8DB85EF92002E0BF38509E136C4E3171BADAD188A43E20");
    BN_hex2bn(&cShares[5]->y, "428DA5481B94E5C50094B2895ACC1CD96115E1C7F7DB4C9C3D77A95BB77DD1D5");

    /*BN_hex2bn(&dShares[0]->y, );
    BN_hex2bn(&dShares[1]->y, );
    BN_hex2bn(&dShares[2]->y, );
    BN_hex2bn(&dShares[3]->y, );
    BN_hex2bn(&dShares[4]->y, );
    BN_hex2bn(&dShares[5]->y, );

    BN_hex2bn(&eShares[0]->y, );
    BN_hex2bn(&eShares[1]->y, );
    BN_hex2bn(&eShares[2]->y, );
    BN_hex2bn(&eShares[3]->y, );
    BN_hex2bn(&eShares[4]->y, );
    BN_hex2bn(&eShares[5]->y, );

    BN_hex2bn(&resultShares[0]->y, );
    BN_hex2bn(&resultShares[1]->y, );
    BN_hex2bn(&resultShares[2]->y, );
    BN_hex2bn(&resultShares[3]->y, );
    BN_hex2bn(&resultShares[4]->y, );
    BN_hex2bn(&resultShares[5]->y, );
*/
    BN_hex2bn(&rShares[0]->y, "7D872085EA124A8D3345FDE4416BF0CF79966DD0E26877EC7413A6CC6D260EF8");
    BN_hex2bn(&rShares[1]->y, "26D2A435BC6BADEDA91285C93CF77D4160FDB9E5D569DC14336266EBDE5CBE95");
    BN_hex2bn(&rShares[2]->y, "D01E27E58EC5114E1EDF0DAE388309B20313E2E177B3E077B28385981FC9AF73");
    BN_hex2bn(&rShares[3]->y, "7969AB95611E74AE94AB9593340E9623EA7B2EF66AB5449F71D245B791005F10");
    BN_hex2bn(&rShares[4]->y, "22B52F453377D80F0A781D782F9A2295D1E27B0B5DB6A8C7312105D702370EAD");
    BN_hex2bn(&rShares[5]->y, "CC00B2F505D13B6F8044A55D2B25AF0673F8A4070000AD2AB042248343A3FF8B");

    BN_hex2bn(&savePinShares[0]->y, "72A2BFF7031E506BC2072EF6E81BE3E270E723E0B775A224D49C8F9CA2A0F7CE");
    BN_hex2bn(&savePinShares[1]->y, "3CE9040EE9575C33A313243F742DEFC0FE4F72D27118DA087745EA73E7496078");
    BN_hex2bn(&savePinShares[2]->y, "072F4826CF9067FB841F1988003FFB9F8BB7C1C42ABC11EC19EF454B2BF1C922");
    BN_hex2bn(&savePinShares[3]->y, "D1758C3EB5C973C3652B0ED08C52077CD3CEED9C93A7EA0B7C6AFEAF40D0730D");
    BN_hex2bn(&savePinShares[4]->y, "9BBBD0569C027F8B463704191864135B61373C8E4D4B21EF1F1459868578DBB7");
    BN_hex2bn(&savePinShares[5]->y, "6602146E823B8B532742F961A4761F39EE9F8B8006EE59D2C1BDB45DCA214461");


    BN_hex2bn(&recoverPinShares[0]->y, "96258095A478EEFBCF694598BF9FD20DD09A902E12E7CF82828147B4807EB3B1");
    BN_hex2bn(&recoverPinShares[1]->y, "83EE854C2C0C9953BDD751832335CC17BDB64B6D27FD34C3D30F5AA3A304D83E");
    BN_hex2bn(&recoverPinShares[2]->y, "71B78A02B3A043ABAC455D6D86CBC621AAD206AC3D129A05239D6D92C58AFCCB");
    BN_hex2bn(&recoverPinShares[3]->y, "5F808EB93B33EE039AB36957EA61C02B97EDC1EB5227FF46742B8081E8112158");
    BN_hex2bn(&recoverPinShares[4]->y, "4D49936FC2C7985B892175424DF7BA3585097D2A673D6487C4B993710A9745E5");
    BN_hex2bn(&recoverPinShares[5]->y, "3B1298264A5B42B3778F812CB18DB43F722538697C52C9C91547A6602D1D6A72");

    for (int i = 0; i < 6; i++) {
        BN_mod_sub(pinDiffShares[i]->y, recoverPinShares[i]->y, savePinShares[i]->y, params->order, params->bn_ctx);
        BN_mod_sub(dShares[i]->y, rShares[i]->y, aShares[i]->y, params->order, params->bn_ctx);
        printf("d[%d] = %s\n", i, BN_bn2hex(dShares[i]->y));
        BN_mod_sub(eShares[i]->y, pinDiffShares[i]->y, bShares[i]->y, params->order, params->bn_ctx);
        printf("e[%d] = %s\n", i, BN_bn2hex(eShares[i]->y));
    }

    BN_hex2bn(&d, "19AEA0CE2C58F02A0F142112FBD68178308ADDF4F5E6A498FA84549ACB6D49B9");
    BN_hex2bn(&e, "31A066CF2F1C559B8937170AC2F66EE938DCFDCA439D24D8C505332D3664782E");

    BIGNUM *tmp1 = BN_new();
    BIGNUM *tmp2 = BN_new();
    BIGNUM *inv = BN_new();
    for (int i = 0; i < 6; i++) {
        BN_zero(resultShares[i]->y);
        BN_mod_mul(tmp1, d, e, params->order, params->bn_ctx);
        BN_mod_inverse(inv, threshold, params->order, params->bn_ctx);
        //BN_mod_mul(tmp1, tmp1, inv, params->order, params->bn_ctx);

        BN_mod_mul(tmp2, d, bShares[i]->y, params->order, params->bn_ctx);
        BN_mod_add(resultShares[i]->y, tmp1, tmp2, params->order, params->bn_ctx);

        BN_mod_mul(tmp2, e, aShares[i]->y, params->order, params->bn_ctx);
        BN_mod_add(resultShares[i]->y, resultShares[i]->y, tmp2, params->order, params->bn_ctx);

        BN_mod_add(resultShares[i]->y, resultShares[i]->y, cShares[i]->y, params->order, params->bn_ctx);
        printf("result[%d] = %s\n", i, BN_bn2hex(resultShares[i]->y));
    }

    Shamir_ReconstructShares(2, 6, resultShares, params->order, result);
    printf("result = %s\n", BN_bn2hex(result));


    BIGNUM *a = BN_new();
    //BIGNUM *b = BN_new();
    BIGNUM *c = BN_new();
    Shamir_ReconstructShares(2, 6, aShares, params->order, a);
    Shamir_ReconstructShares(2, 6, bShares, params->order, b);
    Shamir_ReconstructShares(2, 6, cShares, params->order, c);
    printf("a = %s\n", BN_bn2hex(a));
    printf("b = %s\n", BN_bn2hex(b));
    printf("c = %s\n", BN_bn2hex(c));
    BN_mod_mul(c, a, b, params->order, params->bn_ctx);
    printf("c_test = %s\n", BN_bn2hex(c));
    Shamir_ReconstructShares(2, 6, recoverPinShares, params->order, c);
    printf("recoverPin = %s\n", BN_bn2hex(c));
    Shamir_ReconstructShares(2, 6, savePinShares, params->order, c);
    printf("savePin = %s\n", BN_bn2hex(c));
    Shamir_ReconstructShares(2, 6, pinDiffShares, params->order, c);
    printf("pinDiff = %s\n", BN_bn2hex(c));
    printf("threshold  %s\n", BN_bn2hex(threshold));
cleanup:
    printf("done\n");

}

void ElGamalTest() {
    printf("----- EL GAMAL TEST -----\n");
    Params *params = Params_new();
    BIGNUM *sk = BN_new();
    EC_POINT *pk = EC_POINT_new(params->group);
    ElGamal_ciphertext *c = ElGamalCiphertext_new(params);
    BIGNUM *msg = BN_new();
    BIGNUM *msgTest = BN_new();

    BN_rand_range(sk, params->order);
    BN_rand_range(msg, params->order);
    EC_POINT_mul(params->group, pk, sk, NULL, NULL, params->bn_ctx);

    ElGamal_Encrypt(params, msg, pk, NULL, NULL, c);
    ElGamal_Decrypt(params, msgTest, sk, c);

    printf("msg: %s\n", BN_bn2hex(msg));
    printf("msgTest: %s\n", BN_bn2hex(msgTest));
}    

void ElGamalShamirTest() {
    printf("----- EL GAMAL SHAMIR TEST ------ \n");
    Params *params = Params_new();
    int t = 3;
    int n = 10;
    uint8_t msg[32];
    uint8_t msgTest[32];
    BIGNUM *sks[n];
    EC_POINT *pks[n];
    ShamirShare *msgShares[n];
    LocationHidingCt *locationHidingCt;

    for (int i = 0; i < n; i++) {
        sks[i] = BN_new();
        pks[i] = EC_POINT_new(params->group);
        BN_rand_range(sks[i], params->order);
        EC_POINT_mul(params->group, pks[i], sks[i], NULL, NULL, params->bn_ctx);
        msgShares[i] = ShamirShare_new();
    }
    locationHidingCt = LocationHidingCt_new(params, n);

    memset(msg, 0xff, 32);

    ElGamalShamir_CreateShares(params, t, n, msg, pks, locationHidingCt, NULL);

    for (int i = 0; i < n; i++) {
        ElGamal_Decrypt(params, msgShares[i]->y, sks[i], locationHidingCt->shares[i]->ct);
        msgShares[i]->x = BN_dup(locationHidingCt->shares[i]->x);
    }

    ElGamalShamir_ReconstructShares(params, t, n, locationHidingCt, msgShares, msgTest);
    
    printf("msg: ");
    for (int i = 0; i < 32; i++) printf("%02x", msg[i]);
    printf("\n");
    printf("msgTest: ");
    for (int i = 0; i < 32; i++) printf("%02x", msgTest[i]);
    printf("\n");
    if (memcmp(msg, msgTest, 32) == 0) {
        printf("Reconstruction successful\n");
    }
 
    //printf("msgTest: %s\n", EC_POINT_point2hex(params->group, msgTest, POINT_CONVERSION_UNCOMPRESSED, params->bn_ctx));
}

void MultisigTest() {
    printf("----- MULTISIG TEST ------ \n");
    embedded_pairing_core_bigint_256_t sk[2];
    embedded_pairing_bls12_381_g2_t pk[2];
    embedded_pairing_bls12_381_g2_t aggPk;
    uint8_t msg[32];
    embedded_pairing_bls12_381_g1_t sig[2];
    embedded_pairing_bls12_381_g1_t aggSig;

    memset(msg, 0xff, 32);
    Multisig_Setup(&sk[0], &pk[0]);
    Multisig_Sign(&sk[0], msg, 32, &sig[0]);
    if (Multisig_Verify(&pk[0], msg, 32, &sig[0])) {
        printf("Single signer multisig successfully verifies.\n");
    } else {
        printf("FAIL: Single signer multisig does not verify.\n");
    }
   
    Multisig_Setup(&sk[1], &pk[1]);
    Multisig_Sign(&sk[1], msg, 32, &sig[1]);
    if (Multisig_Verify(&pk[1], msg, 32, &sig[1])) {
        printf("Single signer multisig successfully verifies.\n");
    } else {
        printf("FAIL: Single signer multisig does not verify.\n");
    }
    
    Multisig_AggPks(pk, 2, &aggPk);
    Multisig_AggSigs(sig, 2, &aggSig);

    if (Multisig_Verify(&aggPk, msg, 32, &aggSig)) {
        printf("Multiple signer multisig successfully verifies.\n");
    } else {
        printf("FAIL: Multiple signer multisig does not verify.\n");
    }

}

void MerkleTreeTest() {
    printf("----- MERKLE TREE TEST ------ \n");
    uint64_t ids[32];
    uint8_t **values = (uint8_t **)malloc(32 * sizeof(uint8_t *));
    for (uint64_t i = 0; i < 32; i++) {
        ids[i] = i;
        values[i] = (uint8_t *)malloc(SHA256_DIGEST_LENGTH);
        memset(values[i], 0xaa, SHA256_DIGEST_LENGTH);
    }
    printf("going to create tree\n");
    Node *head = MerkleTree_CreateTree(ids, values, 32);
    printf("finished creating tree\n");
    MerkleProof *proof = MerkleTree_GetProof(head, 2);
    printf("Got proof\n");
    if (MerkleTree_VerifyProof(head, proof, values[1], 2) == OKAY) {
        printf("Merkle proof verifies.\n");
    } else {
        printf("FAIL: Merkle proof doesn't verify.\n");
    }
    uint8_t newValue[SHA256_DIGEST_LENGTH];
    memset(newValue, 0xaa, SHA256_DIGEST_LENGTH);
    MerkleTree_InsertLeaf(head, 32, newValue);
    MerkleTree_InsertLeaf(head, 33, newValue);
    MerkleTree_InsertLeaf(head, 34, newValue);
    proof = MerkleTree_GetProof(head, 1);
    printf("Got proof\n");
    if (MerkleTree_VerifyProof(head, proof, newValue, 1) == OKAY) {
        printf("Merkle proof verifies.\n");
    } else {
        printf("FAIL: Merkle proof doesn't verify.\n");
    }
    proof = MerkleTree_GetProof(head, 33);
    printf("Got proof\n");
    if (MerkleTree_VerifyProof(head, proof, newValue, 33) == OKAY) {
        printf("Merkle proof verifies.\n");
    } else {
        printf("FAIL: Merkle proof doesn't verify.\n");
    }
/*    MerkleTree_InsertLeaf(head, 35, newValue);
    proof = MerkleTree_GetProof(head, 35);
    printf("Got proof\n");
    if (MerkleTree_VerifyProof(head, proof, newValue, 35) == OKAY) {
        printf("Merkle proof verifies.\n");
    } else {
        printf("FAIL: Merkle proof doesn't verify.\n");
    }
 */
    proof = MerkleTree_GetEmptyProof(head, 256);
    printf("Got empty proof\n");
    if (MerkleTree_VerifyEmptyProof(head, proof, 256) == OKAY) {
        printf("Merkle proof verifies.\n");
    } else {
        printf("FAIL: Merkle proof doesn't verify.\n");
    }
 

    
}

int main(int argc, char *argv[]) {
  IBETest();
  ShamirTest();
  AESGCMTest();
  ElGamalTest();
  ElGamalShamirTest();
  MultisigTest();
  MerkleTreeTest();
  //scratch();
  return 0;
}
