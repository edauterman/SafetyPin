#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "bls12_381/bls12_381.h"
#include "common.h"
#include "datacenter.h"
#include "hsm.h"
#include "mpc.h"
#include "params.h"
#include "punc_enc.h"
#include "shamir.h"
#include "punc_enc.h"

#define VENDOR_ID 0x0483
#define PRODUCT_ID 0xa2ca

using namespace std;

typedef struct {
    uint8_t aesKey[KEY_LEN];
    uint8_t hmacKey[KEY_LEN];
} MpcMsg;

typedef struct {
    uint8_t msg[FIELD_ELEM_LEN];
    uint8_t a[NUM_ATTEMPTS][FIELD_ELEM_LEN];
    uint8_t b[NUM_ATTEMPTS][FIELD_ELEM_LEN];
    uint8_t c[NUM_ATTEMPTS][FIELD_ELEM_LEN];
    uint8_t rShare[FIELD_ELEM_LEN];
    uint8_t savePinShare[FIELD_ELEM_LEN];
} InnerMpcMsg;

RecoveryCiphertext *RecoveryCiphertext_new(Params *params) {
    int rv = ERROR;
    RecoveryCiphertext *c = NULL;
    CHECK_A (c = (RecoveryCiphertext *)malloc(sizeof(RecoveryCiphertext)));
    for (int i = 0; i < HSM_GROUP_SIZE; i++)  {
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A (c->recoveryCts[i][j] = IBE_ciphertext_new(IBE_MSG_LEN));
//            CHECK_A (c->saltCts[i][j] = IBE_ciphertext_new(IBE_MSG_LEN));
        }
        CHECK_A (c->elGamalCts[i] = ElGamalCtShare_new(params));
    }
    CHECK_A (c->r = BN_new());
    CHECK_A (c->s = BN_new());
cleanup:
    if (rv == ERROR) {
        RecoveryCiphertext_free(c);
        return NULL;
    }
    return c;
}

void RecoveryCiphertext_free(RecoveryCiphertext *c) {
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            //if (c && c->recoveryCts[i] && c->recoveryCts[i][j]) IBE_ciphertext_free(c->recoveryCts[i][j]);
//            if (c && c->saltCts[i] && c->saltCts[i][j]) IBE_ciphertext_free(c->saltCts[i][j]);
        }
        free(c->elGamalCts[i]);
    }
    if (c && c->r) BN_free(c->r);
    if (c && c->s) BN_free(c->s);
    if (c) free(c);
}

Datacenter *Datacenter_new() {
    int rv = ERROR;
    Datacenter *d;

    CHECK_A (d = (Datacenter *)malloc(sizeof(Datacenter)));
    for (int i  = 0; i < NUM_HSMS; i++) {
        CHECK_A (d->hsms[i] = HSM_new());
    }

cleanup:
    if (rv == ERROR){
        return NULL;
    }
    return d;
}

int Datacenter_VirtualSetup(Datacenter *d) {
    int rv;
    uint8_t msk[KEY_LEN];
    uint8_t hmacKey[KEY_LEN];
    embedded_pairing_bls12_381_g2_t mpk;

    for (int i = 0; i < NUM_HSMS; i++) {
        embedded_pairing_core_bigint_256_t sk;
        IBE_Setup(&sk, &d->hsms[i]->mpk, &d->hsms[i]->mpkPrepared);
        BIGNUM *x = BN_new();
        BN_rand_range(x, d->hsms[i]->params->order);
        EC_POINT_mul(d->hsms[i]->params->group, d->hsms[i]->elGamalPk, x, NULL, NULL, d->hsms[i]->params->bn_ctx);
        printf("Done with setup for %d/%d\n", i, NUM_HSMS);
    }
cleanup:
    return rv;
}


/*int chooseHsmsFromSalt(Params *params, uint8_t h[HSM_GROUP_SIZE], BIGNUM *salt) {
    int rv = ERROR;
    BIGNUM *hsm;
    uint8_t out[SHA256_DIGEST_LENGTH];
    BIGNUM *saltHashes[HSM_GROUP_SIZE];

    CHECK_A (hsm = BN_new());

  */  /* Hash salt and pin to choose recovery HSMs. */
    /*printf("num hsms: %s\n", BN_bn2hex(params->numHsms));
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t *in = NULL;
        int len = BN_num_bytes(salt) + 1;
        CHECK_A (in = (uint8_t *)malloc(len));
        in[0] = i;
        BN_bn2bin(salt, in + 1);
        hash_to_bytes(out, SHA256_DIGEST_LENGTH, in, len);
        CHECK_A (saltHashes[i] = BN_bin2bn(out, SHA256_DIGEST_LENGTH, NULL));
        CHECK_C (BN_mod(hsm, saltHashes[i], params->numHsms, params->bn_ctx));
        // NOTE: ASSUMING NUM_HSMS NEVER GREATER THAN 256
        h[i] = 0;
        BN_bn2bin(hsm, &h[i]);
        printf("h[%d] = %d\n", i, h[i]);
    }
cleanup:
    if (hsm) BN_free(hsm);
    return rv;
}*/

int chooseHsmsFromSaltAndPin(Params *params, uint8_t h[HSM_GROUP_SIZE], BIGNUM *saltHashes[HSM_GROUP_SIZE], BIGNUM *salt, BIGNUM *pin) {
    int rv = ERROR;
    BIGNUM *hsm;
    uint8_t out[SHA256_DIGEST_LENGTH];

    CHECK_A (hsm = BN_new());

    /* Hash salt and pin to choose recovery HSMs. */
    printf("num hsms: %s\n", BN_bn2hex(params->numHsms));
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t *in = NULL;
        int len = BN_num_bytes(salt) + BN_num_bytes(pin) + 1;
        CHECK_A (in = (uint8_t *)malloc(len));
        in[0] = i;
        BN_bn2bin(salt, in + 1);
        BN_bn2bin(pin, in + 1 + BN_num_bytes(salt));
        hash_to_bytes(out, SHA256_DIGEST_LENGTH, in, len);
        CHECK_A (saltHashes[i] = BN_bin2bn(out, SHA256_DIGEST_LENGTH, NULL));
        CHECK_C (BN_mod(hsm, saltHashes[i], params->numHsms, params->bn_ctx));
        // NOTE: ASSUMING NUM_HSMS NEVER GREATER THAN 256
        h[i] = 0;
        BN_bn2bin(hsm, &h[i]);
        h[i] = i % NUM_HSMS; // JUST FOR TESTING!!!
        debug_print("h[%d] = %d\n", i, h[i]);
    }
cleanup:
    if (hsm) BN_free(hsm);
    return rv;
}

int hashPinAndSalt(BIGNUM *pin, BIGNUM *salt, uint8_t *out) {
    int rv;
    /* Salted hash of pin. */
    uint8_t *in = NULL;
    int len = BN_num_bytes(salt) + BN_num_bytes(pin);
    CHECK_A (in = (uint8_t *)malloc(len));
    BN_bn2bin(salt, in);
    BN_bn2bin(pin, in + BN_num_bytes(salt));
    hash_to_bytes(out, SHA256_DIGEST_LENGTH, in, len);
cleanup:
    if (in) free(in);
    return rv;
}

/* bns: prime, numHsms
 * bn_ctx 
 * make IBE_MSG_LEN = 32 + 16 = 48*/

int Datacenter_Save(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, BIGNUM *pin, RecoveryCiphertext *c) {
    int rv = ERROR;
    uint8_t h1[HSM_GROUP_SIZE];
    uint8_t h2[HSM_GROUP_SIZE];
    BIGNUM *r = NULL;
    BIGNUM *saltHashes[HSM_GROUP_SIZE];
    uint8_t saltHash[SHA256_DIGEST_LENGTH];
    BIGNUM *elGamalRand = NULL;
    EC_POINT *elGamalRandPt = NULL;
    ShamirShare *saveKeyShares[HSM_GROUP_SIZE];
    ShamirShare *saltShares[HSM_GROUP_SIZE];
    ShamirShare *aShares[NUM_ATTEMPTS][HSM_GROUP_SIZE];
    ShamirShare *bShares[NUM_ATTEMPTS][HSM_GROUP_SIZE];
    ShamirShare *cShares[NUM_ATTEMPTS][HSM_GROUP_SIZE];
    ShamirShare *rShares[HSM_GROUP_SIZE];
    ShamirShare *pinShares[HSM_GROUP_SIZE];
    ShamirShare *elGamalRandShares[HSM_GROUP_SIZE];
    BIGNUM *h1Bns[HSM_GROUP_SIZE];
    EC_POINT *h1Pks[HSM_GROUP_SIZE];
    IBE_ciphertext *recoveryCts[HSM_GROUP_SIZE][PUNC_ENC_REPL];
    uint8_t elGamalRandBuf[33];
    uint8_t keyBuf[AES256_KEY_LEN];
    uint8_t list[HSM_GROUP_SIZE];
    BIGNUM *encryptedSaveKey;
    uint8_t encryptedSaveKeyBuf[FIELD_ELEM_LEN];
    uint8_t saveKeyBuf[FIELD_ELEM_LEN];
    int bytesFilled = 0;

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        CHECK_A (saveKeyShares[i] = ShamirShare_new());
        CHECK_A (saltShares[i] = ShamirShare_new());
        CHECK_A (rShares[i] = ShamirShare_new());
        CHECK_A (pinShares[i] = ShamirShare_new());
        CHECK_A (elGamalRandShares[i] = ShamirShare_new());
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A (recoveryCts[i][j] = IBE_ciphertext_new(IBE_MSG_LEN));
        }
        for (int j = 0; j < NUM_ATTEMPTS; j++) {
            CHECK_A (aShares[j][i] = ShamirShare_new());
            CHECK_A (bShares[j][i] = ShamirShare_new());
            CHECK_A (cShares[j][i] = ShamirShare_new());
        }
        list[i] = i + 1;
    }
    CHECK_A (elGamalRandPt = EC_POINT_new(params->group));
    CHECK_A (elGamalRand = BN_new());
    CHECK_A (encryptedSaveKey = BN_new());
    
    debug_print("start save key: %s\n", BN_bn2hex(saveKey));

    /* Choose salts. */
    CHECK_A (r = BN_new());
    CHECK_C (BN_rand_range(c->s, params->order));
    CHECK_C (BN_rand_range(c->r, params->order));
    CHECK_C (BN_rand_range(r, params->order));

    /* Hash salt and pin to choose recovery HSMs. */
    chooseHsmsFromSaltAndPin(params, h1, saltHashes, c->r, pin);
    CHECK_C (intsToBignums(h1Bns, list, HSM_GROUP_SIZE));
    //CHECK_C (intsToBignums(h1Bns, h1, HSM_GROUP_SIZE));

    debug_print("hashed salt and pin to find HSMs\n");

    /* Salted hash of pin. */
    CHECK_C (hashPinAndSalt(pin, c->s, saltHash));
    memset(saveKeyBuf, 0, FIELD_ELEM_LEN);
    BN_bn2bin(saveKey, saveKeyBuf + FIELD_ELEM_LEN - BN_num_bytes(saveKey));
    EVP_CIPHER_CTX *ctx; 
    CHECK_A (ctx = EVP_CIPHER_CTX_new());
    CHECK_C (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, saltHash, NULL));
    CHECK_C (EVP_EncryptUpdate(ctx, encryptedSaveKeyBuf, &bytesFilled, saveKeyBuf, FIELD_ELEM_LEN));
    BN_bin2bn(encryptedSaveKeyBuf, FIELD_ELEM_LEN, encryptedSaveKey);

    /* Split saveKey into shares */
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, saveKey, params->order, saveKeyShares, h1Bns));
    //CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, encryptedSaveKey, params->order, saveKeyShares, h1Bns));

    debug_print("created shares of save key\n");

    /* Generate Beaver triple. */
    CHECK_C (MPC_generateBeaverTripleShares(params, aShares, bShares, cShares, h1Bns));

    debug_print("created beaver triple\n");

    /* Split r and PIN into shares. */
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, r, params->order, rShares, h1Bns));
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, pin, params->order, pinShares, h1Bns));

    debug_print("Going to encrypt ciphertexts to each HSM\n");

    /* Encrypt [saveKey]_i, H(pin, salt) to each HSM. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        debug_print("starting ct %d\n", i);
        bytesFilled = 0;

        InnerMpcMsg innerMpcMsg;
        Shamir_MarshalCompressed(innerMpcMsg.msg, saveKeyShares[i]);
        Shamir_MarshalCompressed(innerMpcMsg.rShare, rShares[i]);
        Shamir_MarshalCompressed(innerMpcMsg.savePinShare, pinShares[i]);

        for (int j = 0; j < NUM_ATTEMPTS; j++) {
            Shamir_MarshalCompressed(innerMpcMsg.a[j], aShares[j][i]);
            Shamir_MarshalCompressed(innerMpcMsg.b[j], bShares[j][i]);
            Shamir_MarshalCompressed(innerMpcMsg.c[j], cShares[j][i]);
        }

        MpcMsg mpcMsg;
        CHECK_C (RAND_bytes(mpcMsg.aesKey, KEY_LEN));
        CHECK_C (RAND_bytes(mpcMsg.hmacKey, KEY_LEN));

        EVP_CIPHER_CTX *ctx; 
        CHECK_A (ctx = EVP_CIPHER_CTX_new());
        CHECK_C (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, mpcMsg.aesKey, NULL));
        CHECK_C (EVP_EncryptUpdate(ctx, c->aesCts[i], &bytesFilled, (uint8_t *)&innerMpcMsg, AES_CT_LEN));
        hmac(mpcMsg.hmacKey, c->aesCtTags[i], c->aesCts[i], AES_CT_LEN);

        printf("aesCtTag[%d]: ", i);
        for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
            printf("%02x", c->aesCtTags[i][j]);
        }
        printf("\n");
       
        printf("hmacKey[%d]: ", i);
        for (int j = 0; j < KEY_LEN; j++) {
            printf("%02x", mpcMsg.hmacKey[j]);
        }
        printf("\n");
      
        printf("aesCt[%d]: ", i);
        for (int j = 0; j < AES_CT_LEN; j++) {
            printf("%02x", c->aesCts[i][j]);
        }
        printf("\n");
      

        printf("saveKeyShare[%d]: %s, %s\n", i, BN_bn2hex(saveKeyShares[i]->x), BN_bn2hex(saveKeyShares[i]->y));
        printf("aShare[%d]: %s\n", i, BN_bn2hex(aShares[0][i]->y));
        printf("bShare[%d]: %s\n", i, BN_bn2hex(bShares[0][i]->y));
        printf("cShare[%d]: %s\n", i, BN_bn2hex(cShares[0][i]->y));
        printf("rShare[%d]: %s\n", i, BN_bn2hex(rShares[i]->y));
        printf("savePinShare[%d]: %s\n", i, BN_bn2hex(pinShares[i]->y));
       
        CHECK_C (HSM_Encrypt(d->hsms[h1[i]], userID + i, (uint8_t *)&mpcMsg, IBE_MSG_LEN, recoveryCts[i]));

    }

    CHECK_C (BN_rand_range(elGamalRand, params->order));
    for (int i = 0; i < HSM_GROUP_SIZE; i++)  {
        CHECK_A (h1Pks[i] = EC_POINT_dup(d->hsms[h1[i]]->elGamalPk, params->group));
    }
    ElGamalShamir_CreateShares(params, HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, elGamalRand, h1Pks, c->elGamalCts, h1Bns);
 
    CHECK_C (EC_POINT_mul(params->group, elGamalRandPt, elGamalRand, NULL, NULL, params->bn_ctx));

    /* Encrypt all those ciphertexts with a transport key. */
    uint8_t innerCtBuf[HSM_GROUP_SIZE * PUNC_ENC_REPL * IBE_CT_LEN];
    memset(innerCtBuf, 0, HSM_GROUP_SIZE * IBE_CT_LEN);
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            IBE_MarshalCt(innerCtBuf + (i * PUNC_ENC_REPL + j) * IBE_CT_LEN, IBE_MSG_LEN, recoveryCts[i][j]);
        }
    }

    Params_pointToBytes(params, elGamalRandBuf, elGamalRandPt);
    CHECK_C (hash_to_bytes(keyBuf, AES256_KEY_LEN, elGamalRandBuf, 33));
    CHECK_C (aesEncrypt(keyBuf, innerCtBuf, HSM_GROUP_SIZE * PUNC_ENC_REPL * IBE_CT_LEN, c->iv, c->ct));

    printf("done with all the encryption\n");

    /*  TODO: need to use elGamalRand to generate pad to XOR ciphertexts with */

    /* Choose HSMs to hide salt  r. */
    //chooseHsmsFromSalt(params, h2, c->s);

    /* Split salt r into shares. */
    //CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, r, params->prime, saltShares));

    /* Encrypt [r]_i for each HSM. */
    /*for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t msg[IBE_MSG_LEN];
        memset(msg, 0, IBE_MSG_LEN);
        Shamir_Marshal(msg, saltShares[i]);
        memset(msg + SHAMIR_MARSHALLED_SIZE, 0xff, SHA256_DIGEST_LENGTH);
        printf("saltShares[%d]: ", i);
        for (int j = 0; j < IBE_MSG_LEN; j++) {
            printf("%x", msg[j]);
        }
        printf("\n");
 
        CHECK_C (HSM_Encrypt(d->hsms[h2[i]], userID  + 2, msg, IBE_MSG_LEN, c->saltCts[i]));
    }*/

cleanup:
    if (r) BN_free(r);

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        if (saveKeyShares[i]) ShamirShare_free(saveKeyShares[i]);
        if (saltShares[i]) ShamirShare_free(saltShares[i]);
        if (rShares[i]) ShamirShare_free(rShares[i]);
        if (pinShares[i]) ShamirShare_free(pinShares[i]);
        if (h1Bns[i]) BN_free(h1Bns[i]);
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            if (recoveryCts[i][j]) IBE_ciphertext_free(recoveryCts[i][j]);
        }
        for (int j = 0; j < NUM_ATTEMPTS; j++) {
            if (aShares[j][i]) ShamirShare_free(aShares[j][i]);
            if (bShares[j][i]) ShamirShare_free(bShares[j][i]);
            if (cShares[j][i]) ShamirShare_free(cShares[j][i]);
        }
    }
    return rv;
}
