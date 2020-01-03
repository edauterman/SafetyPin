#include <stdlib.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <thread>

#include "bls12_381/bls12_381.h"
#include "common.h"
#include "datacenter.h"
#include "hidapi.h"
#include "hsm.h"
#include "params.h"
#include "punc_enc.h"
#include "shamir.h"
#include "u2f_util.h"
#include "punc_enc.h"

#define VENDOR_ID 0x0483
#define PRODUCT_ID 0xa2ca

using namespace std;

RecoveryCiphertext *RecoveryCiphertext_new() {
    int rv = ERROR;
    RecoveryCiphertext *c = NULL;
    CHECK_A (c = (RecoveryCiphertext *)malloc(sizeof(RecoveryCiphertext)));
    for (int i = 0; i < HSM_GROUP_SIZE; i++)  {
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A (c->transportKeyCts[i][j] = IBE_ciphertext_new(IBE_MSG_LEN));
            CHECK_A (c->saltCts[i][j] = IBE_ciphertext_new(IBE_MSG_LEN));
        }
    }
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
            if (c && c->transportKeyCts[i] && c->transportKeyCts[i][j]) IBE_ciphertext_free(c->transportKeyCts[i][j]);
            if (c && c->saltCts[i] && c->saltCts[i][j]) IBE_ciphertext_free(c->saltCts[i][j]);
        }
    }
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
        Datacenter_free(d);
        return NULL;
    }
    return d;
}

void Datacenter_free(Datacenter *d) {
    for (int i = 0; i < NUM_HSMS; i++) {
        U2Fob_destroy(d->hsms[i]->device);
        HSM_free(d->hsms[i]);
    }
    free(d);
}

/* Given the path to the U2F device, initialize the agent. */
int create_hsm(HSM *h, char *deviceName, int i) {
  int rv = ERROR;

  CHECK_A (h->device = U2Fob_create());

  printf("going to create\n");
  CHECK_C (!U2Fob_open(h->device, deviceName));
  printf("opened\n");
  CHECK_C (!U2Fob_init(h->device));
  printf("finished creating\n");

cleanup:
  if (rv == ERROR) {
    HSM_free(h);
  }
  return rv;
}

/* Initialize the datacenter with all the connected HSMst. */
int Datacenter_init(Datacenter *d) {
  int rv = ERROR;
  struct hid_device_info *devs, *cur_dev;
  int i = 0;

  hid_init();
  //devs = hid_enumerate(0x0, 0x0);
  devs = hid_enumerate(VENDOR_ID, PRODUCT_ID);
  cur_dev = devs;
  while (cur_dev) {

    //if ((cur_dev->vendor_id == VENDOR_ID) &&
    //    (cur_dev->product_id == PRODUCT_ID)) {
      printf("serial no: %s\n", cur_dev->serial_number);
      CHECK_C(create_hsm(d->hsms[i], cur_dev->path, i));
      printf("created hsm %d/%d\n", i, NUM_HSMS);
      i++;
      if (i == NUM_HSMS) break;
    //}
    cur_dev = cur_dev->next;
  }

cleanup:
  hid_exit();
  return rv;
}

int Datacenter_Setup(Datacenter *d) {
    int rv;
    thread t[NUM_HSMS];
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_C (HSM_GetMpk(d->hsms[i]));
        printf("Got mpk %d/%d\n", i, NUM_HSMS);
    }
    for (int i = 0; i < NUM_HSMS; i++) {
        t[i] = thread(HSM_Setup, d->hsms[i]);
        printf("Started setup  %d/%d\n", i, NUM_HSMS);
        //HSM_Setup(d->hsms[i]));
    }
    for (int i = 0; i < NUM_HSMS; i++) {
        t[i].join();
        printf("Done with setup  for %d/%d\n", i, NUM_HSMS);
    }
cleanup:
    return rv;
}

int Datacenter_SmallSetup(Datacenter *d) {
    int rv;
    thread t[NUM_HSMS];
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_C (HSM_GetMpk(d->hsms[i]));
        printf("Got mpk %d/%d\n", i, NUM_HSMS);
    }
    for (int i = 0; i < NUM_HSMS; i++) {
        t[i] = thread(HSM_SmallSetup, d->hsms[i]);
        printf("Started setup  %d/%d\n", i, NUM_HSMS);
        //HSM_Setup(d->hsms[i]));
    }
    for (int i = 0; i < NUM_HSMS; i++) {
        t[i].join();
        printf("Done with setup  for %d/%d\n", i, NUM_HSMS);
    }
cleanup:
    return rv;
}

int Datacenter_TestSetup(Datacenter *d) {
    int rv;
    uint8_t *cts;
    uint8_t msk[KEY_LEN];
    uint8_t hmacKey[KEY_LEN];
    embedded_pairing_bls12_381_g2_t mpk;

    CHECK_A (cts = (uint8_t *)malloc(TREE_SIZE * CT_LEN));

    printf("going to build tree\n");
    PuncEnc_BuildTree(cts, msk, hmacKey, &mpk);
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_C (HSM_GetMpk(d->hsms[i]));
        CHECK_C (HSM_TestSetupInput(d->hsms[i], cts, msk, hmacKey, &mpk));
        printf("Done with setup for %d/%d\n", i, NUM_HSMS);
    }
cleanup:
    if (cts) free(cts);
    return rv;
}

int chooseHsmsFromSalt(Params *params, uint8_t h[HSM_GROUP_SIZE], BIGNUM *salt) {
    int rv = ERROR;
    BIGNUM *hsm;
    uint8_t out[SHA256_DIGEST_LENGTH];
    BIGNUM *saltHashes[HSM_GROUP_SIZE];

    CHECK_A (hsm = BN_new());

    /* Hash salt and pin to choose recovery HSMs. */
    printf("num hsms: %s\n", BN_bn2hex(params->numHsms));
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
}

int chooseHsmsFromSaltAndPin(Params *params, uint8_t h[HSM_GROUP_SIZE], BIGNUM *saltHashes[HSM_GROUP_SIZE], BIGNUM *salt, uint8_t pin[PIN_LEN]) {
    int rv = ERROR;
    BIGNUM *hsm;
    uint8_t out[SHA256_DIGEST_LENGTH];

    CHECK_A (hsm = BN_new());

    /* Hash salt and pin to choose recovery HSMs. */
    printf("num hsms: %s\n", BN_bn2hex(params->numHsms));
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t *in = NULL;
        int len = BN_num_bytes(salt) + PIN_LEN + 1;
        CHECK_A (in = (uint8_t *)malloc(len));
        in[0] = i;
        BN_bn2bin(salt, in + 1);
        memcpy(in + BN_num_bytes(salt) + 1, pin, PIN_LEN);
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
}

void marshalShareAndHash(uint8_t *buf, ShamirShare *share, BIGNUM *hash) {
    Shamir_Marshal(buf, share);
    printf("hash bytes: %d\n", BN_num_bytes(hash));
    BN_bn2bin(hash, buf + SHAMIR_MARSHALLED_SIZE + 32 - BN_num_bytes(hash));
}

void unmarshalShareAndHash(uint8_t *buf, ShamirShare *share, BIGNUM *hash) {
    Shamir_Unmarshal(buf, share);
    BN_bin2bn(buf + SHAMIR_MARSHALLED_SIZE, 16, hash);
}

/* bns: prime, numHsms
 * bn_ctx 
 * make IBE_MSG_LEN = 32 + 16 = 48*/

int Datacenter_Save(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, uint8_t pin[PIN_LEN], RecoveryCiphertext *c) {
    int rv = ERROR;
    uint8_t h1[HSM_GROUP_SIZE];
    uint8_t h2[HSM_GROUP_SIZE];
    BIGNUM *r = NULL;
    BIGNUM *saltHashes[HSM_GROUP_SIZE];
    ShamirShare *saveKeyShares[HSM_GROUP_SIZE];
    IBE_ciphertext *innerCts[HSM_GROUP_SIZE][PUNC_ENC_REPL];
    BIGNUM *transportKey = NULL;
    uint8_t transportKeyBuf[AES128_KEY_LEN];
    ShamirShare *transportKeyShares[HSM_GROUP_SIZE];
    ShamirShare *saltShares[HSM_GROUP_SIZE];

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        CHECK_A (saveKeyShares[i] = ShamirShare_new());
        CHECK_A (transportKeyShares[i] = ShamirShare_new());
        CHECK_A (saltShares[i] = ShamirShare_new());
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A (innerCts[i][j] = IBE_ciphertext_new(IBE_MSG_LEN));
        }
    }
    CHECK_A (transportKey = BN_new());

    printf("start save key: %s\n", BN_bn2hex(saveKey));

    /* Choose salts. */
    CHECK_A (r = BN_new());
    CHECK_C (BN_rand_range(r, params->prime));
    CHECK_C (BN_rand_range(c->s, params->prime));

    printf("r: %s\n", BN_bn2hex(r));

    /* Hash salt and pin to choose recovery HSMs. */
    chooseHsmsFromSaltAndPin(params, h1, saltHashes, r, pin);
    
    /* Split saveKey into shares */
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, saveKey, params->prime, saveKeyShares));

    /* Encrypt [saveKey]_i, H(pin, salt) to each HSM. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t msg[IBE_MSG_LEN];
        memset(msg, 0, IBE_MSG_LEN);
        marshalShareAndHash(msg, saveKeyShares[i], saltHashes[i]);
        
        printf("share[%d]: ", i);
        for (int j = 0; j < IBE_MSG_LEN; j++) {
            printf("%x ", msg[j]);
        }
        printf("\n");
        
        CHECK_C (HSM_Encrypt(d->hsms[h1[i]], userID, msg, IBE_MSG_LEN, innerCts[i]));

    }

    /* Encrypt all those ciphertexts with a transport key. */
    uint8_t innerCtBuf[HSM_GROUP_SIZE * PUNC_ENC_REPL * IBE_CT_LEN];
    memset(innerCtBuf, 0, HSM_GROUP_SIZE * IBE_CT_LEN);
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            IBE_MarshalCt(innerCtBuf + (i * PUNC_ENC_REPL + j) * IBE_CT_LEN, IBE_MSG_LEN, innerCts[i][j]);
        }
    }

    CHECK_C (BN_rand_range(transportKey, params->prime));
    printf("transport key: %s\n", BN_bn2hex(transportKey));
    memset(transportKeyBuf, 0, AES128_KEY_LEN);
    BN_bn2bin(transportKey, transportKeyBuf);
    CHECK_C (aesGcmEncrypt(transportKeyBuf, innerCtBuf, HSM_GROUP_SIZE * PUNC_ENC_REPL * IBE_CT_LEN, c->iv, c->tag, c->ct));
   
    /* Make shares of transport key. */
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, transportKey, params->prime, transportKeyShares));

    /* Encrypt shares of transport key to recovery HSMs. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        /* Have an empty 16 bytes here, might want to fix. */
        uint8_t msg[IBE_MSG_LEN];
        memset(msg, 0, IBE_MSG_LEN);
        Shamir_Marshal(msg, transportKeyShares[i]);
        memset(msg + SHAMIR_MARSHALLED_SIZE, 0xff, SHA256_DIGEST_LENGTH);
        CHECK_C (HSM_Encrypt(d->hsms[h1[i]], userID + 1, msg, IBE_MSG_LEN, c->transportKeyCts[i]));
         
    }

    /* Choose HSMs to hide salt  r. */
    chooseHsmsFromSalt(params, h2, c->s);

    /* Split salt r into shares. */
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, r, params->prime, saltShares));

    /* Encrypt [r]_i for each HSM. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t msg[IBE_MSG_LEN];
        memset(msg, 0, IBE_MSG_LEN);
        Shamir_Marshal(msg, saltShares[i]);
        memset(msg + SHAMIR_MARSHALLED_SIZE, 0xff, SHA256_DIGEST_LENGTH);
        CHECK_C (HSM_Encrypt(d->hsms[h2[i]], userID  + 2, msg, IBE_MSG_LEN, c->saltCts[i]));
    }

cleanup:
    if (r) BN_free(r);

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        if (saveKeyShares[i]) ShamirShare_free(saveKeyShares[i]);
        if (transportKeyShares[i]) ShamirShare_free(transportKeyShares[i]);
        if (saltShares[i]) ShamirShare_free(saltShares[i]);
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            if (innerCts[i] && innerCts[i][j]) IBE_ciphertext_free(innerCts[i][j]);
        }
    }
    return rv;
}

int Datacenter_Recover(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, uint8_t pin[PIN_LEN], RecoveryCiphertext *c) {
    int rv = ERROR;
    uint8_t h1[HSM_GROUP_SIZE];
    uint8_t h2[HSM_GROUP_SIZE];
    BIGNUM *saltHashes[HSM_GROUP_SIZE];
    ShamirShare *transportKeyShares[HSM_GROUP_SIZE];
    BIGNUM *transportKey = NULL;
    BIGNUM *r = NULL;
    uint8_t transportKeyBuf[AES128_KEY_LEN];
    uint8_t innerCtBuf[HSM_GROUP_SIZE * PUNC_ENC_REPL * IBE_CT_LEN];
    IBE_ciphertext *innerCts[HSM_GROUP_SIZE][PUNC_ENC_REPL];
    ShamirShare *saveKeyShares[HSM_GROUP_SIZE];
    ShamirShare *saltShares[HSM_GROUP_SIZE];
    thread t0[HSM_GROUP_SIZE];
    thread t1[HSM_GROUP_SIZE];
    thread t2[HSM_GROUP_SIZE];

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        CHECK_A (transportKeyShares[i] = ShamirShare_new());
        CHECK_A (saveKeyShares[i] = ShamirShare_new());
        CHECK_A (saltShares[i] = ShamirShare_new());
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A (innerCts[i][j] = IBE_ciphertext_new(IBE_MSG_LEN));
        }
    }
    CHECK_A (transportKey = BN_new());
    CHECK_A (r = BN_new());

    /* Hash meta-salt to find salt HSMs. */
    chooseHsmsFromSalt(params, h2, c->s);

    uint8_t pinHashPlaceholder[SHA256_DIGEST_LENGTH];
    memset(pinHashPlaceholder, 0xff, SHA256_DIGEST_LENGTH);
    uint8_t saltShareBufs[HSM_GROUP_SIZE][IBE_MSG_LEN];
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t0[i] = thread(HSM_AuthDecrypt, d->hsms[h2[i]], userID + 2, c->saltCts[i], saltShareBufs[i], IBE_MSG_LEN, pinHashPlaceholder);
    }
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t0[i].join();
        Shamir_Unmarshal(saltShareBufs[i], saltShares[i]);
    }

    /* Reassemble salt r. */
    CHECK_C (Shamir_ReconstructShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, saltShares, params->prime, r));

    printf("r: %s\n", BN_bn2hex(r));

    /* Hash salt and pin to find recovery HSMs. */
    chooseHsmsFromSaltAndPin(params, h1, saltHashes, r, pin);
    
    /* Decrypt shares of transport key with HSMs. */
    uint8_t transportKeyShareBufs[HSM_GROUP_SIZE][IBE_MSG_LEN];
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t1[i] = thread(HSM_AuthDecrypt, d->hsms[h1[i]], userID + 1, c->transportKeyCts[i], transportKeyShareBufs[i], IBE_MSG_LEN, pinHashPlaceholder);
        //CHECK_C (HSM_AuthDecrypt(d->hsms[h1[i]], userID, c->transportKeyCts[i], share, IBE_MSG_LEN, pinHashPlaceholder));
        //Shamir_Unmarshal(share, transportKeyShares[i]);
    }
    for (int i = 0; i < HSM_GROUP_SIZE; i++)  {
        t1[i].join();
        printf("transport key share %d/%d: ", i, HSM_GROUP_SIZE);
        for (int j = 0; j < HSM_GROUP_SIZE; j++) {
            printf("%x ", transportKeyShareBufs[i][j]);
        }
        printf("\n");
        Shamir_Unmarshal(transportKeyShareBufs[i], transportKeyShares[i]);
    }

    /* Reassemble transport key. */
    CHECK_C (Shamir_ReconstructShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, transportKeyShares, params->prime, transportKey));

    printf("transport key: %s\n", BN_bn2hex(transportKey));

    /* Decrypt ct to get inner ciphertexts using transport key. */
    memset(transportKeyBuf, 0, AES128_KEY_LEN);
    printf("num bytes: %d\n", BN_num_bytes(transportKey));
    BN_bn2bin(transportKey, transportKeyBuf);
    CHECK_C (aesGcmDecrypt(transportKeyBuf, innerCtBuf, c->iv, c->tag, c->ct, HSM_GROUP_SIZE * PUNC_ENC_REPL * IBE_CT_LEN));
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            IBE_UnmarshalCt(innerCtBuf + (i * PUNC_ENC_REPL + j) * IBE_CT_LEN, IBE_MSG_LEN, innerCts[i][j]);
        }
    }

    /* Decrypt inner cts with HSMs. */
    uint8_t saveKeyShareBufs[HSM_GROUP_SIZE][IBE_MSG_LEN];
    uint8_t pinHashes[HSM_GROUP_SIZE][SHA256_DIGEST_LENGTH];
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        BN_bn2bin(saltHashes[i], pinHashes[i]);
        t2[i] = thread(HSM_AuthDecrypt, d->hsms[h1[i]], userID, innerCts[i], saveKeyShareBufs[i], IBE_MSG_LEN, pinHashes[i]);
        //CHECK_C (HSM_AuthDecrypt(d->hsms[h1[i]], userID, innerCts[i], share, IBE_MSG_LEN, pinHash));
        //Shamir_Unmarshal(share, saveKeyShares[i]);
    }
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t2[i].join();
        Shamir_Unmarshal(saveKeyShareBufs[i], saveKeyShares[i]);
    }

    /* Reassemble original saveKey. */
    CHECK_C (Shamir_ReconstructShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, saveKeyShares, params->prime, saveKey));
    printf("done: %s\n", BN_bn2hex(saveKey));

cleanup:
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        if (transportKeyShares[i]) ShamirShare_free(transportKeyShares[i]);
        if (saveKeyShares[i]) ShamirShare_free(saveKeyShares[i]);
        if (saltShares[i]) ShamirShare_free(saltShares[i]);
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            if (innerCts[i] && innerCts[i][j]) IBE_ciphertext_free(innerCts[i][j]);
        }
    }
    BN_free(transportKey);
    BN_free(r);
    return rv;
}