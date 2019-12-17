#include <stdlib.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#include "common.h"
#include "datacenter.h"
#include "hidapi.h"
#include "hsm.h"
#include "params.h"
#include "shamir.h"
#include "u2f_util.h"

#define VENDOR_ID 0x0483
#define PRODUCT_ID 0xa2ca

using namespace std;

RecoveryCiphertext *RecoveryCiphertext_new() {
    int rv = ERROR;
    RecoveryCiphertext *c = NULL;
    CHECK_A (c = (RecoveryCiphertext *)malloc(sizeof(RecoveryCiphertext)));
    for (int i = 0; i < HSM_GROUP_SIZE; i++)  {
        CHECK_A (c->transportKeyCts[i] = IBE_ciphertext_new(IBE_MSG_LEN));
    }
    CHECK_A (c->r = BN_new());
cleanup:
    if (rv == ERROR) {
        RecoveryCiphertext_free(c);
        return NULL;
    }
    return c;
}

void RecoveryCiphertext_free(RecoveryCiphertext *c) {
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        if (c && c->transportKeyCts[i]) IBE_ciphertext_free(c->transportKeyCts[i]);
    }
    if (c && c->r) BN_free(c->r);
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

  CHECK_C (!U2Fob_open(h->device, deviceName));
  CHECK_C (!U2Fob_init(h->device));

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
  devs = hid_enumerate(0x0, 0x0);
  cur_dev = devs;
  while (cur_dev) {

    if ((cur_dev->vendor_id == VENDOR_ID) &&
        (cur_dev->product_id == PRODUCT_ID)) {
      CHECK_C(create_hsm(d->hsms[i], cur_dev->path, i));
      printf("created hsm %d/%d\n", i, NUM_HSMS);
      i++;
      if (i == NUM_HSMS) break;
    }
    cur_dev = cur_dev->next;
  }

cleanup:
  hid_exit();
  return rv;
}

int Datacenter_Setup(Datacenter *d) {
    int rv;
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_C (HSM_GetMpk(d->hsms[i]));
        CHECK_C (HSM_Setup(d->hsms[i]));
    }
cleanup:
    return rv;
}

int Datacenter_SmallSetup(Datacenter *d) {
    int rv;
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_C (HSM_GetMpk(d->hsms[i]));
        CHECK_C (HSM_SmallSetup(d->hsms[i]));
    }
cleanup:
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
    BIGNUM *s = NULL;
    BIGNUM *saltHashes[HSM_GROUP_SIZE];
    ShamirShare *saveKeyShares[HSM_GROUP_SIZE];
    IBE_ciphertext *innerCts[HSM_GROUP_SIZE];
    BIGNUM *transportKey = NULL;
    uint8_t transportKeyBuf[AES128_KEY_LEN];
    ShamirShare *transportKeyShares[HSM_GROUP_SIZE];

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        CHECK_A (saveKeyShares[i] = ShamirShare_new());
        CHECK_A (transportKeyShares[i] = ShamirShare_new());
        CHECK_A (innerCts[i] = IBE_ciphertext_new(IBE_MSG_LEN));
    }
    CHECK_A (transportKey = BN_new());

    printf("start save key: %s\n", BN_bn2hex(saveKey));

    /* Choose salts. */
    CHECK_A (s = BN_new());
    CHECK_C (BN_rand_range(c->r, params->prime));
    CHECK_C (BN_rand_range(s, params->prime));

    /* Hash salt and pin to choose recovery HSMs. */
    chooseHsmsFromSaltAndPin(params, h1, saltHashes, c->r, pin);
    
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
    uint8_t innerCtBuf[HSM_GROUP_SIZE * IBE_CT_LEN];
    memset(innerCtBuf, 0, HSM_GROUP_SIZE * IBE_CT_LEN);
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        IBE_MarshalCt(innerCtBuf + i * IBE_CT_LEN, IBE_MSG_LEN, innerCts[i]);
    }

    printf("inner ct: ");
    for (int i = 0; i < HSM_GROUP_SIZE * IBE_CT_LEN; i++) {
        printf("%x ", innerCtBuf[i]);
    }
    printf("\n");


    CHECK_C (BN_rand_range(transportKey, params->prime));
    printf("transport key: %s\n", BN_bn2hex(transportKey));
    memset(transportKeyBuf, 0, AES128_KEY_LEN);
    BN_bn2bin(transportKey, transportKeyBuf);
    CHECK_C (aesGcmEncrypt(transportKeyBuf, innerCtBuf, HSM_GROUP_SIZE * IBE_CT_LEN, c->iv, c->tag, c->ct));
   
    /* Make shares of transport key. */
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, transportKey, params->prime, transportKeyShares));

    /* Encrypt shares of transport key to recovery HSMs. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        /* Have an empty 16 bytes here, might want to fix. */
        uint8_t msg[IBE_MSG_LEN];
        memset(msg, 0, IBE_MSG_LEN);
        Shamir_Marshal(msg, transportKeyShares[i]);
        memset(msg + SHAMIR_MARSHALLED_SIZE, 0xff, SHA256_DIGEST_LENGTH);
        CHECK_C (HSM_Encrypt(d->hsms[h1[i]], userID, msg, IBE_MSG_LEN, c->transportKeyCts[i]));
        //IBE_Encrypt(&d->hsms[h1[i]]->mpk, userID, msg, IBE_MSG_LEN, c->transportKeyCts[i]);
         
    }
    // No hiding meta-salt yet.

cleanup:
    if (s) BN_free(s);

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        ShamirShare_free(saveKeyShares[i]);
        ShamirShare_free(transportKeyShares[i]);
        IBE_ciphertext_free(innerCts[i]);
    }
    return rv;
}

int Datacenter_Recover(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, uint8_t pin[PIN_LEN], RecoveryCiphertext *c) {
    int rv = ERROR;
    uint8_t h1[HSM_GROUP_SIZE];
    BIGNUM *saltHashes[HSM_GROUP_SIZE];
    ShamirShare *transportKeyShares[HSM_GROUP_SIZE];
    BIGNUM *transportKey = NULL;
    uint8_t transportKeyBuf[AES128_KEY_LEN];
    uint8_t innerCtBuf[HSM_GROUP_SIZE * IBE_CT_LEN];
    IBE_ciphertext *innerCts[HSM_GROUP_SIZE];
    ShamirShare *saveKeyShares[HSM_GROUP_SIZE];

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        CHECK_A (transportKeyShares[i] = ShamirShare_new());
        CHECK_A (saveKeyShares[i] = ShamirShare_new());
        CHECK_A (innerCts[i] = IBE_ciphertext_new(IBE_MSG_LEN));
    }
    CHECK_A (transportKey = BN_new());

    /* Hash salt and pin to find recovery HSMs. */
    chooseHsmsFromSaltAndPin(params, h1, saltHashes, c->r, pin);
    
    /* Decrypt shares of transport key with HSMs. */
    uint8_t pinHashPlaceholder[SHA256_DIGEST_LENGTH];
    memset(pinHashPlaceholder, 0xff, SHA256_DIGEST_LENGTH);
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t share[IBE_MSG_LEN];
        CHECK_C (HSM_AuthDecrypt(d->hsms[h1[i]], userID, c->transportKeyCts[i], share, IBE_MSG_LEN, pinHashPlaceholder));
        Shamir_Unmarshal(share, transportKeyShares[i]);
    }

    /* Reassemble transport key. */
    CHECK_C (Shamir_ReconstructShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, transportKeyShares, params->prime, transportKey));

    printf("transport key: %s\n", BN_bn2hex(transportKey));

    /* Decrypt ct to get inner ciphertexts using transport key. */
    memset(transportKeyBuf, 0, AES128_KEY_LEN);
    printf("num bytes: %d\n", BN_num_bytes(transportKey));
    BN_bn2bin(transportKey, transportKeyBuf);
    CHECK_C (aesGcmDecrypt(transportKeyBuf, innerCtBuf, c->iv, c->tag, c->ct, HSM_GROUP_SIZE * IBE_CT_LEN));
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        IBE_UnmarshalCt(innerCtBuf + i * IBE_CT_LEN, IBE_MSG_LEN, innerCts[i]);
    }

    /* Decrypt inner cts with HSMs. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t share[IBE_MSG_LEN];
        // TODO: SHOULD ALSO CHECK THE PIN!! This message has pin hash appended

        uint8_t pinHash[SHA256_DIGEST_LENGTH];
        BN_bn2bin(saltHashes[i], pinHash);
        CHECK_C (HSM_AuthDecrypt(d->hsms[h1[i]], userID, innerCts[i], share, IBE_MSG_LEN, pinHash));
        printf("share[%d]: ", i);
        for (int j = 0; j < IBE_MSG_LEN; j++) {
            printf("%x ", share[j]);
        }
        printf("\n");
        Shamir_Unmarshal(share, saveKeyShares[i]);
    }

    /* Reassemble original saveKey. */
    CHECK_C (Shamir_ReconstructShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, saveKeyShares, params->prime, saveKey));
    printf("done: %s\n", BN_bn2hex(saveKey));

cleanup:
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        if (transportKeyShares[i]) ShamirShare_free(transportKeyShares[i]);
        if (innerCts[i]) IBE_ciphertext_free(innerCts[i]);
        if (saveKeyShares[i]) ShamirShare_free(saveKeyShares[i]);
    }
    BN_free(transportKey);
    return rv;
}
