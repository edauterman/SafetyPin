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
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t *in = NULL;
        int len = BN_num_bytes(salt) + PIN_LEN;
        CHECK_A (in = (uint8_t *)malloc(len));
        BN_bn2bin(salt, in);
        memcpy(in + BN_num_bytes(salt), pin, PIN_LEN);
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



/* bns: prime, numHsms
 * bn_ctx 
 * make IBE_MSG_LEN = 32 + 16 = 48*/

int Datacenter_Save(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, uint8_t pin[PIN_LEN], RecoveryCiphertext *c) {
    int rv = ERROR;
    uint8_t h1[HSM_GROUP_SIZE];
    BIGNUM *r = NULL;
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

    /* Choose salts. */
    CHECK_A (r = BN_new());
    CHECK_A (s = BN_new());
    CHECK_C (BN_rand_range(r, params->prime));
    CHECK_C (BN_rand_range(s, params->prime));

    /* Hash salt and pin to choose recovery HSMs. */
    chooseHsmsFromSaltAndPin(params, h1, saltHashes, r, pin);
    
    /* Split saveKey into shares */
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, saveKey, params->prime, saveKeyShares));

    /* Encrypt [saveKey]_i, H(pin, salt) to each HSM. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        uint8_t msg[IBE_MSG_LEN];
        memset(msg, 0, IBE_MSG_LEN);
        BN_bn2bin(saveKeyShares[i]->x, msg +  16 - BN_num_bytes(saveKeyShares[i]->x));
        BN_bn2bin(saveKeyShares[i]->y, msg +  32 - BN_num_bytes(saveKeyShares[i]->x));
        BN_bn2bin(saltHashes[i], msg +  48 - BN_num_bytes(saltHashes[i]));
        
        IBE_Encrypt(&d->hsms[h1[i]]->mpk, userID, msg, IBE_MSG_LEN, innerCts[i]);
    }

    /* Encrypt all those ciphertexts with a transport key. */
    uint8_t innerCtBuf[HSM_GROUP_SIZE * IBE_CT_LEN];
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        IBE_MarshalCt(innerCtBuf + i * IBE_CT_LEN, IBE_MSG_LEN, innerCts[i]);
    }
    CHECK_C (BN_rand_range(transportKey, params->prime));
    memset(transportKeyBuf, 0, AES128_KEY_LEN);
    BN_bn2bin(transportKey, transportKeyBuf);
    CHECK_C (aesGcmEncrypt(transportKey, innerCtBuf, HSM_GROUP_SIZE * IBE_CT_LEN, c->iv, c->tag, c->ct));

    /* Make shares of transport key. */
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, transportKey, params->prime, transportKeyShares));

    /* Encrypt shares of transport key to recovery HSMs. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        /* Have an empty 16 bytes here, might want to fix. */
        uint8_t msg[IBE_MSG_LEN];
        memset(msg, 0, IBE_MSG_LEN);
        BN_bn2bin(transportKeyShares[i]->x, msg +  16 - BN_num_bytes(saveKeyShares[i]->x));
        BN_bn2bin(transportKeyShares[i]->y, msg +  32 - BN_num_bytes(saveKeyShares[i]->x));
        IBE_Encrypt(&d->hsms[h1[i]]->mpk, userID, msg, IBE_MSG_LEN, c->transportKeyCts[i]);
         
    }
    // No hiding meta-salt yet.

cleanup:
    if (r) BN_free(r);
    if (s) BN_free(s);

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        ShamirShare_free(saveKeyShares[i]);
    }
    return rv;
}
