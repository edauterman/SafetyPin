#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <thread>

#include "bls12_381/bls12_381.h"
#include "common.h"
#include "datacenter.h"
#include "hidapi.h"
#include "hsm.h"
#include "mpc.h"
#include "params.h"
#include "punc_enc.h"
#include "shamir.h"
#include "u2f_util.h"
#include "punc_enc.h"
#include "usb.h"

#define VENDOR_ID 0x0483
#define PRODUCT_ID 0xa2ca

using namespace std;

//const char *HANDLES[] = {
//    "/dev/serial/by-id/usb-SoloKeys_Solo_3.0.0-1-gf91fb79_206F37AE5048-if01",
//};
const char *HANDLES[] = {
    "/dev/ttyACM0",
    "/dev/ttyACM1",
    "/dev/ttyACM2",
    "/dev/ttyACM3",
    "/dev/ttyACM4",
    "/dev/ttyACM5",
    "/dev/ttyACM6",
    "/dev/ttyACM7",
    "/dev/ttyACM8",
    "/dev/ttyACM9",
    "/dev/ttyACM10",
    "/dev/ttyACM11",
    "/dev/ttyACM12",
    "/dev/ttyACM13",
    "/dev/ttyACM14",
    "/dev/ttyACM15",
    "/dev/ttyACM16",
    "/dev/ttyACM17",
    "/dev/ttyACM18",
    "/dev/ttyACM19",
    "/dev/ttyACM20",
    "/dev/ttyACM21",
    "/dev/ttyACM22",
    "/dev/ttyACM23",
    "/dev/ttyACM24",
    "/dev/ttyACM25",
    "/dev/ttyACM26",
    "/dev/ttyACM27",
    "/dev/ttyACM28",
    "/dev/ttyACM29",
    "/dev/ttyACM30",
    "/dev/ttyACM31",
    "/dev/ttyACM32",
    "/dev/ttyACM33",
    "/dev/ttyACM34",
    "/dev/ttyACM35",
    "/dev/ttyACM36",
    "/dev/ttyACM37",
    "/dev/ttyACM38",
    "/dev/ttyACM39",
    "/dev/ttyACM40",
    "/dev/ttyACM41",
    "/dev/ttyACM42",
    "/dev/ttyACM43",
    "/dev/ttyACM44",
    "/dev/ttyACM45",
    "/dev/ttyACM46",
    "/dev/ttyACM47",
    "/dev/ttyACM48",
    "/dev/ttyACM49",
    "/dev/ttyACM50",
    "/dev/ttyACM51",
    "/dev/ttyACM52",
    "/dev/ttyACM53",
    "/dev/ttyACM54",
    "/dev/ttyACM55",
    "/dev/ttyACM56",
    "/dev/ttyACM57",
    "/dev/ttyACM58",
    "/dev/ttyACM59",
    "/dev/ttyACM60",
    "/dev/ttyACM61",
    "/dev/ttyACM62",
    "/dev/ttyACM63",
    "/dev/ttyACM64",
    "/dev/ttyACM65",
    "/dev/ttyACM66",
    "/dev/ttyACM67",
    "/dev/ttyACM68",
    "/dev/ttyACM69",
    "/dev/ttyACM70",
    "/dev/ttyACM71",
    "/dev/ttyACM72",
    "/dev/ttyACM73",
    "/dev/ttyACM74",
    "/dev/ttyACM75",
    "/dev/ttyACM76",
    "/dev/ttyACM77",
    "/dev/ttyACM78",
    "/dev/ttyACM79",
    "/dev/ttyACM80",
    "/dev/ttyACM81",
    "/dev/ttyACM82",
    "/dev/ttyACM83",
    "/dev/ttyACM84",
    "/dev/ttyACM85",
    "/dev/ttyACM86",
    "/dev/ttyACM87",
    "/dev/ttyACM88",
    "/dev/ttyACM89",
    "/dev/ttyACM90",
    "/dev/ttyACM91",
    "/dev/ttyACM92",
    "/dev/ttyACM93",
    "/dev/ttyACM94",
    "/dev/ttyACM95",
    "/dev/ttyACM96",
    "/dev/ttyACM97",
    "/dev/ttyACM98",
    "/dev/ttyACM99",
};
//const char *HANDLES[] = {"/dev/cu.usbmodem208532CA31412"};

typedef struct {
    uint8_t msg[FIELD_ELEM_LEN];
    uint8_t a[FIELD_ELEM_LEN];
    uint8_t b[FIELD_ELEM_LEN];
    uint8_t c[FIELD_ELEM_LEN];
    uint8_t rShare[FIELD_ELEM_LEN];
    uint8_t savePinShare[FIELD_ELEM_LEN];
} MpcMsg;

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
    //CHECK_A (c->s = BN_new());
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
    //if (c && c->s) BN_free(c->s);
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
#ifdef HID
        U2Fob_destroy(d->hsms[i]->hidDevice);
#else
        UsbDevice_free(d->hsms[i]->usbDevice);
#endif
        HSM_free(d->hsms[i]);
    }
    free(d);
}

/* Given the path to the U2F device, initialize the agent. */
int create_hsm(HSM *h, char *deviceName, int i) {
  int rv = ERROR;

  CHECK_A (h->hidDevice = U2Fob_create());

  printf("going to create\n");
  CHECK_C (!U2Fob_open(h->hidDevice, deviceName));
  printf("opened\n");
  CHECK_C (!U2Fob_init(h->hidDevice));
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

#ifdef HID
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
#else
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_A (d->hsms[i]->usbDevice = UsbDevice_new(HANDLES[i]));
    }
#endif

cleanup:
  hid_exit();
  return rv;
}

int setMacKeys(Datacenter *d) {
    int rv;
    uint8_t ***macKeys = NULL;

    CHECK_A (macKeys = (uint8_t ***)malloc(NUM_HSMS * sizeof(uint8_t **)));
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_A (macKeys[i] = (uint8_t **)malloc(NUM_HSMS * sizeof(uint8_t *)));
        for (int j = 0; j < NUM_HSMS; j++) {
            CHECK_A (macKeys[i][j] = (uint8_t *)malloc(KEY_LEN));
        }
    }

    if (NUM_HSMS % 2 != 0) printf("ERROR: NOT AN EVEN NUMBER OF HSMS %d\n", NUM_HSMS);

    for (int i = 0; i < NUM_HSMS; i++) {
    //for (int i = 0; i < NUM_HSMS / 2; i++) {
        for (int j = 0; j < NUM_HSMS; j++) {
        //for (int j = NUM_HSMS / 2; j < NUM_HSMS; j++) {
            CHECK_C (RAND_bytes(macKeys[i][j], KEY_LEN));
            memcpy(macKeys[j][i], macKeys[i][j], KEY_LEN);
        }
    }

    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_C (HSM_SetMacKeys(d->hsms[i], macKeys[i]));
    }
cleanup:
    if (rv == ERROR) printf("Error setting initial MAC keys\n");
    return rv;
}

int Datacenter_Setup(Datacenter *d) {
    int rv;
    thread t[NUM_HSMS];
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_C (HSM_GetMpk(d->hsms[i]));
        CHECK_C (HSM_ElGamalGetPk(d->hsms[i]));
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
    setMacKeys(d);
cleanup:
    return rv;
}

int Datacenter_SmallSetup(Datacenter *d) {
    int rv;
    thread t[NUM_HSMS];
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_C (HSM_GetMpk(d->hsms[i]));
        CHECK_C (HSM_ElGamalGetPk(d->hsms[i]));
        printf("Got mpk and el gamal pk %d/%d\n", i, NUM_HSMS);
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
    setMacKeys(d);
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

    setMacKeys(d);

    printf("going to build tree\n");
    PuncEnc_BuildTree(cts, msk, hmacKey, &mpk);
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_C (HSM_GetMpk(d->hsms[i]));
        CHECK_C (HSM_ElGamalGetPk(d->hsms[i]));
        CHECK_C (HSM_TestSetupInput(d->hsms[i], cts, msk, hmacKey, &mpk));
        printf("Done with setup for %d/%d\n", i, NUM_HSMS);
    }
cleanup:
    if (cts) free(cts);
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
        printf("h[%d] = %d\n", i, h[i]);
    }
cleanup:
    if (hsm) BN_free(hsm);
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
    BIGNUM *elGamalRand = NULL;
    EC_POINT *elGamalRandPt = NULL;
    ShamirShare *saveKeyShares[HSM_GROUP_SIZE];
    ShamirShare *saltShares[HSM_GROUP_SIZE];
    ShamirShare *aShares[HSM_GROUP_SIZE];
    ShamirShare *bShares[HSM_GROUP_SIZE];
    ShamirShare *cShares[HSM_GROUP_SIZE];
    ShamirShare *rShares[HSM_GROUP_SIZE];
    ShamirShare *pinShares[HSM_GROUP_SIZE];
    ShamirShare *elGamalRandShares[HSM_GROUP_SIZE];
    BIGNUM *h1Bns[HSM_GROUP_SIZE];
    EC_POINT *h1Pks[HSM_GROUP_SIZE];
    IBE_ciphertext *recoveryCts[HSM_GROUP_SIZE][PUNC_ENC_REPL];
    uint8_t elGamalRandBuf[33];
    uint8_t keyBuf[AES256_KEY_LEN];
    uint8_t list[6] = {1,2,3,4,5,6};

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        CHECK_A (saveKeyShares[i] = ShamirShare_new());
        CHECK_A (saltShares[i] = ShamirShare_new());
        CHECK_A (aShares[i] = ShamirShare_new());
        CHECK_A (bShares[i] = ShamirShare_new());
        CHECK_A (cShares[i] = ShamirShare_new());
        CHECK_A (rShares[i] = ShamirShare_new());
        CHECK_A (pinShares[i] = ShamirShare_new());
        CHECK_A (elGamalRandShares[i] = ShamirShare_new());
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A (recoveryCts[i][j] = IBE_ciphertext_new(IBE_MSG_LEN));
        }
    }
    CHECK_A (elGamalRandPt = EC_POINT_new(params->group));
    CHECK_A (elGamalRand = BN_new());
    
    printf("start save key: %s\n", BN_bn2hex(saveKey));

    /* Choose salts. */
    CHECK_A (r = BN_new());
    CHECK_C (BN_rand_range(c->r, params->order));
    CHECK_C (BN_rand_range(r, params->order));

    /* Hash salt and pin to choose recovery HSMs. */
    chooseHsmsFromSaltAndPin(params, h1, saltHashes, c->r, pin);
    CHECK_C (intsToBignums(h1Bns, list, HSM_GROUP_SIZE));
    //CHECK_C (intsToBignums(h1Bns, h1, HSM_GROUP_SIZE));

    printf("hashed salt and pin to find HSMs\n");

    /* Split saveKey into shares */
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, saveKey, params->order, saveKeyShares, h1Bns));

    printf("created shares of save key\n");

    /* Generate Beaver triple. */
    CHECK_C (MPC_generateBeaverTripleShares(params, aShares, bShares, cShares, h1Bns));

    printf("created beaver triple\n");

    /* Split r and PIN into shares. */
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, r, params->order, rShares, h1Bns));
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, pin, params->order, pinShares, h1Bns));

    printf("Going to encrypt ciphertexts to each HSM\n");

    /* Encrypt [saveKey]_i, H(pin, salt) to each HSM. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        printf("starting ct %d\n", i);
        uint8_t msg[IBE_MSG_LEN];
        memset(msg, 0, IBE_MSG_LEN);
        
        MpcMsg mpcMsg;
        Shamir_MarshalCompressed(mpcMsg.msg, saveKeyShares[i]);
        Shamir_MarshalCompressed(mpcMsg.a, aShares[i]);
        Shamir_MarshalCompressed(mpcMsg.b, bShares[i]);
        Shamir_MarshalCompressed(mpcMsg.c, cShares[i]);
        Shamir_MarshalCompressed(mpcMsg.rShare, rShares[i]);
        Shamir_MarshalCompressed(mpcMsg.savePinShare, pinShares[i]);

        printf("share[%d]: ", i);
        for (int j = 0; j < IBE_MSG_LEN; j++) {
            printf("%x ", ((uint8_t *)&mpcMsg)[j]);
        }
        printf("\n");

        printf("saveKeyShare[%d]: %s, %s\n", i, BN_bn2hex(saveKeyShares[i]->x), BN_bn2hex(saveKeyShares[i]->y));
        printf("aShare[%d]: %s\n", i, BN_bn2hex(aShares[i]->y));
        printf("bShare[%d]: %s\n", i, BN_bn2hex(bShares[i]->y));
        printf("cShare[%d]: %s\n", i, BN_bn2hex(cShares[i]->y));
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
        if (aShares[i]) ShamirShare_free(aShares[i]);
        if (bShares[i]) ShamirShare_free(bShares[i]);
        if (cShares[i]) ShamirShare_free(cShares[i]);
        if (rShares[i]) ShamirShare_free(rShares[i]);
        if (pinShares[i]) ShamirShare_free(pinShares[i]);
        if (h1Bns[i]) BN_free(h1Bns[i]);
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            if (recoveryCts[i][j]) IBE_ciphertext_free(recoveryCts[i][j]);
        }
    }
    return rv;
}

int Datacenter_Recover(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, BIGNUM *pin, RecoveryCiphertext *c) {
    int rv = ERROR;
    uint8_t h1[HSM_GROUP_SIZE];
    uint8_t h2[HSM_GROUP_SIZE];
    BIGNUM *saltHashes[HSM_GROUP_SIZE];
    BIGNUM *r = NULL;
    BIGNUM *dVal = NULL;
    BIGNUM *eVal = NULL;
    BIGNUM *result = NULL;
    ShamirShare *saveKeyShares[HSM_GROUP_SIZE];
    ShamirShare *pinShares[HSM_GROUP_SIZE];
    ShamirShare **dShares;
    ShamirShare **eShares;
    ShamirShare **resultShares;
    uint8_t ***dMacs;
    uint8_t ***eMacs;
    uint8_t ***resultMacs;
    uint8_t **dMacsCurr;
    uint8_t **eMacsCurr;
    uint8_t **resultMacsCurr;
    thread t0[HSM_GROUP_SIZE];
    thread t1[HSM_GROUP_SIZE];
    thread t2[HSM_GROUP_SIZE];
    thread t3[HSM_GROUP_SIZE];
    BIGNUM *h1Bns[HSM_GROUP_SIZE];
    uint8_t list[6] = {1,2,3,4,5,6};
    uint8_t dOrder[2 * HSM_THRESHOLD_SIZE];
    uint8_t eOrder[2 * HSM_THRESHOLD_SIZE];
    uint8_t resultOrder[2 * HSM_THRESHOLD_SIZE];
    uint8_t validHsms[2 * HSM_THRESHOLD_SIZE];
    ShamirShare **dValidShares;
    ShamirShare **eValidShares;
    ShamirShare **resultValidShares;
    uint8_t innerCtBuf[HSM_GROUP_SIZE * PUNC_ENC_REPL * IBE_CT_LEN];
    IBE_ciphertext *recoveryCts[HSM_GROUP_SIZE][PUNC_ENC_REPL];
    ElGamalMsgShare *elGamalRandShares[HSM_GROUP_SIZE];
    EC_POINT *elGamalRand =  NULL;
    uint8_t elGamalRandBuf[33];
    uint8_t keyBuf[AES256_KEY_LEN];

    CHECK_A (dShares = (ShamirShare **)malloc(HSM_GROUP_SIZE * sizeof(ShamirShare *)));
    CHECK_A (eShares = (ShamirShare **)malloc(HSM_GROUP_SIZE * sizeof(ShamirShare *)));
    CHECK_A (resultShares = (ShamirShare **)malloc(HSM_GROUP_SIZE * sizeof(ShamirShare *)));
    CHECK_A (dValidShares = (ShamirShare **)malloc(2 * HSM_THRESHOLD_SIZE * sizeof(ShamirShare *)));
    CHECK_A (eValidShares = (ShamirShare **)malloc(2 * HSM_THRESHOLD_SIZE * sizeof(ShamirShare *)));
    CHECK_A (resultValidShares = (ShamirShare **)malloc(2 * HSM_THRESHOLD_SIZE * sizeof(ShamirShare *)));
    CHECK_A (dMacs = (uint8_t ***)malloc(HSM_GROUP_SIZE * sizeof(uint8_t **)));
    CHECK_A (eMacs = (uint8_t ***)malloc(HSM_GROUP_SIZE * sizeof(uint8_t **)));
    CHECK_A (resultMacs = (uint8_t ***)malloc(HSM_GROUP_SIZE * sizeof(uint8_t **)));

    CHECK_A (dMacsCurr = (uint8_t **)malloc(2 * HSM_THRESHOLD_SIZE * sizeof(uint8_t *)));
    CHECK_A (eMacsCurr = (uint8_t **)malloc(2 * HSM_THRESHOLD_SIZE * sizeof(uint8_t *)));
    CHECK_A (resultMacsCurr = (uint8_t **)malloc(2 * HSM_THRESHOLD_SIZE * sizeof(uint8_t *)));

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        CHECK_A (saveKeyShares[i] = ShamirShare_new());
        CHECK_A (pinShares[i] = ShamirShare_new());
        CHECK_A (dShares[i] = ShamirShare_new());
        CHECK_A (eShares[i] = ShamirShare_new());
        CHECK_A (resultShares[i] = ShamirShare_new());
        CHECK_A (dMacs[i] = (uint8_t **)malloc(HSM_GROUP_SIZE * sizeof(uint8_t *)));
        CHECK_A (eMacs[i] = (uint8_t **)malloc(HSM_GROUP_SIZE * sizeof(uint8_t *)));
        CHECK_A (resultMacs[i] = (uint8_t **)malloc(HSM_GROUP_SIZE * sizeof(uint8_t *)));
        CHECK_A (elGamalRandShares[i] = ElGamalMsgShare_new(params));
        for (int j = 0; j < HSM_GROUP_SIZE; j++) {
            CHECK_A (dMacs[i][j] = (uint8_t *)malloc(SHA256_DIGEST_LENGTH));
            CHECK_A (eMacs[i][j] = (uint8_t *)malloc(SHA256_DIGEST_LENGTH));
            CHECK_A (resultMacs[i][j] = (uint8_t *)malloc(SHA256_DIGEST_LENGTH));
        }
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A  (recoveryCts[i][j] = IBE_ciphertext_new(IBE_MSG_LEN));
        }
    }
    CHECK_A (r = BN_new());
    CHECK_A (dVal = BN_new());
    CHECK_A (eVal = BN_new());
    CHECK_A (result = BN_new());
    CHECK_A (elGamalRand = EC_POINT_new(params->group));

    /* Hash meta-salt to find salt HSMs. */
/*    chooseHsmsFromSalt(params, h2, c->s);

    uint8_t pinHashPlaceholder[SHA256_DIGEST_LENGTH];
    memset(pinHashPlaceholder, 0xff, SHA256_DIGEST_LENGTH);
    uint8_t saltShareBufs[HSM_GROUP_SIZE][IBE_MSG_LEN];
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t0[i] = thread(HSM_AuthDecrypt, d->hsms[h2[i]], userID + 2, c->saltCts[i], saltShareBufs[i], IBE_MSG_LEN, pinHashPlaceholder);
    }
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t0[i].join();
        printf("saltShareBuf[%d] = ", i);
        for (int j = 0; j < IBE_MSG_LEN; j++) {
            printf("%x", saltShareBufs[i][j]);
        }
        printf("\n");
        Shamir_Unmarshal(saltShareBufs[i], saltShares[i]);
    }*/

    /* Reassemble salt r. */
  /*  CHECK_C (Shamir_ReconstructShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, saltShares, params->prime, r));

    printf("r: %s\n", BN_bn2hex(r));
*/
    /* Hash salt and pin to find recovery HSMs. */
    chooseHsmsFromSaltAndPin(params, h1, saltHashes, c->r, pin);
    CHECK_C (intsToBignums(h1Bns, list, HSM_GROUP_SIZE));
    //CHECK_C (intsToBignums(h1Bns, h1, HSM_GROUP_SIZE));
    printf("bns[0] = %s\n", BN_bn2hex(h1Bns[0]));
    printf("bns[1] = %s\n", BN_bn2hex(h1Bns[1]));
    printf("bns[2] = %s\n", BN_bn2hex(h1Bns[2]));

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        elGamalRandShares[i]->x = h1Bns[i];
        //HSM_ElGamalDecrypt(d->hsms[h1[i]], elGamalRandShares[i]->msg, c->elGamalCts[i]->ct);
        t0[i] = thread(HSM_ElGamalDecrypt, d->hsms[h1[i]], elGamalRandShares[i]->msg, c->elGamalCts[i]->ct);
    }
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t0[i].join();
    }
    CHECK_C (ElGamalShamir_ReconstructShares(params, HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, elGamalRandShares, elGamalRand));

    /* Decrypt ct to get inner ciphertexts using elGamalRand. */
    Params_pointToBytes(params, elGamalRandBuf, elGamalRand);
    CHECK_C (hash_to_bytes(keyBuf, AES256_KEY_LEN, elGamalRandBuf, 33));
    CHECK_C (aesDecrypt(keyBuf, innerCtBuf, c->iv, c->ct, HSM_GROUP_SIZE * PUNC_ENC_REPL * IBE_CT_LEN));
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            IBE_UnmarshalCt(innerCtBuf + (i * PUNC_ENC_REPL + j) * IBE_CT_LEN, IBE_MSG_LEN, recoveryCts[i][j]);
        }
    }


    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, pin, params->order, pinShares, h1Bns));

    /* Run stage 1 of MPC with HSMs. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t1[i] = thread(HSM_AuthMPCDecrypt1, d->hsms[h1[i]], dShares[i], eShares[i], dMacs[i], eMacs[i], userID + i, recoveryCts[i], pinShares[i], h1, i + 1);
    }
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t1[i].join();
    }

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
    for (int j = 0; j < HSM_GROUP_SIZE; j++) {
        printf("orig dMacs[%d][%d]", i,j);
        for (int k = 0; k < SHA256_DIGEST_LENGTH; k++) {
            printf("%02x", dMacs[i][j][k]);
        }
        printf("\n");
            
        printf("orig eMacs[%d][%d]", i,j);
        for (int k = 0; k < SHA256_DIGEST_LENGTH; k++) {
            printf("%02x", eMacs[i][j][k]);
        }
        printf("\n");
    }
    }

    /* Reconstruct d and e. TODO: validate shares. */
    CHECK_C (Shamir_FindValidShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, dShares, dValidShares, dOrder, params->order, dVal));
    CHECK_C (Shamir_FindValidShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, eShares, eValidShares, eOrder, params->order, eVal));
    for (int i = 0; i < 2 * HSM_THRESHOLD_SIZE; i++) {
        validHsms[i] = h1[dOrder[i]];   //assume same set of valid shares across d and e
    }

    printf("threshold size %d, group size %d\n", HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE);
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        printf("dShare[%d] = %s\n", i, BN_bn2hex(dShares[i]->y));
    }
    printf("d: %s\n", BN_bn2hex(dVal));
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        printf("eShare[%d] = %s\n", i, BN_bn2hex(eShares[i]->y));
    }
    printf("e: %s\n", BN_bn2hex(eVal));

    /* Run stage 2 of MPC with HSMs. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        for (int j = 0; j < 2 * HSM_THRESHOLD_SIZE; j++) {
            eMacsCurr[j] = eMacs[j][i];
            dMacsCurr[j] = dMacs[j][i];
            
            printf("dMacs[%d]", j);
            for (int k = 0; k < SHA256_DIGEST_LENGTH; k++) {
                printf("%02x", dMacsCurr[j][k]);
            }
            printf("\n");
            
            printf("eMacs[%d]", j);
            for (int k = 0; k < SHA256_DIGEST_LENGTH; k++) {
                printf("%02x", eMacsCurr[j][k]);
            }
            printf("\n");
        }
        t2[i] = thread(HSM_AuthMPCDecrypt2, d->hsms[h1[i]], resultShares[i], resultMacs[i], dVal, eVal, dValidShares, eValidShares, dOrder, eOrder, dMacsCurr, eMacsCurr, validHsms, h1, i + 1);
    }
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t2[i].join();
    }

    /* Reconstruct result. TODO: validate shares. */
    CHECK_C (Shamir_FindValidShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, resultShares, resultValidShares, resultOrder, params->order, result));
    printf("result: %s\n", BN_bn2hex(result));
    for (int i = 0; i < 2 * HSM_THRESHOLD_SIZE; i++) {
        validHsms[i] = h1[resultOrder[i]];   //assume same set of valid shares across d and e
    }


    /* Run stage 3 of MPC with HSMs. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        for (int j = 0; j < 2 * HSM_THRESHOLD_SIZE; j++) {
            resultMacsCurr[j] = resultMacs[j][i];
        }
        t3[i] = thread(HSM_AuthMPCDecrypt3, d->hsms[h1[i]], saveKeyShares[i], result, resultValidShares, resultOrder, resultMacsCurr, validHsms, i + 1);
    }
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t3[i].join();
        printf("saveKeyShare[%d] = %s, %s\n", i, BN_bn2hex(saveKeyShares[i]->x), BN_bn2hex(saveKeyShares[i]->y));
    }

    /* Reassemble original saveKey. */
    CHECK_C (Shamir_ReconstructShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, saveKeyShares, params->order, saveKey));
    printf("done: %s\n", BN_bn2hex(saveKey));

cleanup:
    if (rv == ERROR) printf("ERROR in recovery\n");
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        if (saveKeyShares[i]) ShamirShare_free(saveKeyShares[i]);
        if (pinShares[i]) ShamirShare_free(pinShares[i]);
        if (dShares[i]) ShamirShare_free(dShares[i]);
        if (eShares[i]) ShamirShare_free(eShares[i]);
        if (resultShares[i]) ShamirShare_free(resultShares[i]);
    }
    free(dValidShares);
    free(eValidShares);
    free(resultValidShares);
    BN_free(r);
    BN_free(dVal);
    BN_free(eVal);
    BN_free(result);
    return rv;
}
