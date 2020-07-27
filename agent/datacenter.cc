#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <thread>
#include <sys/time.h>

#include "bls12_381/bls12_381.h"
#include "common.h"
#include "datacenter.h"
#include "hidapi.h"
#include "hsm.h"
#include "log.h"
#include "multisig.h"
#include "params.h"
#include "punc_enc.h"
#include "shamir.h"
#include "u2f_util.h"
#include "punc_enc.h"
#include "usb.h"

#define VENDOR_ID 0x0483
#define PRODUCT_ID 0xa2ca

using namespace std;

/* UPDATE AS NEEDED */
const char *HANDLES[] = {"/dev/ttyACM0",
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


RecoveryCiphertext *RecoveryCiphertext_new(Params *params) {
    int rv = ERROR;
    RecoveryCiphertext *c = NULL;
    CHECK_A (c = (RecoveryCiphertext *)malloc(sizeof(RecoveryCiphertext)));
    for (int i = 0; i < HSM_GROUP_SIZE; i++)  {
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A (c->recoveryCts[i][j] = ElGamalCiphertext_new(params));
        }
    }
    CHECK_A (c->locationHidingCt = LocationHidingCt_new(params, HSM_GROUP_SIZE));
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
    if (c && c->locationHidingCt) LocationHidingCt_free(c->locationHidingCt, HSM_GROUP_SIZE);
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

  CHECK_C (!U2Fob_open(h->hidDevice, deviceName));
  CHECK_C (!U2Fob_init(h->hidDevice));

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
  devs = hid_enumerate(VENDOR_ID, PRODUCT_ID);
  cur_dev = devs;
  while (cur_dev) {
      CHECK_C(create_hsm(d->hsms[i], cur_dev->path, i));
      printf("created hsm %d/%d\n", i, NUM_HSMS);
      i++;
      if (i == NUM_HSMS) break;
    cur_dev = cur_dev->next;
  }
#else
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_A (d->hsms[i]->usbDevice = UsbDevice_new(HANDLES[i]));
    }
#endif

    Log_Init(d->hsms[0]->params);
cleanup:
  hid_exit();
  return rv;
}

/* Run setup for datacenter, performing full puncturable encryption setup on HSMs
 * (necessary for security, but don't use for benchmarking/testing because
 * takes days). */
int Datacenter_Setup(Datacenter *d) {
    int rv;
    thread t[NUM_HSMS];
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_C (HSM_GetMpk(d->hsms[i]));
        CHECK_C (HSM_ElGamalGetPk(d->hsms[i]));
    }
    for (int i = 0; i < NUM_HSMS; i++) {
        t[i] = thread(HSM_Setup, d->hsms[i]);
    }
    for (int i = 0; i < NUM_HSMS; i++) {
        t[i].join();
        printf("Done with setup  for %d/%d\n", i, NUM_HSMS);
    }
cleanup:
    return rv;
}

/* Run setup for datacenter, performing mini puncturable encryption setup
 * on HSMs. */
int Datacenter_SmallSetup(Datacenter *d) {
    int rv;
    thread t[NUM_HSMS];
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_C (HSM_GetMpk(d->hsms[i]));
        CHECK_C (HSM_ElGamalGetPk(d->hsms[i]));
    }
    for (int i = 0; i < NUM_HSMS; i++) {
        t[i] = thread(HSM_SmallSetup, d->hsms[i]);
    }
    for (int i = 0; i < NUM_HSMS; i++) {
        t[i].join();
        printf("Done with setup  for %d/%d\n", i, NUM_HSMS);
    }
cleanup:
    return rv;
}

/* Run setup for datacenter, performing expensive puncturable encryption
 * setup at the host. */
int Datacenter_TestSetup(Datacenter *d) {
    int rv;
    uint8_t *cts;
    uint8_t msk[KEY_LEN];
    uint8_t hmacKey[KEY_LEN];
    EC_POINT **mpk;
    uint8_t logPk[COMPRESSED_PT_SZ];
    thread t[NUM_HSMS];

    CHECK_A (cts = (uint8_t *)malloc(TREE_SIZE * CT_LEN));
    CHECK_A (mpk = (EC_POINT **)malloc(NUM_LEAVES * sizeof(EC_POINT *)));

    printf("Starting to build puncturable encryption tree...\n");
    Log_GetPk(d->hsms[0]->params, logPk);
    PuncEnc_BuildTree(d->hsms[0]->params, cts, msk, hmacKey, mpk);
    printf("Finished building puncturable encryption tree.\n");
    for (int i = 0; i < NUM_HSMS; i++) {
        CHECK_C (HSM_GetMpk(d->hsms[i]));
        CHECK_C (HSM_ElGamalGetPk(d->hsms[i]));
        CHECK_C (HSM_TestSetupInput(d->hsms[i], cts, msk, hmacKey, mpk));
        printf("Done with setup for %d/%d\n", i, NUM_HSMS);
    }
cleanup:
    if (cts) free(cts);
    return rv;
}

/* Run setup for datacenter WITHOUT interacting with HSMs. ONLY use for
 * benchmarking save operations. */
int Datacenter_VirtualSetup(Datacenter *d) {
    int rv;
    uint8_t msk[KEY_LEN];
    uint8_t hmacKey[KEY_LEN];
    embedded_pairing_bls12_381_g2_t mpk;

    for (int i = 0; i < NUM_HSMS; i++) {
        embedded_pairing_core_bigint_256_t sk;
        BIGNUM *x = BN_new();
        for (int j = 0; j < NUM_LEAVES; j++) {
            BN_rand_range(x, d->hsms[i]->params->order);
            EC_POINT_mul(d->hsms[i]->params->group, d->hsms[i]->mpk[j], x, NULL, NULL, d->hsms[i]->params->bn_ctx);
        
        }
        BN_rand_range(x, d->hsms[i]->params->order);
        EC_POINT_mul(d->hsms[i]->params->group, d->hsms[i]->elGamalPk, x, NULL, NULL, d->hsms[i]->params->bn_ctx);
        printf("Done with setup for %d/%d\n", i, NUM_HSMS);
    }
cleanup:
    return rv;
}

/* Choose the set of HSMs using the salt and the PIN. For testing,
 * instrumented to take a group of HSMs in order, but for security should
 * hash the salt and  PIN. */
int chooseHsmsFromSaltAndPin(Params *params, uint8_t h[HSM_GROUP_SIZE], BIGNUM *saltHashes[HSM_GROUP_SIZE], BIGNUM *salt, BIGNUM *pin) {
    int rv = ERROR;
    BIGNUM *hsm;
    uint8_t out[SHA256_DIGEST_LENGTH];

    CHECK_A (hsm = BN_new());

    /* Hash salt and pin to choose recovery HSMs. */
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
	// Assign HSMs in order for testing slice of data center.
        h[i] = i % NUM_HSMS;
        debug_print("h[%d] = %d\n", i, h[i]);
    }
cleanup:
    if (hsm) BN_free(hsm);
    return rv;
}

/* Hash the PIN and salt (used to choose group of HSMs). */
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

/* Encrypt saveKey to set of HSMs for the user userID using the PIN:
 * - Select salts (s, r).
 * - Hash(r, pin) to choose the set of recovery HSMs H. 
 * - c = Enc(Hash(pin), saveKey)
 * - (HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE) share c. 
 * - Encrypt c_i to H_i with puncturable encryption. [puncturable property]
 * - Encrypt c_1, ..., c_HSM_GROUP_SIZE under transport key.
 * - Encrypt shares of transport key to each HSM in H. [location-hiding property] */
int Datacenter_Save(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, BIGNUM *pin, RecoveryCiphertext *c) {
    int rv = ERROR;
    uint8_t h1[HSM_GROUP_SIZE];
    uint8_t h2[HSM_GROUP_SIZE];
    BIGNUM *r = NULL;
    BIGNUM *saltHashes[HSM_GROUP_SIZE];
    uint8_t saltHash[SHA256_DIGEST_LENGTH];
    ShamirShare *saveKeyShares[HSM_GROUP_SIZE];
    ShamirShare *saltShares[HSM_GROUP_SIZE];
    ShamirShare *pinShares[HSM_GROUP_SIZE];
    ShamirShare *elGamalRandShares[HSM_GROUP_SIZE];
    BIGNUM *h1Bns[HSM_GROUP_SIZE];
    EC_POINT *h1Pks[HSM_GROUP_SIZE];
    ElGamal_ciphertext *recoveryCts[HSM_GROUP_SIZE][PUNC_ENC_REPL];
    uint8_t elGamalRand[FIELD_ELEM_LEN];
    uint8_t keyBuf[AES256_KEY_LEN];
    uint8_t list[HSM_GROUP_SIZE];
    BIGNUM *encryptedSaveKey;
    uint8_t encryptedSaveKeyBuf[FIELD_ELEM_LEN];
    uint8_t saveKeyBuf[FIELD_ELEM_LEN];
    int bytesFilled = 0;

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        CHECK_A (saveKeyShares[i] = ShamirShare_new());
        CHECK_A (saltShares[i] = ShamirShare_new());
        CHECK_A (pinShares[i] = ShamirShare_new());
        CHECK_A (elGamalRandShares[i] = ShamirShare_new());
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A (recoveryCts[i][j] = ElGamalCiphertext_new(params));
        }
        list[i] = i + 1;
    }
    CHECK_A (encryptedSaveKey = BN_new());
    
    debug_print("start save key: %s\n", BN_bn2hex(saveKey));

    /* Choose salts. */
    CHECK_C (BN_rand_range(c->s, params->order));
    CHECK_C (BN_rand_range(c->r, params->order));

    /* Hash salt and pin to choose recovery HSMs. */
    chooseHsmsFromSaltAndPin(params, h1, saltHashes, c->r, pin);
    CHECK_C (intsToBignums(h1Bns, list, HSM_GROUP_SIZE));

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
    printf("encryptedSaveKey: %s\n", BN_bn2hex(encryptedSaveKey));

    /* Split saveKey into shares */
    CHECK_C (Shamir_CreateShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, encryptedSaveKey, params->order, saveKeyShares, h1Bns));

    debug_print("created shares of save key\n");

    debug_print("Going to encrypt ciphertexts to each HSM\n");

    /* Encrypt [saveKey]_i, H(pin, salt) to each HSM. */
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        debug_print("starting ct %d\n", i);

        debug_print("saveKeyShare[%d]: %s, %s\n", i, BN_bn2hex(saveKeyShares[i]->x), BN_bn2hex(saveKeyShares[i]->y));
       
        CHECK_C (HSM_Encrypt(d->hsms[h1[i]], userID + i, saveKeyShares[i]->y, recoveryCts[i]));

    }

    CHECK_C (RAND_bytes(elGamalRand, FIELD_ELEM_LEN));
    for (int i = 0; i < HSM_GROUP_SIZE; i++)  {
        CHECK_A (h1Pks[i] = EC_POINT_dup(d->hsms[h1[i]]->elGamalPk, params->group));
    }
    CHECK_C (ElGamalShamir_CreateShares(params, HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, elGamalRand, h1Pks, c->locationHidingCt, h1Bns));

    /* Encrypt all those ciphertexts with a transport key. */
    uint8_t innerCtBuf[HSM_GROUP_SIZE * PUNC_ENC_REPL * ELGAMAL_CT_LEN];
    memset(innerCtBuf, 0, HSM_GROUP_SIZE * ELGAMAL_CT_LEN);
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            ElGamal_Marshal(params, innerCtBuf + (i * PUNC_ENC_REPL + j) * ELGAMAL_CT_LEN, recoveryCts[i][j]);
        }
    }

    CHECK_C (aesEncrypt(elGamalRand, innerCtBuf, HSM_GROUP_SIZE * PUNC_ENC_REPL * ELGAMAL_CT_LEN, c->iv, c->ct));

    printf("Finished saving secret.\n");

cleanup:
    if (r) BN_free(r);

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        if (saveKeyShares[i]) ShamirShare_free(saveKeyShares[i]);
        if (saltShares[i]) ShamirShare_free(saltShares[i]);
        if (h1Bns[i]) BN_free(h1Bns[i]);
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            if (recoveryCts[i][j]) ElGamalCiphertext_free(recoveryCts[i][j]);
        }
    }
    return rv;
}

/* Generate a proof that a recovery attempt was logged. */
int Datacenter_GenerateLogProofs(Datacenter *d, Params *params, LogProof **logProofs, BIGNUM *pin, RecoveryCiphertext *c) {
    int rv;
    uint8_t h[HSM_GROUP_SIZE];
    BIGNUM *saltHashes[HSM_GROUP_SIZE];
    chooseHsmsFromSaltAndPin(params, h, saltHashes, c->r, pin);
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        CHECK_C (Log_Prove(params, logProofs[i], c->locationHidingCt->shares[i]->ct, h));
    } 
cleanup:
    return rv;
}

/* Recover the original save key: 
 * - Hash(salt, PIN) to identify original HSM group H.
 * - Send proof that recovery attempt is logged to each HSM in H. 
 * - Ask each HSM in H to decrypt its share of the transport key.
 * - Reassemble transport key. 
 * - Decrypt puncturable encryption ciphertexts c_1, ..., c_HSM_GROUP_SIZE.
 * - Ask HSM H_i to decrypt c_i. 
 * - Reassemble ciphertext of form Enc(Hash(PIN), saveKey).
 * - Compute Hash(PIN) and decrypt to get saveKey. */
int Datacenter_Recover(Datacenter *d, Params *params, BIGNUM *saveKey, uint16_t userID, BIGNUM *pin, RecoveryCiphertext *c, LogProof **logProofs) {
    int rv = ERROR;
    uint8_t h1[HSM_GROUP_SIZE];
    uint8_t h2[HSM_GROUP_SIZE];
    BIGNUM *saltHashes[HSM_GROUP_SIZE];
    ShamirShare *saveKeyShares[HSM_GROUP_SIZE];
    ShamirShare *pinShares[HSM_GROUP_SIZE];
    thread t0[HSM_GROUP_SIZE];
    thread t1[HSM_GROUP_SIZE];
    thread t2[HSM_GROUP_SIZE];
    BIGNUM *h1Bns[HSM_GROUP_SIZE];
    uint8_t list[HSM_GROUP_SIZE];
    uint8_t innerCtBuf[HSM_GROUP_SIZE * PUNC_ENC_REPL * ELGAMAL_CT_LEN];
    ElGamal_ciphertext *recoveryCts[HSM_GROUP_SIZE][PUNC_ENC_REPL];
    ShamirShare *elGamalRandShares[HSM_GROUP_SIZE];
    uint8_t elGamalRand[32];
    uint8_t keyBuf[AES256_KEY_LEN];
    BIGNUM *encryptedSaveKey;
    uint8_t encryptedSaveKeyBuf[FIELD_ELEM_LEN];
    uint8_t saveKeyBuf[FIELD_ELEM_LEN];
    uint8_t saltHash[SHA256_DIGEST_LENGTH];
    int bytesFilled = 0;
    struct timeval tStart, tLog, tElGamal, tEnd;
    long logSec, logMicro, elGamalSec, elGamalMicro, puncEncSec, puncEncMicro, mpcSec, mpcMicro;
    double logTime, elGamalTime, puncEncTime, mpcTime;

    gettimeofday(&tStart, NULL);

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        CHECK_A (saveKeyShares[i] = ShamirShare_new());
        CHECK_A (elGamalRandShares[i] = ShamirShare_new());
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A  (recoveryCts[i][j] = ElGamalCiphertext_new(params));
        }
        list[i] = i + 1;
    }
    CHECK_A (encryptedSaveKey = BN_new());

    /* Hash salt and pin to find recovery HSMs. */
    chooseHsmsFromSaltAndPin(params, h1, saltHashes, c->r, pin);
    CHECK_C (intsToBignums(h1Bns, list, HSM_GROUP_SIZE));

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t0[i] = thread(HSM_LogProof, d->hsms[h1[i]], c->locationHidingCt->shares[i]->ct, h1, logProofs[i]);
    }
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t0[i].join();
    }
 
    gettimeofday(&tLog, NULL);

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        elGamalRandShares[i]->x = h1Bns[i];
        t1[i] = thread(HSM_ElGamalDecrypt, d->hsms[h1[i]], elGamalRandShares[i]->y, c->locationHidingCt->shares[i]->ct);
    }
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t1[i].join();
    }
    CHECK_C (ElGamalShamir_ReconstructShares(params, HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, c->locationHidingCt, elGamalRandShares, elGamalRand));

    gettimeofday(&tElGamal, NULL);

    /* Decrypt ct to get inner ciphertexts using elGamalRand. */
    CHECK_C (aesDecrypt(elGamalRand, innerCtBuf, c->iv, c->ct, HSM_GROUP_SIZE * PUNC_ENC_REPL * ELGAMAL_CT_LEN));
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            ElGamal_Unmarshal(params, innerCtBuf + (i * PUNC_ENC_REPL + j) * ELGAMAL_CT_LEN, recoveryCts[i][j]);
        }
    }

    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        t2[i] = thread(HSM_AuthDecrypt, d->hsms[h1[i]], userID + i, recoveryCts[i], saveKeyShares[i]->y);
    }
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
	t2[i].join();
        Shamir_UnmarshalX(saveKeyShares[i], i + 1);
    }

    /* Reassemble original saveKey. */
    CHECK_C (Shamir_ReconstructShares(HSM_THRESHOLD_SIZE, HSM_GROUP_SIZE, saveKeyShares, params->order, encryptedSaveKey));

    /* Salted hash of pin. */
    CHECK_C (hashPinAndSalt(pin, c->s, saltHash));
    memset(encryptedSaveKeyBuf, 0, FIELD_ELEM_LEN);
    BN_bn2bin(encryptedSaveKey, encryptedSaveKeyBuf + FIELD_ELEM_LEN - BN_num_bytes(encryptedSaveKey));
    EVP_CIPHER_CTX *ctx; 
    CHECK_A (ctx = EVP_CIPHER_CTX_new());
    CHECK_C (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, saltHash, NULL));
    CHECK_C (EVP_DecryptUpdate(ctx, saveKeyBuf, &bytesFilled, encryptedSaveKeyBuf, SHA256_DIGEST_LENGTH));
    BN_bin2bn(saveKeyBuf, FIELD_ELEM_LEN, saveKey);

    gettimeofday(&tEnd, NULL);

    logSec = (tLog.tv_sec - tStart.tv_sec);
    logMicro = (tLog.tv_usec - tStart.tv_usec);
    logTime = logSec + (logMicro / 1000000.0);
    elGamalSec = (tElGamal.tv_sec - tStart.tv_sec);
    elGamalMicro = (tElGamal.tv_usec - tStart.tv_usec);
    elGamalTime = elGamalSec + (elGamalMicro / 1000000.0);
    puncEncSec = (tEnd.tv_sec - tStart.tv_sec);
    puncEncMicro = (tEnd.tv_usec - tStart.tv_usec);
    puncEncTime = puncEncSec + (puncEncMicro / 1000000.0);

    printf("------ Log time: %f, %d sec, %d micros\n", logTime, logSec, logMicro);
    printf("------ El Gamal time: %f, %d sec, %d micros\n", elGamalTime, elGamalSec, elGamalMicro);
    printf("------ Punc Enc time: %f, %d sec, %d micros\n", puncEncTime, puncEncSec, puncEncMicro);

cleanup:
    if (rv == ERROR) printf("ERROR in recovery\n");
    for (int i = 0; i < HSM_GROUP_SIZE; i++) {
        if (saveKeyShares[i]) ShamirShare_free(saveKeyShares[i]);
    }
    return rv;
}

/* Run every epoch to verify that the log was correctly updated. Each HSM
 * randomly chooses NUM_CHUNKS number of chunks to audit, each with
 * CHUNK_SIZE transitions. If each transition in each chunk is performed
 * correctly, each HSM signs the log head. The host aggregates the signatures
 * and sends them back to the HSMs for verification. 
 *
 * This function assumes that the aggregate public key is already set
 * correctly on all HSMs. */
int Datacenter_LogEpochVerification(Datacenter *d, LogState *state) {
    int rv;
    thread t[NUM_HSMS];
    embedded_pairing_bls12_381_g1_t aggSig;
    embedded_pairing_bls12_381_g1_t sigs[NUM_HSMS];
    struct timeval tStart, tVerify, tEnd;
    long verifySec, verifyMicro, aggSec, aggMicro;
    double verifyTime, aggTime;

    gettimeofday(&tStart, NULL);

    for (int i = 0; i < NUM_HSMS; i++) {
        t[i] = thread(HSM_LogEpochVerification, d->hsms[i], &sigs[i], state);
    }
    for (int i = 0; i < NUM_HSMS; i++) {
        t[i].join();
    }

    for (int i = 0; i < NUM_HSMS; i++) {
        t[i] = thread(HSM_MultisigSign, d->hsms[i], &sigs[i], state->rootsTree->hash);
    }
    for (int i = 0; i < NUM_HSMS; i++) {
        t[i].join();
    }

    gettimeofday(&tVerify, NULL);

    Multisig_AggSigs(sigs, NUM_HSMS, &aggSig);
    for (int i = 0; i < NUM_HSMS; i++) {
        t[i] = thread(HSM_MultisigVerify, d->hsms[i], &aggSig, state->rootsTree->hash);
    }
    for (int i = 0; i < NUM_HSMS; i++) {
        t[i].join();
    }

    gettimeofday(&tEnd, NULL);

    verifySec = (tVerify.tv_sec - tStart.tv_sec);
    verifyMicro = (tVerify.tv_usec - tStart.tv_usec);
    verifyTime = verifySec + (verifyMicro / 1000000.0);
    aggSec = (tEnd.tv_sec - tStart.tv_sec);
    aggMicro = (tEnd.tv_usec - tStart.tv_usec);
    aggTime = aggSec + (aggMicro / 1000000.0);

    printf("------ Transition verification time: %f, %d sec, %d micros\n", verifyTime, verifySec, verifyMicro);
    printf("------ Signature aggregation and verification: %f, %d sec, %d micros\n", aggTime, aggSec, aggMicro);

cleanup:
    return rv;
}
