#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <thread>
#include <vector>
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
const char *HANDLES[] = { "/dev/cu.usbmodem2052338246482" };
/*const char *HANDLES[] = {"/dev/ttyACM0",
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
};*/


RecoveryCiphertext *RecoveryCiphertext_new(Params *params, int hsmGroupSize) {
    int rv = ERROR;
    RecoveryCiphertext *c = NULL;
    CHECK_A (c = (RecoveryCiphertext *)malloc(sizeof(RecoveryCiphertext)));
    CHECK_A (c->recoveryCts = (ElGamal_ciphertext ***)malloc(hsmGroupSize * sizeof(ElGamal_ciphertext **)));
    CHECK_A (c->aesCts = (uint8_t **)malloc(hsmGroupSize * sizeof(uint8_t *)));
    CHECK_A (c->aesCtTags = (uint8_t **)malloc(hsmGroupSize * sizeof(uint8_t *)));
    CHECK_A (c->ct = (uint8_t *)malloc(hsmGroupSize * PUNC_ENC_REPL * IBE_CT_LEN));

    for (int i = 0; i < hsmGroupSize; i++)  {
        CHECK_A (c->recoveryCts[i] = (ElGamal_ciphertext **)malloc(PUNC_ENC_REPL * sizeof(ElGamal_ciphertext *)));
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A (c->recoveryCts[i][j] = ElGamalCiphertext_new(params));
        }
        CHECK_A (c->aesCts[i] = (uint8_t *)malloc(AES_CT_LEN));
        CHECK_A (c->aesCtTags[i] = (uint8_t *)malloc(SHA256_DIGEST_LENGTH));
    }
    CHECK_A (c->locationHidingCt = LocationHidingCt_new(params, hsmGroupSize));
    CHECK_A (c->r = BN_new());
    CHECK_A (c->s = BN_new());
cleanup:
    if (rv == ERROR) {
        RecoveryCiphertext_free(c, hsmGroupSize);
        return NULL;
    }
    return c;
}

void RecoveryCiphertext_free(RecoveryCiphertext *c, int hsmGroupSize) {
    if (c && c->locationHidingCt) LocationHidingCt_free(c->locationHidingCt, hsmGroupSize);
    if (c && c->r) BN_free(c->r);
    if (c && c->s) BN_free(c->s);
    if (c && c->ct) free(c->ct);

    for (int i = 0; i < hsmGroupSize; i++) {
        if (c && c->aesCts[i]) free(c->aesCts[i]);
        if (c && c->aesCtTags[i]) free(c->aesCtTags[i]);
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            if (c && c->recoveryCts[i][j]) free(c->recoveryCts[i][j]);
        }
        if (c && c->recoveryCts[i]) free(c->recoveryCts[i]);
    }
    if (c) free(c);
}

Datacenter *Datacenter_new(int numHsms, int hsmGroupSize) {
    int rv = ERROR;
    Datacenter *d;

    CHECK_A (d = (Datacenter *)malloc(sizeof(Datacenter)));
    d->numHsms = numHsms;
    d->hsmGroupSize = hsmGroupSize;
    d->hsmThresholdSize = hsmGroupSize > 1 ? hsmGroupSize / 2 : 1;

    printf("# HSMs = %d, group size = %d, threshold size = %d\n", d->numHsms, d->hsmGroupSize, d->hsmThresholdSize);

    d->hsms = (HSM **)malloc(numHsms * sizeof(HSM *));
    for (int i  = 0; i < numHsms; i++) {
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
    for (int i = 0; i < d->numHsms; i++) {
#ifdef HID
        U2Fob_destroy(d->hsms[i]->hidDevice);
#else
        UsbDevice_free(d->hsms[i]->usbDevice);
#endif
        HSM_free(d->hsms[i]);
    }
    free(d->hsms);
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
      printf("created hsm %d/%d\n", i, d->numHsms);
      i++;
      if (i == d->numHsms) break;
    cur_dev = cur_dev->next;
  }
#else
    for (int i = 0; i < d->numHsms; i++) {
        CHECK_A (d->hsms[i]->usbDevice = UsbDevice_new(HANDLES[i]));
    }
#endif

    Log_Init(d->hsms[0]->params);
cleanup:
  hid_exit();
  return rv;
}

/* Run setup for datacenter, performing expensive puncturable encryption
 * setup at the host (only for testing, not secure). */
int Datacenter_TestSetup(Datacenter *d) {
    int rv;
    uint8_t *cts;
    uint8_t msk[KEY_LEN];
    uint8_t hmacKey[KEY_LEN];
    EC_POINT **mpk;
    uint8_t logPk[COMPRESSED_PT_SZ];
    thread *t;

    CHECK_A (t = (thread *)malloc(d->numHsms * sizeof(thread)));
    CHECK_A (cts = (uint8_t *)malloc(TREE_SIZE * CT_LEN));
    CHECK_A (mpk = (EC_POINT **)malloc(NUM_LEAVES * sizeof(EC_POINT *)));

    printf("Starting to build puncturable encryption tree...\n");
    Log_GetPk(d->hsms[0]->params, logPk);
    PuncEnc_BuildTree(d->hsms[0]->params, cts, msk, hmacKey, mpk);
    printf("Finished building puncturable encryption tree.\n");
    for (int i = 0; i < d->numHsms; i++) {
        CHECK_C (HSM_ElGamalGetPk(d->hsms[i]));
        CHECK_C (HSM_TestSetupInput(d->hsms[i], cts, msk, hmacKey, mpk));
	    CHECK_C (HSM_SetParams(d->hsms[i], d->hsmGroupSize, d->hsmThresholdSize, logPk));
        printf("Done with setup for %d/%d\n", i, d->numHsms);
    }
cleanup:
    if (t) free(t);
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

    for (int i = 0; i < d->numHsms; i++) {
        embedded_pairing_core_bigint_256_t sk;
        BIGNUM *x = BN_new();
        for (int j = 0; j < NUM_LEAVES; j++) {
            BN_rand_range(x, d->hsms[i]->params->order);
            EC_POINT_mul(d->hsms[i]->params->group, d->hsms[i]->mpk[j], x, NULL, NULL, d->hsms[i]->params->bn_ctx);
        
        }
        BN_rand_range(x, d->hsms[i]->params->order);
        EC_POINT_mul(d->hsms[i]->params->group, d->hsms[i]->elGamalPk, x, NULL, NULL, d->hsms[i]->params->bn_ctx);
        printf("Done with setup for %d/%d\n", i, d->numHsms);
    }
cleanup:
    return rv;
}

/* Choose the set of HSMs using the salt and the PIN. For testing,
 * instrumented to take a group of HSMs in order, but for security should
 * hash the salt and  PIN. */
int chooseHsmsFromSaltAndPin(Datacenter *d, Params *params, uint8_t *h, BIGNUM **saltHashes, BIGNUM *salt, BIGNUM *pin) {
    int rv = ERROR;
    BIGNUM *hsm;
    BIGNUM *numHsmsBn;
    uint8_t out[SHA256_DIGEST_LENGTH];

    CHECK_A (hsm = BN_new());
    CHECK_A (numHsmsBn = BN_new());

    char numHsmsBuf[4];
    sprintf(numHsmsBuf, "%d", d->numHsms);
    BN_dec2bn(&numHsmsBn, numHsmsBuf);

    /* Hash salt and pin to choose recovery HSMs. */
    for (int i = 0; i < d->hsmGroupSize; i++) {
        uint8_t *in = NULL;
        int len = BN_num_bytes(salt) + BN_num_bytes(pin) + 1;
        CHECK_A (in = (uint8_t *)malloc(len));
        in[0] = i;
        BN_bn2bin(salt, in + 1);
        BN_bn2bin(pin, in + 1 + BN_num_bytes(salt));
        hash_to_bytes(out, SHA256_DIGEST_LENGTH, in, len);
        CHECK_A (saltHashes[i] = BN_bin2bn(out, SHA256_DIGEST_LENGTH, NULL));

        CHECK_C (BN_mod(hsm, saltHashes[i], numHsmsBn, params->bn_ctx));
        // NOTE: ASSUMING NUM_HSMS NEVER GREATER THAN 256
        h[i] = 0;
        BN_bn2bin(hsm, &h[i]);
	// Assign HSMs in order for testing slice of data center.
        h[i] = i % d->numHsms;
        debug_print("h[%d] = %d\n", i, h[i]);
    }
cleanup:
    if (hsm) BN_free(hsm);
    if (numHsmsBn) BN_free(numHsmsBn);
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
    uint8_t *h1;
    uint8_t *h2;
    BIGNUM *r = NULL;
    BIGNUM **saltHashes;
    uint8_t saltHash[SHA256_DIGEST_LENGTH];
    ShamirShare **saveKeyShares;
    ShamirShare **saltShares;
    ShamirShare **pinShares;
    BIGNUM **h1Bns;
    EC_POINT **h1Pks;
    ElGamal_ciphertext ***recoveryCts;
    uint8_t elGamalRand[FIELD_ELEM_LEN];
    uint8_t *list;
    BIGNUM *encryptedSaveKey;
    uint8_t encryptedSaveKeyBuf[FIELD_ELEM_LEN];
    uint8_t saveKeyBuf[FIELD_ELEM_LEN];
    int bytesFilled = 0;
    uint8_t *innerCtBuf;
   
    CHECK_A (h1 = (uint8_t *)malloc(d->hsmGroupSize * sizeof(uint8_t)));
    CHECK_A (h2 = (uint8_t *)malloc(d->hsmGroupSize * sizeof(uint8_t)));
    CHECK_A (list = (uint8_t *)malloc(d->hsmGroupSize * sizeof(uint8_t)));
    CHECK_A (saltHashes = (BIGNUM **)malloc(d->hsmGroupSize * sizeof(BIGNUM *)));
    CHECK_A (saveKeyShares = (ShamirShare **)malloc(d->hsmGroupSize * sizeof(ShamirShare *)));
    CHECK_A (saltShares = (ShamirShare **)malloc(d->hsmGroupSize * sizeof(ShamirShare *)));
    CHECK_A (pinShares = (ShamirShare **)malloc(d->hsmGroupSize * sizeof(ShamirShare *)));
    CHECK_A (h1Bns = (BIGNUM **)malloc(d->hsmGroupSize * sizeof(BIGNUM *)));
    CHECK_A (h1Pks = (EC_POINT **)malloc(d->hsmGroupSize * sizeof(EC_POINT *)));
    CHECK_A (recoveryCts = (ElGamal_ciphertext ***)malloc(d->hsmGroupSize * sizeof(ElGamal_ciphertext *)));
    CHECK_A (innerCtBuf = (uint8_t *)malloc(d->hsmGroupSize * PUNC_ENC_REPL * ELGAMAL_CT_LEN));

    for (int i = 0; i < d->hsmGroupSize; i++) {
        CHECK_A (saveKeyShares[i] = ShamirShare_new());
        CHECK_A (saltShares[i] = ShamirShare_new());
        CHECK_A (pinShares[i] = ShamirShare_new());
        CHECK_A (recoveryCts[i] = (ElGamal_ciphertext **)malloc(PUNC_ENC_REPL * sizeof(ElGamal_ciphertext *)));
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A (recoveryCts[i][j] = ElGamalCiphertext_new(params));
        }
        list[i] = i + 1;
    }
    CHECK_A (encryptedSaveKey = BN_new());

    memset(innerCtBuf, 0, d->hsmGroupSize * ELGAMAL_CT_LEN);
    
    debug_print("start save key: %s\n", BN_bn2hex(saveKey));

    /* Choose salts. */
    CHECK_C (BN_rand_range(c->s, params->order));
    CHECK_C (BN_rand_range(c->r, params->order));

    /* Hash salt and pin to choose recovery HSMs. */
    chooseHsmsFromSaltAndPin(d, params, h1, saltHashes, c->r, pin);
    CHECK_C (intsToBignums(h1Bns, list, d->hsmGroupSize));

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
    CHECK_C (Shamir_CreateShares(d->hsmThresholdSize, d->hsmGroupSize, encryptedSaveKey, params->order, saveKeyShares, h1Bns));

    debug_print("created shares of save key\n");

    debug_print("Going to encrypt ciphertexts to each HSM\n");

    /* Encrypt [saveKey]_i, H(pin, salt) to each HSM. */
    for (int i = 0; i < d->hsmGroupSize; i++) {
        debug_print("starting ct %d\n", i);

        debug_print("saveKeyShare[%d]: %s, %s\n", i, BN_bn2hex(saveKeyShares[i]->x), BN_bn2hex(saveKeyShares[i]->y));
       
        CHECK_C (HSM_Encrypt(d->hsms[h1[i]], userID + i, saveKeyShares[i]->y, recoveryCts[i]));

    }

    CHECK_C (RAND_bytes(elGamalRand, FIELD_ELEM_LEN));
    for (int i = 0; i < d->hsmGroupSize; i++)  {
        CHECK_A (h1Pks[i] = EC_POINT_dup(d->hsms[h1[i]]->elGamalPk, params->group));
    }
    CHECK_C (ElGamalShamir_CreateShares(params, d->hsmThresholdSize, d->hsmGroupSize, elGamalRand, h1Pks, c->locationHidingCt, h1Bns));

    /* Encrypt all those ciphertexts with a transport key. */
    for (int i = 0; i < d->hsmGroupSize; i++) {
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            ElGamal_Marshal(params, innerCtBuf + (i * PUNC_ENC_REPL + j) * ELGAMAL_CT_LEN, recoveryCts[i][j]);
        }
    }

    CHECK_C (aesEncrypt(elGamalRand, innerCtBuf, d->hsmGroupSize * PUNC_ENC_REPL * ELGAMAL_CT_LEN, c->iv, c->ct));

    printf("Finished saving secret.\n");

cleanup:
    if (r) BN_free(r);

    for (int i = 0; i < d->hsmGroupSize; i++) {
        if (saveKeyShares[i]) ShamirShare_free(saveKeyShares[i]);
        if (saltShares[i]) ShamirShare_free(saltShares[i]);
        if (h1Bns[i]) BN_free(h1Bns[i]);
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            if (recoveryCts[i][j]) ElGamalCiphertext_free(recoveryCts[i][j]);
        }
        if (recoveryCts[i]) free(recoveryCts[i]);
    }

    if (h1) free(h1);
    if (h2) free(h2);
    if (list) free(list);
    if (saltHashes) free(saltHashes);
    if (saveKeyShares) free(saveKeyShares);
    if (saltShares) free(saltShares);
    if (pinShares) free(pinShares);
    if (h1Bns) free(h1Bns);
    if (h1Pks) free(h1Pks);
    if (recoveryCts) free(recoveryCts);
    if (innerCtBuf) free(innerCtBuf);

    return rv;
}

/* Generate a proof that a recovery attempt was logged. */
int Datacenter_GenerateLogProofs(Datacenter *d, Params *params, LogProof **logProofs, BIGNUM *pin, RecoveryCiphertext *c) {
    int rv;
    uint8_t *h;
    BIGNUM **saltHashes;

    CHECK_A (h = (uint8_t *)malloc(d->hsmGroupSize * sizeof(uint8_t)));
    CHECK_A (saltHashes = (BIGNUM **)malloc(d->hsmGroupSize * sizeof(BIGNUM *)));

    chooseHsmsFromSaltAndPin(d, params, h, saltHashes, c->r, pin);
    for (int i = 0; i < d->hsmGroupSize; i++) {
        CHECK_C (Log_Prove(params, logProofs[i], c->locationHidingCt->shares[i]->ct, h, d->hsmGroupSize));
    } 
cleanup:
    if (h) free(h);
    if (saltHashes) free(saltHashes);
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
    uint8_t *h1;
    uint8_t *h2;
    BIGNUM **saltHashes;
    ShamirShare **saveKeyShares;
    ShamirShare **pinShares;
    BIGNUM **h1Bns;
    uint8_t *list;
    uint8_t *innerCtBuf;
    ElGamal_ciphertext ***recoveryCts;
    ShamirShare **elGamalRandShares;
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

    vector<thread> t0(d->hsmGroupSize);
    vector<thread> t1(d->hsmGroupSize);
    vector<thread> t2(d->hsmGroupSize);

    CHECK_A (h1 = (uint8_t *)malloc(HSM_MAX_GROUP_SIZE * sizeof(uint8_t)));
    CHECK_A (h2 = (uint8_t *)malloc(d->hsmGroupSize * sizeof(uint8_t)));
    CHECK_A (list = (uint8_t *)malloc(d->hsmGroupSize * sizeof(uint8_t)));
    CHECK_A (saltHashes = (BIGNUM **)malloc(d->hsmGroupSize * sizeof(BIGNUM *)));
    CHECK_A (saveKeyShares = (ShamirShare **)malloc(d->hsmGroupSize * sizeof(ShamirShare *)));
    CHECK_A (pinShares = (ShamirShare **)malloc(d->hsmGroupSize * sizeof(ShamirShare *)));
    CHECK_A (elGamalRandShares = (ShamirShare **)malloc(d->hsmGroupSize * sizeof(ShamirShare *)));
    CHECK_A (h1Bns = (BIGNUM **)malloc(d->hsmGroupSize * sizeof(BIGNUM *)));
    CHECK_A (recoveryCts = (ElGamal_ciphertext ***)malloc(d->hsmGroupSize * sizeof(ElGamal_ciphertext **)));
    CHECK_A (innerCtBuf = (uint8_t *)malloc(d->hsmGroupSize * PUNC_ENC_REPL * ELGAMAL_CT_LEN));

    gettimeofday(&tStart, NULL);

    for (int i = 0; i < d->hsmGroupSize; i++) {
        CHECK_A (saveKeyShares[i] = ShamirShare_new());
        CHECK_A (elGamalRandShares[i] = ShamirShare_new());
        CHECK_A (pinShares[i] = ShamirShare_new());
        CHECK_A (recoveryCts[i] = (ElGamal_ciphertext **)malloc(PUNC_ENC_REPL * sizeof(ElGamal_ciphertext *)));
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            CHECK_A  (recoveryCts[i][j] = ElGamalCiphertext_new(params));
        }
        list[i] = i + 1;
    }
    CHECK_A (encryptedSaveKey = BN_new());

    /* Hash salt and pin to find recovery HSMs. */
    chooseHsmsFromSaltAndPin(d, params, h1, saltHashes, c->r, pin);
    CHECK_C (intsToBignums(h1Bns, list, d->hsmGroupSize));

    for (int i = 0; i < d->hsmGroupSize; i++) {
        t0[i] = thread(HSM_LogProof, d->hsms[h1[i]], c->locationHidingCt->shares[i]->ct, h1, logProofs[i]);
    }
    for (int i = 0; i < d->hsmGroupSize; i++) {
        t0[i].join();
    }
 
    gettimeofday(&tLog, NULL);

    for (int i = 0; i < d->hsmGroupSize; i++) {
        elGamalRandShares[i]->x = h1Bns[i];
        t1[i] = thread(HSM_ElGamalDecrypt, d->hsms[h1[i]], elGamalRandShares[i]->y, c->locationHidingCt->shares[i]->ct);
    }
    for (int i = 0; i < d->hsmGroupSize; i++) {
        t1[i].join();
    }
    CHECK_C (ElGamalShamir_ReconstructShares(params, d->hsmThresholdSize, d->hsmGroupSize, c->locationHidingCt, elGamalRandShares, elGamalRand));

    gettimeofday(&tElGamal, NULL);

    /* Decrypt ct to get inner ciphertexts using elGamalRand. */
    CHECK_C (aesDecrypt(elGamalRand, innerCtBuf, c->iv, c->ct, d->hsmGroupSize * PUNC_ENC_REPL * ELGAMAL_CT_LEN));
    for (int i = 0; i < d->hsmGroupSize; i++) {
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            ElGamal_Unmarshal(params, innerCtBuf + (i * PUNC_ENC_REPL + j) * ELGAMAL_CT_LEN, recoveryCts[i][j]);
        }
    }

    for (int i = 0; i < d->hsmGroupSize; i++) {
        t2[i] = thread(HSM_AuthDecrypt, d->hsms[h1[i]], userID + i, recoveryCts[i], saveKeyShares[i]->y);
    }
    for (int i = 0; i < d->hsmGroupSize; i++) {
	    t2[i].join();
        Shamir_UnmarshalX(saveKeyShares[i], i + 1);
    }

    /* Reassemble original saveKey. */
    CHECK_C (Shamir_ReconstructShares(d->hsmThresholdSize, d->hsmGroupSize, saveKeyShares, params->order, encryptedSaveKey));

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
    printf("3\n");

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

    for (int i = 0; i < d->hsmGroupSize; i++) {
        if (saveKeyShares[i]) ShamirShare_free(saveKeyShares[i]);
        if (h1Bns[i]) BN_free(h1Bns[i]);
        for (int j = 0; j < PUNC_ENC_REPL; j++) {
            if (recoveryCts[i][j]) ElGamalCiphertext_free(recoveryCts[i][j]);
        }
        if (recoveryCts[i]) free(recoveryCts[i]);
    }

    if (h1) free(h1);
    if (h2) free(h2);
    if (list) free(list);
    if (saltHashes) free(saltHashes);
    if (saveKeyShares) free(saveKeyShares);
    if (pinShares) free(pinShares);
    if (elGamalRandShares) free(elGamalRandShares);
    if (h1Bns) free(h1Bns);
    if (recoveryCts) free(recoveryCts);
    if (innerCtBuf) free(innerCtBuf);
    printf("finished cleanup\n");

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
    embedded_pairing_bls12_381_g1_t aggSig;
    embedded_pairing_bls12_381_g1_t *sigs;
    struct timeval tStart, tVerify, tEnd;
    long verifySec, verifyMicro, aggSec, aggMicro;
    double verifyTime, aggTime;

    vector<thread> t(d->numHsms);
    CHECK_A (sigs = (embedded_pairing_bls12_381_g1_t *)malloc(d->numHsms * sizeof(embedded_pairing_bls12_381_g1_t)));

    gettimeofday(&tStart, NULL);

    for (int i = 0; i < d->numHsms; i++) {
        t[i] = thread(HSM_LogEpochVerification, d->hsms[i], &sigs[i], state);
    }
    for (int i = 0; i < d->numHsms; i++) {
        t[i].join();
    }

    for (int i = 0; i < d->numHsms; i++) {
        t[i] = thread(HSM_MultisigSign, d->hsms[i], &sigs[i], state->rootsTree->hash);
    }
    for (int i = 0; i < d->numHsms; i++) {
        t[i].join();
    }

    gettimeofday(&tVerify, NULL);

    Multisig_AggSigs(sigs, d->numHsms, &aggSig);
    for (int i = 0; i < d->numHsms; i++) {
        t[i] = thread(HSM_MultisigVerify, d->hsms[i], &aggSig, state->rootsTree->hash);
    }
    for (int i = 0; i < d->numHsms; i++) {
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
