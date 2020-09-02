#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "bls12_381/bls12_381.h"
#include "crypto.h"
#include "ctap.h"
#include "device.h"
#include "ibe.h"
#include "log.h"
#include "hsm.h"
#include "punc_enc.h"

/* Puncturable encryption scheme. */

static uint8_t msk[KEY_LEN];
static uint8_t hmacKey[KEY_LEN];

/* Encrypt with separate input and output buffers. */
void crypto_aes256_encrypt_sep(uint8_t *out, uint8_t *in, int length) {
    for (int i = 0; i < length / 16; i++) {
        uint8_t tmp[16];
        memcpy(tmp, in + (i * 16), 16);
        crypto_aes256_encrypt(tmp, 16);
        memcpy(out + (i * 16), tmp, 16);
    }   
}

/* Decrypt with separate input and output buffers. */
void crypto_aes256_decrypt_sep(uint8_t *out, uint8_t *in, int length) {
    for (int i = 0; i < length / 16; i++) {
        uint8_t tmp[16];
        memcpy(tmp, in + (i * 16), 16);
        crypto_aes256_decrypt(tmp, 16);
        memcpy(out + (i * 16), tmp, 16);
    }   
}

/* Compute HMAC. */
void crypto_hmac(uint8_t *key, uint8_t *out, uint8_t *in, int inLen) {
    uint8_t keyBuf[64];
    uint8_t keyPadBuf[64];
    uint8_t outBuf[32];
    memset(keyBuf, 0, 64);
    memcpy(keyBuf, key, KEY_LEN);
    for (int i = 0; i < 64; i++) {
        keyPadBuf[i] = keyBuf[i] ^ 0x36;
    }
    memset(outBuf, 0, 32);
    memset(out, 0, 32);
    crypto_sha256_init();
    crypto_sha256_update(keyPadBuf, 64);
    crypto_sha256_update(in, inLen);
    crypto_sha256_final(outBuf);
    for (int i = 0; i < 64; i++) {
        keyPadBuf[i] = keyBuf[i] ^ 0x5c;
    }
    crypto_sha256_init();
    crypto_sha256_update(keyPadBuf, 64);
    crypto_sha256_update(outBuf, 32);
    crypto_sha256_final(out);
}

void encryptKeysAndCreateTag(uint8_t *encKey, uint8_t *hmacKey, uint8_t *key1, uint8_t *key2, uint8_t *ct) {
    crypto_aes256_init(encKey, NULL);
    crypto_aes256_encrypt_sep(ct, key1, KEY_LEN);
    crypto_aes256_encrypt_sep(ct + KEY_LEN, key2, KEY_LEN);
    crypto_hmac(hmacKey, ct + 2 * KEY_LEN, ct, 2 * KEY_LEN);
}

int decryptKeysAndCheckTag(uint8_t *encKey, uint8_t *hmacKey, uint8_t *key1, uint8_t *key2, uint8_t *ct) {
    uint8_t hmacTest[32];
    crypto_aes256_init(encKey, NULL);
    crypto_aes256_decrypt_sep(key1, ct, KEY_LEN);
    crypto_aes256_decrypt_sep(key2, ct + KEY_LEN, KEY_LEN);
    crypto_hmac(hmacKey, hmacTest, ct, 2 * KEY_LEN);
    if (memcmp(hmacTest, ct + 2 * KEY_LEN, 32) != 0) {
        return ERROR;
    } else {
        return OKAY;
    }
}

/* Run initialization for puncturable encryption. */
void PuncEnc_Init() {
    ctap_generate_rng(hmacKey, KEY_LEN);
}

void PuncEnc_TestSetup(uint8_t newMsk[KEY_LEN], uint8_t newHmacKey[KEY_LEN]) {
    setMsk(newMsk);
    memcpy(hmacKey, newHmacKey, KEY_LEN);
}

/* Set msk value. Should be called for final_key value for top subtree. */
void setMsk(uint8_t newMsk[KEY_LEN]) {
    memcpy(msk, newMsk, KEY_LEN);
}

/* Look up leaf in the tree given ciphertexts along the path to that leaf. */
int PuncEnc_RetrieveLeaf(uint8_t cts[LEVELS][CT_LEN], uint32_t index, uint8_t leaf[CT_LEN]) {
    int numLeaves = NUM_LEAVES;
    int levels = LEVELS;
    uint8_t currKey[KEY_LEN];
    uint8_t leftKey[KEY_LEN];
    uint8_t rightKey[KEY_LEN];
    uint32_t currCmp = numLeaves / 2;
    //uint16_t currCmp = NUM_LEAVES / 2;
    uint32_t currIndex = index;
    uint32_t t3, t4;

    uint32_t t1 = millis();   
    memcpy(currKey, msk, KEY_LEN);

 /*   printf("msk: ");
    for (int i = 0; i < KEY_LEN; i++) {
        printf("%02x", msk[i]);
    }
    printf("\n");
*/
    /* Walk down the tree. */
    for (int i = 0; i < levels - 1; i++) {
        /* Decrypt current ciphertext. */
        t3 = millis();
        if (decryptKeysAndCheckTag(currKey, hmacKey, leftKey, rightKey, cts[i]) == ERROR) {
            printf("ERROR IN DECRYPTION OF INNER NODE\n");
            return ERROR;
        }
        //crypto_aes256_init(currKey, NULL);
        //crypto_aes256_decrypt_sep(leftKey, cts[i], KEY_LEN);
        //crypto_aes256_decrypt_sep(rightKey, (uint8_t *)cts[i] + KEY_LEN, KEY_LEN);

        /* Choose to go left or right. */
        if (currIndex < currCmp) {
            memcpy(currKey, leftKey, KEY_LEN);
        } else {
            memcpy(currKey, rightKey, KEY_LEN);
            currIndex -= currCmp;
        }

        /*printf("left key at %d: ", i);
        for (int j = 0; j < KEY_LEN; j++) {
            printf("%x ", leftKey[j]);
        }
        printf("\n");

        printf("right key at %d: ", i);
        for (int j = 0; j < KEY_LEN; j++) {
            printf("%x ", rightKey[j]);
        }
        printf("\n");
*/
        currCmp /= 2;
        //currIndex /= 2;
        t4 = millis();
    }
    /* Set final leaf value. */
    if (decryptKeysAndCheckTag(currKey, hmacKey, leftKey, rightKey, cts[levels - 1]) == ERROR) {
        printf("ERROR IN LEAF DECRYPTION\n");
        return ERROR;
    }
    memcpy(leaf, leftKey, KEY_LEN);
    memcpy(leaf + KEY_LEN, rightKey, KEY_LEN);
    uint32_t t2 = millis();
    //printf1(TAG_GREEN, "retrieve time: %d\n", t2 - t1);
    //printf1(TAG_GREEN, "inner loop: %d\n", t4 - t3);
   
    return OKAY;
}

/* Puncture a leaf. Given ciphertexts along the path to the leaf corresponding
 * to index, output a new set of ciphertexts. Also updates msk. */
void PuncEnc_PunctureLeaf(uint8_t oldCts[KEY_LEVELS][CT_LEN], uint32_t index, uint8_t newCts[KEY_LEVELS][CT_LEN]) {
    int numLeaves = NUM_LEAVES;
    int keyLevels = KEY_LEVELS;
    uint8_t currKey[KEY_LEN];
    uint8_t leftKeys[keyLevels][KEY_LEN];
    uint8_t rightKeys[keyLevels][KEY_LEN];
    uint8_t pathKeys[keyLevels][KEY_LEN];
    uint8_t pathDirs[keyLevels];
    uint32_t currCmp = numLeaves / 2;
    uint32_t currIndex = index;
   
    uint32_t t1= millis(); 
    uint32_t t3, t4, t5, t6;
    memcpy(currKey, msk, KEY_LEN);

    /* Walk down to the leaf, recording information to create new set of cts. */
    for (int i = 0; i < keyLevels; i++) {
        t3 = millis();
        memcpy(pathKeys[i], currKey, KEY_LEN);

        /* Decrypt ciphertext. */
        if (decryptKeysAndCheckTag(currKey, hmacKey, leftKeys[i], rightKeys[i], oldCts[i]) == ERROR) {
            printf("ERROR IN DECRYPTION\n");
        }
        //crypto_aes256_init(currKey, NULL);
        //crypto_aes256_decrypt_sep(leftKeys[i], oldCts[i], KEY_LEN);
        //crypto_aes256_decrypt_sep(rightKeys[i], (uint8_t *)oldCts[i] + KEY_LEN, KEY_LEN);

        /* Decide to go left or right. */
        if (currIndex < currCmp) {
            //printf("going left at %d\n", i);
            memcpy(currKey, leftKeys[i], KEY_LEN);
            pathDirs[i] = 0;
        } else {
            //printf("going right at %d\n", i);
            memcpy(currKey, rightKeys[i], KEY_LEN);
            currIndex -= currCmp;
            pathDirs[i] = 1;
        }
       
        currCmp /= 2;
        t4 = millis();
    }

    /* Zero out leaf. */
    uint8_t newKey[KEY_LEN];
    memset(newKey, 0xaa, KEY_LEN);

    /* Generate new ciphertexts along path. */
    for (int i = keyLevels - 1; i >= 0; i--) {
        t5 = millis();
        uint8_t plaintext[CT_LEN];
        /* Decide which key to leave and which to replace. */
        if (pathDirs[i] == 0) {
            memcpy(plaintext, newKey, KEY_LEN);
            memcpy((uint8_t *)plaintext + KEY_LEN, rightKeys[i], KEY_LEN);
        } else {
            memcpy(plaintext, leftKeys[i], KEY_LEN);
            memcpy((uint8_t *)plaintext + KEY_LEN, newKey, KEY_LEN);
        }

        /* Generate replacement key. */
        device_flag2();
        memset(newKey, 0xff, KEY_LEN);
        //ctap_generate_rng(newKey,  KEY_LEN);
        device_unflag2();
   
        /* Encrypt original key and replacement key. */
        encryptKeysAndCreateTag(newKey, hmacKey, plaintext, plaintext + KEY_LEN, newCts[keyLevels - i - 1]);
        //crypto_aes256_init(newKey, NULL);
        //crypto_aes256_encrypt_sep(newCts[KEY_LEVELS - i - 1], plaintext, KEY_LEN);
        //crypto_aes256_encrypt_sep((uint8_t *)newCts[KEY_LEVELS - i - 1] + KEY_LEN, (uint8_t *)plaintext +  KEY_LEN, KEY_LEN);
        t6 = millis();
    }

    memcpy(msk, newKey, KEY_LEN);
    uint32_t t2 = millis();
    //printf("puncture time: %d\n", t2 - t1);
    //printf("decrypting inner loop %d\n", t4 - t3);
    //printf("encrypting inner loop %d\n", t6 - t5);
}
