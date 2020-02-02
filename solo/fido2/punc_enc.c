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

//#define NUM_LEAVES 256
//#define LEVELS 8 // log2(NUM_LEAVES)

static uint8_t msk[KEY_LEN];
static uint8_t hmacKey[KEY_LEN];
static bool isSmall;

//static uint8_t oldCachedLeaves[NUM_LEAVES / NUM_SUB_LEAVES][KEY_LEN];
//static uint8_t newCachedLeaves[NUM_LEAVES / NUM_SUB_LEAVES][KEY_LEN];
static uint8_t levelOneLeaves[NUM_INTERMEDIATE_KEYS][KEY_LEN];
static uint8_t levelTwoLeaves[NUM_INTERMEDIATE_KEYS][KEY_LEN];
static uint8_t levelThreeLeaves[NUM_INTERMEDIATE_KEYS][KEY_LEN];
static int ctr[4] = {0, 0, 0, 0};
static int ibeLeafCtr = 0;
static int currLevel = LEVEL_0;

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
    printf("in aes256 decrypt, length = %d\n", length);
    for (int i = 0; i < length / 16; i++) {
        uint8_t tmp[16];
        memcpy(tmp, in + (i * 16), 16);
        crypto_aes256_decrypt(tmp, 16);
        memcpy(out + (i * 16), tmp, 16);
    }   
}

// outLen = 32
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

void PuncEnc_Init() {
    ctap_generate_rng(hmacKey, KEY_LEN);
}

/* Set the values of the leaves in a subtree, where the leaves in the subtree
 * begin at value start. */
void setIBELeaves(uint8_t leaves[NUM_SUB_LEAVES][LEAF_LEN], int start) {
    for (int i = 0; i < NUM_SUB_LEAVES; i++) {
        //memset(leaves[i], 0xff, LEAF_LEN);

        printf("start %d\n", i);
        memset(leaves[i], 0, LEAF_LEN);
        uint8_t buf[embedded_pairing_bls12_381_g1_marshalled_compressed_size];
        embedded_pairing_bls12_381_g1_t sk;
        embedded_pairing_bls12_381_g1affine_t sk_affine;
        uint32_t index = i + start;
        IBE_Extract(index, &sk);
        embedded_pairing_bls12_381_g1affine_from_projective(&sk_affine, &sk);
        embedded_pairing_bls12_381_g1_marshal(buf, &sk_affine, true);
        memcpy(leaves[i], buf, embedded_pairing_bls12_381_g1_marshalled_compressed_size);
        printf("leaf %d: ", i);
        for (int j = 0; j < 48; j++) {
            printf("%x ", buf[j]);
        }
        printf("\n"); 
        //memset(leaves[i], 0xff, CT_LEN);
    }
}

void increment() {
    if (currLevel == LEVEL_0) {
        if (ctr[0] == NUM_INTERMEDIATE_KEYS - 1) {
            currLevel = LEVEL_1;
            ctr[0] = 0;
        } else {
            ctr[0]++;
        }
        ibeLeafCtr++;
    } else if (currLevel == LEVEL_1) {
        if (ctr[1] == NUM_INTERMEDIATE_KEYS - 1) {
            currLevel = LEVEL_2;
            ctr[1] = 0;
        } else {
            currLevel = LEVEL_0;
            ctr[1]++;
        }
    } else if (currLevel == LEVEL_2) {
        if (ctr[2] == NUM_INTERMEDIATE_KEYS - 1) {
            currLevel = LEVEL_3;
            ctr[2] = 0;
        } else {
            currLevel = LEVEL_0;
            ctr[2]++;
        }
    }
    /* When LEVEL_3, no rounds left. */
}

void PuncEnc_FillLeaves(uint8_t leaves[NUM_SUB_LEAVES][LEAF_LEN]) {
    if (currLevel == LEVEL_0) {
        setIBELeaves(leaves, ibeLeafCtr * NUM_SUB_LEAVES);
    } else if (currLevel == LEVEL_1) {
        memcpy(leaves, levelOneLeaves, NUM_INTERMEDIATE_KEYS * KEY_LEN);
    } else if (currLevel == LEVEL_2) {
        memcpy(leaves, levelTwoLeaves, NUM_INTERMEDIATE_KEYS * KEY_LEN);
    } else if (currLevel == LEVEL_3) {
        memcpy(leaves, levelThreeLeaves, NUM_INTERMEDIATE_KEYS * KEY_LEN);
    }

}

void processSubTreeRoot(uint8_t root[KEY_LEN]) {
    if (currLevel == LEVEL_0) {
        memcpy(levelOneLeaves[ctr[0]], root, KEY_LEN);
    } else if (currLevel == LEVEL_1) {
        memcpy(levelTwoLeaves[ctr[1]], root, KEY_LEN);
    } else if (currLevel == LEVEL_2) {
        memcpy(levelThreeLeaves[ctr[2]], root, KEY_LEN);
    } else {
        setMsk(root);
    }
}

/* Build the subtree from a set of leaves, outputting a tree of ciphertexts. 
 * First NUM_SUB_LEAVES ciphertexts correspond to the leaves, next NUM_SUB_LEAVES / 2
 * are their parents, and so on, and the last ciphertext is the root. Sets finalKey
 * to be the key encrypting the root. */
void PuncEnc_BuildSubTree(uint8_t leaves[NUM_SUB_LEAVES][LEAF_LEN], uint8_t cts[SUB_TREE_SIZE][CT_LEN]) {
    /* For each level in subtree, choose random key, encrypt two children keys or leaf */
    isSmall = false;
    printf1(TAG_GREEN, "in build subtree\n");

    printf("currLevel: %d, ctr[0] = %d, ctr[1] = %d, ctr[2] = %d ctr[3] = %d\n", currLevel, ctr[0], ctr[1], ctr[2], ctr[3]);

    int index = 0;
    int currNumLeaves = NUM_SUB_LEAVES;
    uint8_t *currLeaves = leaves;
    uint8_t keys[SUB_TREE_SIZE][KEY_LEN];

    printf1(TAG_GREEN, "NUM_SUB_LEAVES = %d, SUB_TREE_SIZE = %d\n", NUM_SUB_LEAVES, SUB_TREE_SIZE);

    /* Repeat for each level in tree. */
    while (currNumLeaves >= 1) {
        int initialIndex = index;
        /* For each child, generate parent. */
        for (int i = 0; i < currNumLeaves; i++) {
            /* Choose random key. */
            ctap_generate_rng(keys[index], KEY_LEN);
            /* Encrypt leaf. */
            encryptKeysAndCreateTag(keys[index], hmacKey, currLeaves, currLeaves + KEY_LEN, cts[index]);
            //crypto_aes256_init(keys[index], NULL);
            //crypto_aes256_encrypt_sep(cts[index], currLeaves, KEY_LEN);
            //currLeaves += KEY_LEN;
            //crypto_aes256_encrypt_sep((uint8_t *)cts[index] + KEY_LEN, currLeaves, KEY_LEN);
            //currLeaves += KEY_LEN;
            currLeaves += LEAF_LEN;
            /* Next index. */
            printf1(TAG_GREEN, "index = %d/%d\n", index, SUB_TREE_SIZE);
            index++;
        }
        currLeaves = (uint8_t *)keys + (initialIndex * KEY_LEN);
        printf1(TAG_GREEN, "old currNumLeaves = %d\n", currNumLeaves);
        currNumLeaves /= 2.0;
        printf1(TAG_GREEN, "new currNumLeaves = %d\n", currNumLeaves);
    }

    printf("going to process and increment\n");

    printf("currLevel: %d, ctr[0] = %d, ctr[1] = %d, ctr[2] = %d\n", currLevel, ctr[0], ctr[1], ctr[2]);
    /* Set key for root. */
    processSubTreeRoot(keys[SUB_TREE_SIZE - 1]);
    printf("processed root, going to increment\n");
    increment();
    //memcpy(finalKey, keys[SUB_TREE_SIZE - 1], KEY_LEN);
    printf("currLevel: %d, ctr[0] = %d, ctr[1] = %d, ctr[2] = %d\n", currLevel, ctr[0], ctr[1], ctr[2]);

    printf1(TAG_GREEN, "done building subtree\n");
}

void PuncEnc_BuildSmallTree(uint8_t cts[SUB_TREE_SIZE][CT_LEN]) {
    isSmall = true;
    
    /* For each level in subtree, choose random key, encrypt two children keys or leaf */
    printf1(TAG_GREEN, "in build subtree\n");

    uint8_t leaves[NUM_SUB_LEAVES][LEAF_LEN];
    int index = 0;
    int currNumLeaves = NUM_SUB_LEAVES;
    uint8_t *currLeaves = leaves;
    uint8_t keys[SUB_TREE_SIZE][KEY_LEN];

    setIBELeaves(leaves, 0);

    printf1(TAG_GREEN, "NUM_SUB_LEAVES = %d, SUB_TREE_SIZE = %d\n", NUM_SUB_LEAVES, SUB_TREE_SIZE);

    /* Repeat for each level in tree. */
    while (currNumLeaves >= 1) {
        int initialIndex = index;
        /* For each child, generate parent. */
        for (int i = 0; i < currNumLeaves; i++) {
            /* Choose random key. */
            ctap_generate_rng(keys[index], KEY_LEN);
            /* Encrypt leaf. */
            encryptKeysAndCreateTag(keys[index], hmacKey, currLeaves, currLeaves + KEY_LEN, cts[index]);
            //crypto_aes256_init(keys[index], NULL);
            //crypto_aes256_encrypt_sep(cts[index], currLeaves, KEY_LEN);
            //currLeaves += KEY_LEN;
            //crypto_aes256_encrypt_sep((uint8_t *)cts[index] + KEY_LEN, currLeaves, KEY_LEN);
            //currLeaves += KEY_LEN;
            currLeaves += LEAF_LEN;
            /* Next index. */
            printf1(TAG_GREEN, "index = %d/%d\n", index, SUB_TREE_SIZE);
            index++;
        }
        currLeaves = (uint8_t *)keys + (initialIndex * KEY_LEN);
        printf1(TAG_GREEN, "old currNumLeaves = %d\n", currNumLeaves);
        currNumLeaves /= 2.0;
        printf1(TAG_GREEN, "new currNumLeaves = %d\n", currNumLeaves);
    }

    printf("going to process and increment\n");

    /* Set key for root. */
    setMsk(keys[SUB_TREE_SIZE - 1]);
    //memcpy(finalKey, keys[SUB_TREE_SIZE - 1], KEY_LEN);

    printf1(TAG_GREEN, "done building small tree\n");
}

void PuncEnc_TestSetup(uint8_t newMsk[KEY_LEN], uint8_t newHmacKey[KEY_LEN]) {
    setMsk(newMsk);
    memcpy(hmacKey, newHmacKey, KEY_LEN);
    isSmall = false;
}

/* Set msk value. Should be called for final_key value for top subtree. */
void setMsk(uint8_t newMsk[KEY_LEN]) {
    memcpy(msk, newMsk, KEY_LEN);
}

/* Look up leaf in the tree given ciphertexts along the path to that leaf. */
int PuncEnc_RetrieveLeaf(uint8_t cts[LEVELS][CT_LEN], uint32_t index, uint8_t leaf[CT_LEN]) {
    int numLeaves = isSmall ? NUM_SUB_LEAVES : NUM_LEAVES;
    int levels = isSmall ? SUB_TREE_LEVELS : LEVELS;
    uint8_t currKey[KEY_LEN];
    uint8_t leftKey[KEY_LEN];
    uint8_t rightKey[KEY_LEN];
    uint32_t currCmp = numLeaves / 2;
    //uint16_t currCmp = NUM_LEAVES / 2;
    uint32_t currIndex = index;
   
    memcpy(currKey, msk, KEY_LEN);

    printf1(TAG_GREEN, "trying to retrieve %d\n", index);

    /* Walk down the tree. */
    for (int i = 0; i < levels - 1; i++) {
        printf("ct[%d]: ", i);
        for (int j = 0; j < CT_LEN; j++) {
            printf("%x ", cts[i][j]);
        }
        printf("\n");
        /* Decrypt current ciphertext. */
        if (decryptKeysAndCheckTag(currKey, hmacKey, leftKey, rightKey, cts[i]) == ERROR) {
            printf("ERROR IN DECRYPTION OF INNER NODE\n");
            return ERROR;
        }
        //crypto_aes256_init(currKey, NULL);
        //crypto_aes256_decrypt_sep(leftKey, cts[i], KEY_LEN);
        //crypto_aes256_decrypt_sep(rightKey, (uint8_t *)cts[i] + KEY_LEN, KEY_LEN);

        /* Choose to go left or right. */
        if (currIndex < currCmp) {
            //printf("going left at %d\n", i);
            memcpy(currKey, leftKey, KEY_LEN);
        } else {
            //printf("going right at %d\n", i);
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
    }
    /* Set final leaf value. */
    if (decryptKeysAndCheckTag(currKey, hmacKey, leftKey, rightKey, cts[levels - 1]) == ERROR) {
        printf("ERROR IN LEAF DECRYPTION\n");
        return ERROR;
    }
    memcpy(leaf, leftKey, KEY_LEN);
    memcpy(leaf + KEY_LEN, rightKey, KEY_LEN);
    printf("finished\n");
    return OKAY;
}

/* Puncture a leaf. Given ciphertexts along the path to the leaf corresponding
 * to index, output a new set of ciphertexts. Also updates msk. */
void PuncEnc_PunctureLeaf(uint8_t oldCts[KEY_LEVELS][CT_LEN], uint32_t index, uint8_t newCts[KEY_LEVELS][CT_LEN]) {
    int numLeaves = isSmall ? NUM_SUB_LEAVES : NUM_LEAVES;
    int keyLevels = isSmall ? SUB_TREE_LEVELS - 1 : KEY_LEVELS;
    uint8_t currKey[KEY_LEN];
    uint8_t leftKeys[keyLevels][KEY_LEN];
    uint8_t rightKeys[keyLevels][KEY_LEN];
    uint8_t pathKeys[keyLevels][KEY_LEN];
    uint8_t pathDirs[keyLevels];
    uint32_t currCmp = numLeaves / 2;
    uint32_t currIndex = index;
    
    memcpy(currKey, msk, KEY_LEN);

    /* Walk down to the leaf, recording information to create new set of cts. */
    for (int i = 0; i < keyLevels; i++) {
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
    }

    /* Zero out leaf. */
    uint8_t newKey[KEY_LEN];
    memset(newKey, 0xaa, KEY_LEN);

    /* Generate new ciphertexts along path. */
    for (int i = keyLevels - 1; i >= 0; i--) {
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
        ctap_generate_rng(newKey,  KEY_LEN);
   
        /* Encrypt original key and replacement key. */
        encryptKeysAndCreateTag(newKey, hmacKey, plaintext, plaintext + KEY_LEN, newCts[keyLevels - i - 1]);
        //crypto_aes256_init(newKey, NULL);
        //crypto_aes256_encrypt_sep(newCts[KEY_LEVELS - i - 1], plaintext, KEY_LEN);
        //crypto_aes256_encrypt_sep((uint8_t *)newCts[KEY_LEVELS - i - 1] + KEY_LEN, (uint8_t *)plaintext +  KEY_LEN, KEY_LEN);
    }

    memcpy(msk, newKey, KEY_LEN);
}
