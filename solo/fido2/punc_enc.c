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

/* Set the values of the leaves in a subtree, where the leaves in the subtree
 * begin at value start. */
void PuncEnc_FillLeaves(uint8_t leaves[NUM_SUB_LEAVES][CT_LEN], int start) {
    for (int i = 0; i < NUM_SUB_LEAVES; i++) {
        /*leaves[i][0] = (i + start) & 0xff;
        leaves[i][1] = ((i + start) >> 8) & 0xff;
        leaves[i][2] = ((i + start) >> 16) & 0xff;
        leaves[i][3] = ((i + start) >> 24) & 0xff;
        memset(leaves[i] + 4, 0, 28);*/
        
        memset(leaves[i], 0xff, CT_LEN);
        memset(leaves[i], 0, CT_LEN);

        // compressed size = 48
        /*uint8_t buf[embedded_pairing_bls12_381_g1_marshalled_compressed_size];
        embedded_pairing_bls12_381_g1_t sk;
        uint16_t index = i + start;
        IBE_Extract(index, &sk);
        embedded_pairing_bls12_381_g1_marshal(buf, &sk, true);
        memcpy(leaves[i], buf, embedded_pairing_bls12_381_g1_marshalled_compressed_size);
    */}
}

/* Build the subtree from a set of leaves, outputting a tree of ciphertexts. 
 * First NUM_SUB_LEAVES ciphertexts correspond to the leaves, next NUM_SUB_LEAVES / 2
 * are their parents, and so on, and the last ciphertext is the root. Sets finalKey
 * to be the key encrypting the root. */
void PuncEnc_BuildSubTree(uint8_t leaves[NUM_SUB_LEAVES][CT_LEN], uint8_t cts[SUB_TREE_SIZE][CT_LEN], uint8_t finalKey[KEY_LEN]) {
    /* For each level in subtree, choose random key, encrypt two children keys or leaf */
    printf1(TAG_GREEN, "in build subtree\n");

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
            crypto_aes256_init(keys[index], NULL);
            crypto_aes256_encrypt_sep(cts[index], currLeaves, KEY_LEN);
            currLeaves += KEY_LEN;
            crypto_aes256_encrypt_sep((uint8_t *)cts[index] + KEY_LEN, currLeaves, KEY_LEN);
            currLeaves += KEY_LEN;
            /* Next index. */
            printf1(TAG_GREEN, "index = %d/%d\n", index, SUB_TREE_SIZE);
            index++;
        }
        currLeaves = (uint8_t *)keys + (initialIndex * KEY_LEN);
        printf1(TAG_GREEN, "old currNumLeaves = %d\n", currNumLeaves);
        currNumLeaves /= 2.0;
        printf1(TAG_GREEN, "new currNumLeaves = %d\n", currNumLeaves);
    }

    /* Set key for root. */
    memcpy(finalKey, keys[SUB_TREE_SIZE - 1], KEY_LEN);

    printf1(TAG_GREEN, "done building subtree\n");
}

/* Set msk value. Should be called for final_key value for top subtree. */
void PuncEnc_SetMsk(uint8_t newMsk[KEY_LEN]) {
    memcpy(msk, newMsk, KEY_LEN);
}

/* Look up leaf in the tree given ciphertexts along the path to that leaf. */
void PuncEnc_RetrieveLeaf(uint8_t cts[LEVELS][CT_LEN], uint16_t index, uint8_t leaf[CT_LEN]) {
    uint8_t currKey[KEY_LEN];
    uint8_t leftKey[KEY_LEN];
    uint8_t rightKey[KEY_LEN];
    uint16_t currCmp = NUM_LEAVES / 2;
    uint16_t currIndex = index;
   
    memcpy(currKey, msk, KEY_LEN);

    printf1(TAG_GREEN, "trying to retrieve %d\n", index);

    /* Walk down the tree. */
    for (int i = 0; i < LEVELS - 1; i++) {
        printf("ct[%d]: ", i);
        for (int j = 0; j < CT_LEN; j++) {
            printf("%x ", cts[i][j]);
        }
        printf("\n");
        /* Decrypt current ciphertext. */
        crypto_aes256_init(currKey, NULL);
        crypto_aes256_decrypt_sep(leftKey, cts[i], KEY_LEN);
        crypto_aes256_decrypt_sep(rightKey, (uint8_t *)cts[i] + KEY_LEN, KEY_LEN);

        /* Choose to go left or right. */
        if (currIndex < currCmp) {
            printf("going left at %d\n", i);
            memcpy(currKey, leftKey, KEY_LEN);
        } else {
            printf("going right at %d\n", i);
            memcpy(currKey, rightKey, KEY_LEN);
            currIndex -= currCmp;
        }

        printf("left key at %d: ", i);
        for (int j = 0; j < KEY_LEN; j++) {
            printf("%x ", leftKey[j]);
        }
        printf("\n");

        printf("right key at %d: ", i);
        for (int j = 0; j < KEY_LEN; j++) {
            printf("%x ", rightKey[j]);
        }
        printf("\n");

        currCmp /= 2;
        //currIndex /= 2;
    }
    /* Set final leaf value. */
    crypto_aes256_init(currKey, NULL);
    crypto_aes256_decrypt_sep(leaf, cts[LEVELS -  1], CT_LEN);
    
    //memcpy(leaf, leftKey, KEY_LEN);
    //memcpy(leaf + KEY_LEN, rightKey, KEY_LEN);
}

/* Puncture a leaf. Given ciphertexts along the path to the leaf corresponding
 * to index, output a new set of ciphertexts. Also updates msk. */
void PuncEnc_PunctureLeaf(uint8_t oldCts[KEY_LEVELS][CT_LEN], uint16_t index, uint8_t newCts[KEY_LEVELS][CT_LEN]) {
    uint8_t currKey[KEY_LEN];
    uint8_t leftKeys[KEY_LEVELS][KEY_LEN];
    uint8_t rightKeys[KEY_LEVELS][KEY_LEN];
    uint8_t pathKeys[KEY_LEVELS][KEY_LEN];
    uint8_t pathDirs[KEY_LEVELS];
    uint16_t currCmp = NUM_LEAVES / 2;
    uint16_t currIndex = index;
    
    memcpy(currKey, msk, KEY_LEN);

    printf1(TAG_GREEN, "trying to puncture %d\n", index);

    /* Walk down to the leaf, recording information to create new set of cts. */
    for (int i = 0; i < KEY_LEVELS; i++) {
        memcpy(pathKeys[i], currKey, KEY_LEN);

        /* Decrypt ciphertext. */
        crypto_aes256_init(currKey, NULL);
        crypto_aes256_decrypt_sep(leftKeys[i], oldCts[i], KEY_LEN);
        crypto_aes256_decrypt_sep(rightKeys[i], (uint8_t *)oldCts[i] + KEY_LEN, KEY_LEN);

        /* Decide to go left or right. */
        if (currIndex < currCmp) {
            printf("going left at %d\n", i);
            memcpy(currKey, leftKeys[i], KEY_LEN);
            pathDirs[i] = 0;
        } else {
            printf("going right at %d\n", i);
            memcpy(currKey, rightKeys[i], KEY_LEN);
            currIndex -= currCmp;
            pathDirs[i] = 1;
        }
       
        printf("left key at %d: ", i);
        for (int j = 0; j < KEY_LEN; j++) {
            printf("%x ", leftKeys[i][j]);
        }
        printf("\n");

        printf("right key at %d: ", i);
        for (int j = 0; j < KEY_LEN; j++) {
            printf("%x ", rightKeys[i][j]);
        }
        printf("\n");

        currCmp /= 2;
    }

    /* Zero out leaf. */
    uint8_t newKey[KEY_LEN];
    memset(newKey, 0xaa, KEY_LEN);

    /* Generate new ciphertexts along path. */
    for (int i = KEY_LEVELS - 1; i >= 0; i--) {
        uint8_t plaintext[CT_LEN];
        /* Decide which key to leave and which to replace. */
        if (pathDirs[i] == 0) {
            printf("***keep right key: ");
            for (int j = 0; j < KEY_LEN; j++) {
                printf("%x ", rightKeys[i][j]);
            }
            printf("\n");

            memcpy(plaintext, newKey, KEY_LEN);
            memcpy((uint8_t *)plaintext + KEY_LEN, rightKeys[i], KEY_LEN);
        } else {
            memcpy(plaintext, leftKeys[i], KEY_LEN);
            memcpy((uint8_t *)plaintext + KEY_LEN, newKey, KEY_LEN);
        }

        /* Generate replacement key. */
        ctap_generate_rng(newKey,  KEY_LEN);
        printf("--- new key: ");
        for (int j = 0; j < KEY_LEN; j++) {
            printf("%x ", newKey[j]);
        }
        printf("\n");

        printf("--- PLAINTEXT: ");
        for (int j = 0; j < CT_LEN; j++) {
            printf("%x ", plaintext[j]);
        }
        printf("\n");
   
        /* Encrypt original key and replacement key. */
        crypto_aes256_init(newKey, NULL);
        crypto_aes256_encrypt_sep(newCts[KEY_LEVELS - i - 1], plaintext, KEY_LEN);
        //crypto_aes256_encrypt_sep(newCts[i], plaintext, KEY_LEN);
        crypto_aes256_encrypt_sep((uint8_t *)newCts[KEY_LEVELS - i - 1] + KEY_LEN, (uint8_t *)plaintext +  KEY_LEN, KEY_LEN);
        //crypto_aes256_encrypt_sep((uint8_t *)newCts[i] + KEY_LEN, (uint8_t *)plaintext +  KEY_LEN, KEY_LEN);

        printf("newCts[%d]: ", i);
        for (int j = 0; j < KEY_LEN; j++) {
            printf("%x ", newCts[i][j]);
        }
        printf("\n");
    }

    memcpy(msk, newKey, KEY_LEN);
}
