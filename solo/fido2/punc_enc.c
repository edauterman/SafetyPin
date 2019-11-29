#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "crypto.h"
#include "ctap.h"
#include "device.h"
#include "log.h"
#include "hsm.h"

//#define NUM_LEAVES 256
//#define LEVELS 8 // log2(NUM_LEAVES)

static uint8_t msk[KEY_LEN];

void crypto_aes256_encrypt_sep(uint8_t *out, uint8_t *in, int length) {
    for (int i = 0; i < length / 16; i++) {
        uint8_t tmp[16];
        memcpy(tmp, in + (i * 16), 16);
        crypto_aes256_encrypt(tmp, 16);
        memcpy(out + (i * 16), tmp, 16);
    }   
}


void crypto_aes256_decrypt_sep(uint8_t *out, uint8_t *in, int length) {
    for (int i = 0; i < length / 16; i++) {
        uint8_t tmp[16];
        memcpy(tmp, in + (i * 16), 16);
        crypto_aes256_decrypt(tmp, 16);
        memcpy(out + (i * 16), tmp, 16);
    }   
}

void PuncEnc_FillLeaves(uint8_t leaves[NUM_SUB_LEAVES][CT_LEN], int start) {
    for (int i = 0; i < NUM_SUB_LEAVES; i++) {
        /*leaves[i][0] = (i + start) & 0xff;
        leaves[i][1] = ((i + start) >> 8) & 0xff;
        leaves[i][2] = ((i + start) >> 16) & 0xff;
        leaves[i][3] = ((i + start) >> 24) & 0xff;
        memset(leaves[i] + 4, 0, 28);*/
        memset(leaves[i], 0xff, CT_LEN);
    }
}

/* need function to orchestrate building the subtree. */
/* SUB_TREE_SIZE = NUM_SUB_LEAVES * 2 - 1 */
void PuncEnc_BuildSubTree(uint8_t leaves[NUM_SUB_LEAVES][CT_LEN], uint8_t cts[SUB_TREE_SIZE][CT_LEN], uint8_t finalKey[KEY_LEN]) {
    /* For each level in subtree, choose random key, encrypt two children keys or leaf */
    printf1(TAG_GREEN, "in build subtree\n");

    int index = 0;
    int currNumLeaves = NUM_SUB_LEAVES;
    uint8_t *currLeaves = leaves;
    uint8_t keys[SUB_TREE_SIZE][KEY_LEN];

    printf1(TAG_GREEN, "NUM_SUB_LEAVES = %d, SUB_TREE_SIZE = %d\n", NUM_SUB_LEAVES, SUB_TREE_SIZE);

   /*  TODO: AES encrypt and decrypt is in place... IV can be 0 and just use a tmp buffer with teh input copied in, keeping in mind will be overwritten for output. */

    while (currNumLeaves >= 1) {
        int initialIndex = index;
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

    memcpy(finalKey, keys[SUB_TREE_SIZE - 1], KEY_LEN);

    printf1(TAG_GREEN, "done building subtree\n");
}

void PuncEnc_SetMsk(uint8_t newMsk[KEY_LEN]) {
    memcpy(msk, newMsk, KEY_LEN);
}

void PuncEnc_RetrieveLeaf(uint8_t cts[LEVELS][CT_LEN], uint16_t index, uint8_t leaf[CT_LEN]) {
    uint8_t currKey[KEY_LEN];
    uint8_t leftKey[KEY_LEN];
    uint8_t rightKey[KEY_LEN];
    uint16_t currCmp = NUM_LEAVES / 2;
    uint16_t currIndex = index;
    
    memcpy(currKey, msk, KEY_LEN);

    printf1(TAG_GREEN, "trying to retrieve %d\n", index);

    for (int i = 0; i < LEVELS; i++) {
        printf("ct[%d]: ", i);
        for (int j = 0; j < CT_LEN; j++) {
            printf("%x ", cts[i][j]);
        }
        printf("\n");
        crypto_aes256_init(currKey, NULL);
        crypto_aes256_decrypt_sep(leftKey, cts[i], KEY_LEN);
        crypto_aes256_decrypt_sep(rightKey, (uint8_t *)cts[i] + KEY_LEN, KEY_LEN);

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
    memcpy(leaf, leftKey, KEY_LEN);
    memcpy(leaf + KEY_LEN, rightKey, KEY_LEN);
}

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

    for (int i = 0; i < KEY_LEVELS - 1; i++) {
        memcpy(pathKeys[i], currKey, KEY_LEN);

        crypto_aes256_init(currKey, NULL);
        crypto_aes256_decrypt_sep(leftKeys[i], oldCts[i], KEY_LEN);
        crypto_aes256_decrypt_sep(rightKeys[i], (uint8_t *)oldCts[i] + KEY_LEN, KEY_LEN);

        if (currIndex <= currCmp) {
            printf("going left at %d\n", i);
            memcpy(currKey, leftKeys[i], KEY_LEN);
            pathDirs[i] = 0;
        } else {
            printf("going right at %d\n", i);
            memcpy(currKey, rightKeys[i], KEY_LEN);
            currIndex -= currCmp;
            pathDirs[i] = 1;
        }
        currCmp /= 2;
    }

    uint8_t newKey[KEY_LEN];
    memset(newKey, 0xaa, KEY_LEN);

    for (int i = KEY_LEVELS - 1; i >= 0; i--) {
        uint8_t plaintext[CT_LEN];
        if (pathDirs[i] == 0) {
            memcpy(plaintext, newKey, KEY_LEN);
            memcpy(plaintext + KEY_LEN, rightKeys[i], KEY_LEN);
        } else {
            memcpy(plaintext, leftKeys[i], KEY_LEN);
            memcpy(plaintext + KEY_LEN, newKey, KEY_LEN);
        }

        ctap_generate_rng(newKey,  KEY_LEN);

        crypto_aes256_init(newKey, NULL);
        crypto_aes256_encrypt_sep(newCts[i], plaintext, CT_LEN);

        printf("newCts[%d]: ", i);
        for (int j = 0; j < KEY_LEN; j++) {
            printf("%x ", newCts[i][j]);
        }
        printf("\n");
    }

    memcpy(msk, currKey, KEY_LEN);
}
