#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "bls12_381/bls12_381.h"
#include "common.h"
#include "hsm.h"
#include "ibe.h"
#include "params.h"
#include "punc_enc.h"

/* Support for puncturable encryption scheme. */

/* Helper for creating puncturable encryption tree at host. */
void encryptKeysAndCreateTag(uint8_t *encKey, uint8_t *hmacKey, uint8_t *key1, uint8_t *key2, uint8_t *ct) {
    EVP_CIPHER_CTX *enc_ctx;
    int bytesFilled;
    
    enc_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(enc_ctx, EVP_aes_256_cbc(), NULL, encKey, NULL);
    EVP_EncryptUpdate(enc_ctx, ct, &bytesFilled, key1, KEY_LEN);
    EVP_EncryptUpdate(enc_ctx, ct + KEY_LEN, &bytesFilled, key2, KEY_LEN);

    hmac(hmacKey, ct + 2 * KEY_LEN, ct, 2 * KEY_LEN);
}

// cts of size TREE_SIZE * CT_LEN
void PuncEnc_BuildTree(Params *params, uint8_t *cts, uint8_t msk[KEY_LEN],  uint8_t hmacKey[KEY_LEN], EC_POINT **mpk) {
    /* For each level in subtree, choose random key, encrypt two children keys or leaf */
    printf("building tree at host\n");

    uint8_t *leaves;
    int index = 0;
    int currNumLeaves = NUM_LEAVES;
    uint8_t *keys;
    BIGNUM *x;
    embedded_pairing_core_bigint_256_t ibeMsk;

    leaves = (uint8_t *)malloc(NUM_LEAVES * LEAF_LEN);
    keys = (uint8_t *)malloc(TREE_SIZE * KEY_LEN);
    uint8_t *currLeaves = (uint8_t *)leaves;
    int currPtr =  TREE_SIZE;
    x = BN_new();

    // Generate all keys.
    for (int i = 0; i < NUM_LEAVES; i++) {
        BN_rand_range(x, params->order);
        mpk[i] = EC_POINT_new(params->group);
        EC_POINT_mul(params->group, mpk[i], x, NULL, NULL, params->bn_ctx);
        memset(leaves + i * LEAF_LEN, 0, LEAF_LEN);
        BN_bn2bin(x, leaves + i * LEAF_LEN + KEY_LEN - BN_num_bytes(x));
    }

    RAND_bytes(hmacKey, KEY_LEN);

    /* Repeat for each level in tree. */
    while (currNumLeaves >= 1) {
        int initialIndex = index;
        /* For each child, generate parent. */
        for (int i = 0; i < currNumLeaves; i++) {
            /* Choose random key. */
            RAND_bytes(keys + (index * KEY_LEN), KEY_LEN);
            /* Encrypt leaf. */
            encryptKeysAndCreateTag(keys + index * KEY_LEN, hmacKey, currLeaves, currLeaves + KEY_LEN, cts + index * CT_LEN);
            currLeaves += LEAF_LEN;
            /* Next index. */
            index++;
        }
        currLeaves = (uint8_t *)keys + (initialIndex * KEY_LEN);
        printf("initial index = %d, currLeaves addr = %x\n", initialIndex, currLeaves);
        currPtr -= currNumLeaves;
        currNumLeaves /= 2.0;
    }

    /* Set key for root. */
    memcpy(msk, keys + (TREE_SIZE - 1) * KEY_LEN, KEY_LEN);

    printf("done building tree\n");
    free(leaves);
    free(keys);
}

/* Get the puncturable encryption indexes corresponding to a given tag. */
int PuncEnc_GetIndexesForTag(Params *params, uint32_t tag, uint32_t indexes[PUNC_ENC_REPL]) {
    int rv;
    uint8_t bufIn[8];
    uint8_t bufOut[SHA256_DIGEST_LENGTH];
    BIGNUM *modIndexBn;
    BIGNUM *rawIndexBn;
    BIGNUM *numLeavesBn;
    uint32_t indexInt;
    uint32_t numLeaves;

    printf("in get indexes for tag\n");

    CHECK_A (modIndexBn = BN_new());
    CHECK_A (numLeavesBn = BN_new());
    memset(bufIn, 0, 8);
    memcpy(bufIn, &tag, sizeof(uint16_t));

/*    printf("before num leaves\n");
    numLeaves = NUM_LEAVES;
    char numLeavesBuf[4];
    memset(numLeavesBuf, 0, 4);
    sprintf(numLeavesBuf, "%x", numLeaves);
    BN_hex2bn(&numLeavesBn, NUM_LEAVES_HEX_STR);
    printf("after num leaves: %s\n", BN_bn2hex(numLeavesBn));
*/
    for (uint32_t i = 0; i < PUNC_ENC_REPL; i++) {
        printf("i=%d\n", i);
        indexes[i] = 0;
        memcpy(bufIn +  sizeof(uint32_t), &i, sizeof(uint32_t));
        CHECK_C (hash_to_bytes(bufOut, SHA256_DIGEST_LENGTH, bufIn, 8));
        CHECK_A (rawIndexBn = BN_bin2bn(bufOut, SHA256_DIGEST_LENGTH, NULL));
        printf("right before mod: %s, %s, %s\n", BN_bn2hex(rawIndexBn), BN_bn2hex(params->numLeaves), BN_bn2hex(modIndexBn));
	CHECK_C (BN_mod(modIndexBn, rawIndexBn, params->numLeaves, params->bn_ctx));
	printf("did mod, i=%d\n", i);
	if (BN_num_bytes(modIndexBn) == 3) {
            uint8_t buf[3];
            memset(buf, 0, 3);
            BN_bn2bin(modIndexBn, buf);
            memcpy((uint8_t *)&indexes[i], buf + 2, 1);
            memcpy((uint8_t *)&indexes[i] + 1, buf + 1, 1);
            memcpy((uint8_t *)&indexes[i] + 2, buf, 1);
        } else if (BN_num_bytes(modIndexBn) == 2) {
            uint8_t buf[2];
            memset(buf, 0, 2);
            BN_bn2bin(modIndexBn, buf);
            memcpy((uint8_t *)&indexes[i], buf + 1, 1);
            memcpy((uint8_t *)&indexes[i] + 1, buf, 1);
        } else {
            BN_bn2bin(modIndexBn, (uint8_t *)&indexes[i]);
        }
    }
    printf("made it through\n");
cleanup:
    if (rv == ERROR) printf("ERROR in get indexes\n");
    else printf("success in get indexes\n");
    if (rawIndexBn) BN_free(rawIndexBn);
    if (modIndexBn) BN_free(modIndexBn);
    return rv;
}
