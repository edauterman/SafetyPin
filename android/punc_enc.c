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

void encryptKeysAndCreateTag(uint8_t *encKey, uint8_t *hmacKey, uint8_t *key1, uint8_t *key2, uint8_t *ct) {
    EVP_CIPHER_CTX *enc_ctx;
    int bytesFilled;
    
    enc_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_ecb(), NULL, encKey, NULL);
    //EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_ecb(), NULL, encKey, NULL);
    EVP_EncryptUpdate(enc_ctx, ct, &bytesFilled, key1, KEY_LEN);
    EVP_EncryptUpdate(enc_ctx, ct + KEY_LEN, &bytesFilled, key2, KEY_LEN);

    hmac(hmacKey, ct + 2 * KEY_LEN, ct, 2 * KEY_LEN);
}

/* Set the values of the leaves in a subtree, where the leaves in the subtree
 * begin at value start. */
void setIBELeaves(embedded_pairing_core_bigint_256_t *ibeMsk, uint8_t *leaves) {
    for (int i = 0; i < NUM_LEAVES; i++) {
        //memset(leaves[i], 0xff, LEAF_LEN);

        memset(leaves + i * LEAF_LEN, 0, LEAF_LEN);
        //memset(leaves[i], 0, LEAF_LEN);
        uint8_t buf[embedded_pairing_bls12_381_g1_marshalled_compressed_size];
        embedded_pairing_bls12_381_g1_t sk;
        embedded_pairing_bls12_381_g1affine_t sk_affine;
        IBE_Extract(ibeMsk, i, &sk);
        embedded_pairing_bls12_381_g1affine_from_projective(&sk_affine, &sk);
        embedded_pairing_bls12_381_g1_marshal(buf, &sk_affine, true);
        //memset(buf, 0xff, embedded_pairing_bls12_381_g1_marshalled_compressed_size);
        memcpy(leaves + i * LEAF_LEN, buf, embedded_pairing_bls12_381_g1_marshalled_compressed_size);
        //memcpy(leaves[i], buf, embedded_pairing_bls12_381_g1_marshalled_compressed_size);
        /* DELETE THIS NEXT LINE */
        //memset(leaves + i * LEAF_LEN, 0xff, LEAF_LEN);

        printf("leaf %d: ", i);
        for (int j = 0; j < 48; j++) {
            printf("%x ", buf[j]);
        }
        printf("\n");
        //memset(leaves[i], 0xff, CT_LEN);
    }
}

// cts of size TREE_SIZE * CT_LEN
void PuncEnc_BuildTree(uint8_t *cts, uint8_t msk[KEY_LEN],  uint8_t hmacKey[KEY_LEN], embedded_pairing_bls12_381_g2_t *mpk) {
    /* For each level in subtree, choose random key, encrypt two children keys or leaf */
    printf("building tree at host\n");

    uint8_t *leaves;
    //uint8_t leaves[NUM_LEAVES][LEAF_LEN];
    int index = 0;
    int currNumLeaves = NUM_LEAVES;
    uint8_t *keys;
    //uint8_t keys[TREE_SIZE][KEY_LEN];
    embedded_pairing_core_bigint_256_t ibeMsk;

    leaves = (uint8_t *)malloc(NUM_LEAVES * LEAF_LEN);
    keys = (uint8_t *)malloc(TREE_SIZE * KEY_LEN);
    uint8_t *currLeaves = (uint8_t *)leaves;

    uint8_t hash[32];
    memset(hash, 0xff, 32);
    embedded_pairing_bls12_381_zp_from_hash(&ibeMsk, hash);
    embedded_pairing_bls12_381_g2_multiply_affine(mpk, embedded_pairing_bls12_381_g2affine_zero, &ibeMsk);
    setIBELeaves(&ibeMsk, leaves);

    printf("set ibe leaves\n");

    RAND_bytes(hmacKey, KEY_LEN);

    /* Repeat for each level in tree. */
    while (currNumLeaves >= 1) {
        int initialIndex = index;
        /* For each child, generate parent. */
        for (int i = 0; i < currNumLeaves; i++) {
            /* Choose random key. */
            RAND_bytes(keys + index * KEY_LEN, KEY_LEN);
            //RAND_bytes(keys[index], KEY_LEN);
            /* Encrypt leaf. */
            encryptKeysAndCreateTag(keys + index * KEY_LEN, hmacKey, currLeaves, currLeaves + KEY_LEN, cts + index * CT_LEN);
            //encryptKeysAndCreateTag(keys + index * KEY_LEN, hmacKey, currLeaves, currLeaves + KEY_LEN, cts[index]);
            currLeaves += LEAF_LEN;
            /* Next index. */
            printf("index = %d/%d\n", index, TREE_SIZE);
            index++;
        }
        currLeaves = (uint8_t *)keys + (initialIndex * KEY_LEN);
        printf("old currNumLeaves = %d\n", currNumLeaves);
        currNumLeaves /= 2.0;
        printf("new currNumLeaves = %d\n", currNumLeaves);
    }

    /* Set key for root. */
    memcpy(msk, keys + (TREE_SIZE - 1) * KEY_LEN, KEY_LEN);
    //memcpy(msk, keys[TREE_SIZE - 1], KEY_LEN);

    printf("done building tree\n");
    free(leaves);
    free(keys);
}

int PuncEnc_GetIndexesForTag(Params *params, uint32_t tag, uint32_t indexes[PUNC_ENC_REPL]) {
    int rv;
    uint8_t bufIn[8];
    uint8_t bufOut[SHA256_DIGEST_LENGTH];
    BIGNUM *modIndexBn;
    BIGNUM *rawIndexBn;
    uint32_t indexInt;
    
    CHECK_A (modIndexBn = BN_new());
    memcpy(bufIn, &tag, sizeof(uint16_t));

    for (uint32_t i = 0; i < PUNC_ENC_REPL; i++) {
        indexes[i] = 0;
        memcpy(bufIn +  sizeof(uint32_t), &i, sizeof(uint32_t));
        CHECK_C (hash_to_bytes(bufOut, SHA256_DIGEST_LENGTH, bufIn, 8));
        CHECK_A (rawIndexBn = BN_bin2bn(bufOut, SHA256_DIGEST_LENGTH, NULL));
        CHECK_C (BN_mod(modIndexBn, rawIndexBn, params->numLeaves, params->bn_ctx));
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

        //printf("numLeaves: %s, tag: %s, num bytes: %d\n", BN_bn2hex(params->numLeaves), BN_bn2hex(modIndexBn), BN_num_bytes(modIndexBn));
        //printf("%d -> %d (%d/%d)\n", tag, indexes[i], i, PUNC_ENC_REPL);
    }
cleanup:
    if (rawIndexBn) BN_free(rawIndexBn);
    if (modIndexBn) BN_free(modIndexBn);
    return rv;
}