#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bls12_381/bls12_381.h"
#include "common.h"
#include "params.h"
#include "multisig.h"

/* Aggregate signature scheme. */

void Multisig_Setup(embedded_pairing_core_bigint_256_t *sk, embedded_pairing_bls12_381_g2_t *pk) {
    uint8_t hash[32];
    memset(hash, 0xff, 32);
    /* USING A DUMMY MSK ONLY FOR TESTING PURPOSES. */
    embedded_pairing_bls12_381_zp_from_hash(sk, hash);
    embedded_pairing_bls12_381_g2_multiply_affine(pk, embedded_pairing_bls12_381_g2affine_generator, sk);
}

void Multisig_Sign(embedded_pairing_core_bigint_256_t *sk, uint8_t *msg, int msgLen, embedded_pairing_bls12_381_g1_t *sig) {
    embedded_pairing_bls12_381_g1affine_t base;
    uint8_t hashedMsg[384];

    // H(m)^sk
    hash_to_bytes(hashedMsg, 384, msg, msgLen);
    embedded_pairing_bls12_381_g1affine_from_hash(&base, hashedMsg);
    embedded_pairing_bls12_381_g1_multiply_affine(sig, &base, sk);
}


bool Multisig_Verify(embedded_pairing_bls12_381_g2_t *pk, uint8_t *msg, int msgLen, embedded_pairing_bls12_381_g1_t *sig) {
    uint8_t hashedMsg[384];
    embedded_pairing_bls12_381_g1affine_t base;
    embedded_pairing_bls12_381_g2affine_t pkAffine;
    embedded_pairing_bls12_381_g1affine_t sigAffine;
    embedded_pairing_bls12_381_fq12_t res1;
    embedded_pairing_bls12_381_fq12_t res2;

    // e(pk, H(m))
    hash_to_bytes(hashedMsg, 384, msg, msgLen);
    hash_to_bytes(hashedMsg, sizeof(embedded_pairing_bls12_381_fq_t), msg, msgLen);
    embedded_pairing_bls12_381_g1affine_from_hash(&base, hashedMsg);
    embedded_pairing_bls12_381_g2affine_from_projective(&pkAffine, pk);
    embedded_pairing_bls12_381_pairing(&res1, &base, &pkAffine); 

    // e(g, sig)
    embedded_pairing_bls12_381_g1affine_from_projective(&sigAffine, sig);
    embedded_pairing_bls12_381_pairing(&res2, &sigAffine, embedded_pairing_bls12_381_g2affine_generator);

    // Check if equal
    return embedded_pairing_bls12_381_gt_equal(&res1, &res2);
}

void Multisig_AggPks(embedded_pairing_bls12_381_g2_t *pkList, int len, embedded_pairing_bls12_381_g2_t *aggPk) {
    embedded_pairing_bls12_381_g2_t tmpList[len];
    if (len == 1) {
        embedded_pairing_bls12_381_g2_add(aggPk, embedded_pairing_bls12_381_g2_zero, &pkList[0]);
        return;
    }
    embedded_pairing_bls12_381_g2_add(&tmpList[0], embedded_pairing_bls12_381_g2_zero, &pkList[0]);
    for (int i = 1; i < len - 1; i++) {
        embedded_pairing_bls12_381_g2_add(&tmpList[i], &tmpList[i-1], &pkList[i]);
    }
    embedded_pairing_bls12_381_g2_add(aggPk, &tmpList[len - 2], &pkList[len - 1]);
}

void Multisig_AggSigs(embedded_pairing_bls12_381_g1_t *sigList, int len, embedded_pairing_bls12_381_g1_t *aggSig) {
    embedded_pairing_bls12_381_g1_t tmpList[len];
    if (len == 1) {
        embedded_pairing_bls12_381_g1_add(aggSig, embedded_pairing_bls12_381_g1_zero, &sigList[0]);
        return;
    }
    embedded_pairing_bls12_381_g1_add(&tmpList[0], embedded_pairing_bls12_381_g1_zero, &sigList[0]);
    for (int i = 1; i < len - 1; i++) {
        embedded_pairing_bls12_381_g1_add(&tmpList[i], &tmpList[i-1], &sigList[i]);
    }
    embedded_pairing_bls12_381_g1_add(aggSig, &tmpList[len - 2], &sigList[len - 1]);
}
