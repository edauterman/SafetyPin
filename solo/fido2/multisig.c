#include "bls12_381/bls12_381.h"
#include "multisig.h"
#include "ibe.h"

embedded_pairing_core_bigint_256_t sk;
embedded_pairing_bls12_381_g2_t pk;
embedded_pairing_bls12_381_g2_t aggPk;
embedded_pairing_bls12_381_g2affine_t aggPkAffine;

void Multisig_Setup() {
    uint8_t hash[32];
    memset(hash, 0xff, 32);
    /* USING A DUMMY MSK ONLY FOR TESTING PURPOSES. */
    embedded_pairing_bls12_381_zp_from_hash(&sk, hash);
    embedded_pairing_bls12_381_g2_multiply_affine(&pk, embedded_pairing_bls12_381_g2affine_generator, &sk);
}

void Multisig_GetPk(uint8_t *pkBuf) {
    embedded_pairing_bls12_381_g2affine_t pkAffine;
    embedded_pairing_bls12_381_g2affine_from_projective(&pkAffine, &pk);
    embedded_pairing_bls12_381_g2_marshal(pkBuf, &pkAffine, true);
}

void Multisig_SetAggPk(uint8_t *aggPkBuf) {
    embedded_pairing_bls12_381_g2_unmarshal(&aggPkAffine, aggPkBuf, true, true);
    embedded_pairing_bls12_381_g2_from_affine(&aggPk, &aggPkAffine);
}

void Multisig_Sign(uint8_t *msg, int msgLen, uint8_t *sig) { 
    embedded_pairing_bls12_381_g1affine_t base;
    uint8_t hashedMsg[embedded_pairing_bls12_381_g1_marshalled_uncompressed_size];
    embedded_pairing_bls12_381_g1_t sigPt;
    embedded_pairing_bls12_381_g1affine_t sigAffine;

    hashToLength(hashedMsg, embedded_pairing_bls12_381_g1_marshalled_uncompressed_size, msg, msgLen);
    embedded_pairing_bls12_381_g1affine_from_hash(&base, hashedMsg);
    embedded_pairing_bls12_381_g1_multiply_affine(&sigPt, &base, &sk);
    embedded_pairing_bls12_381_g1affine_from_projective(&sigPt, &sigAffine);
    embedded_pairing_bls12_381_g1_marshal(sig, &sigAffine, true);
}

uint8_t Multisig_Verify(uint8_t *msg, int msgLen, uint8_t *sig) {
    uint8_t hashedMsg[embedded_pairing_bls12_381_g1_marshalled_uncompressed_size];
    embedded_pairing_bls12_381_g1affine_t base;
    embedded_pairing_bls12_381_g2affine_t pkAffine;
    embedded_pairing_bls12_381_g1affine_t sigAffine;
    embedded_pairing_bls12_381_fq12_t res1;
    embedded_pairing_bls12_381_fq12_t res2;

    // e(pk, H(m))
    hashToLength(hashedMsg, embedded_pairing_bls12_381_g1_marshalled_uncompressed_size, msg, msgLen);
    embedded_pairing_bls12_381_g1affine_from_hash(&base, hashedMsg);
    embedded_pairing_bls12_381_pairing(&res1, &base, &aggPkAffine);

    // e(g, sig)
    embedded_pairing_bls12_381_g1_unmarshal(&sigAffine, sig, true, true);
    embedded_pairing_bls12_381_pairing(&res2, &sigAffine, embedded_pairing_bls12_381_g2affine_generator);

    // Check if equal
    return embedded_pairing_bls12_381_gt_equal(&res1, &res2) ? 1 : 0;
}
