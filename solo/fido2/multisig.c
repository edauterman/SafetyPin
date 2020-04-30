#include "bls12_381/bls12_381.h"
#include "multisig.h"
#include "ibe.h"

void Multisig_Setup(embedded_pairing_core_bigint_256_t *sk, embedded_pairing_bls12_381_g2_t *pk) {
    uint8_t hash[32];
    memset(hash, 0xff, 32);
    /* USING A DUMMY MSK ONLY FOR TESTING PURPOSES. */
    embedded_pairing_bls12_381_zp_from_hash(sk, hash);
    embedded_pairing_bls12_381_g2_multiply_affine(pk, embedded_pairing_bls12_381_g2affine_generator, sk);
}

void Multisig_Sign(embedded_pairing_core_bigint_256_t *sk, uint8_t *msg, int msgLen, embedded_pairing_bls12_381_g1_t *sig) { 
    embedded_pairing_bls12_381_g1affine_t base;
    uint8_t hashedMsg[embedded_pairing_bls12_381_g1_marshalled_uncompressed_size];

    hashToLength(hashedMsg, embedded_pairing_bls12_381_g1_marshalled_uncompressed_size, msg, msgLen);
    embedded_pairing_bls12_381_g1affine_from_hash(&base, hashedMsg);
    embedded_pairing_bls12_381_g1_multiply_affine(sig, &base, sk);
}

bool Multisig_Verify(embedded_pairing_bls12_381_g2_t *pk, uint8_t *msg, int msgLen, embedded_pairing_bls12_381_g1_t *sig) {
    uint8_t hashedMsg[embedded_pairing_bls12_381_g1_marshalled_uncompressed_size];
    embedded_pairing_bls12_381_g1affine_t base;
    embedded_pairing_bls12_381_g2affine_t pkAffine;
    embedded_pairing_bls12_381_g1affine_t sigAffine;
    embedded_pairing_bls12_381_fq12_t res1;
    embedded_pairing_bls12_381_fq12_t res2;

    // e(pk, H(m))
    hashToLength(hashedMsg, embedded_pairing_bls12_381_g1_marshalled_uncompressed_size, msg, msgLen);
    embedded_pairing_bls12_381_g1affine_from_hash(&base, hashedMsg);
    embedded_pairing_bls12_381_g2affine_from_projective(&pkAffine, pk);
    embedded_pairing_bls12_381_pairing(&res1, &base, &pkAffine);

    // e(g, sig)
    embedded_pairing_bls12_381_g1affine_from_projective(&sigAffine, sig);
    embedded_pairing_bls12_381_pairing(&res2, &sigAffine, embedded_pairing_bls12_381_g2affine_generator);

    // Check if equal
    return embedded_pairing_bls12_381_gt_equal(&res1, &res2);
}
