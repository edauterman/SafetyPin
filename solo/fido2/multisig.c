#include "bls12_381/bls12_381.h"
#include "multisig.h"
#include "ibe.h"

/* Aggregate signature scheme. */

embedded_pairing_core_bigint_256_t sk;
embedded_pairing_bls12_381_g2_t pk;
embedded_pairing_bls12_381_g2_t aggPk;
embedded_pairing_bls12_381_g2affine_t aggPkAffine;
embedded_pairing_bls12_381_g2affine_t pkAffine;

/* Run setup (should be called before calling any other Multisig functions). */
void Multisig_Setup() {
    uint8_t hash[32];
    memset(hash, 0xff, 32);
    /* USING A DUMMY MSK ONLY FOR TESTING PURPOSES. */
    embedded_pairing_bls12_381_zp_from_hash(&sk, hash);
    embedded_pairing_bls12_381_g2_multiply_affine(&pk, embedded_pairing_bls12_381_g2affine_generator, &sk);
}

/* Return the public key corresponding to the secret key used to sign. */
void Multisig_GetPk(uint8_t *pkBuf) {
    embedded_pairing_bls12_381_g2affine_from_projective(&pkAffine, &pk);
    memset(pkBuf, 0, embedded_pairing_bls12_381_g2_marshalled_compressed_size);
    embedded_pairing_bls12_381_g2_marshal(pkBuf, &pkAffine, true);
}

/* Set the aggregate public key used for signature verification. */
void Multisig_SetAggPk(uint8_t *aggPkBuf) {
    embedded_pairing_bls12_381_g2_unmarshal(&aggPkAffine, aggPkBuf, true, true);
    embedded_pairing_bls12_381_g2_from_affine(&aggPk, &aggPkAffine);
}

/* Generate a signature for a message (can be aggregate with other signatures). */
void Multisig_Sign(uint8_t *msg, int msgLen, uint8_t *sig) { 
    embedded_pairing_bls12_381_g1affine_t base;
    uint8_t hashedMsg[384];
    embedded_pairing_bls12_381_g1_t sigPt;
    embedded_pairing_bls12_381_g1_t basePt;
    embedded_pairing_bls12_381_g1affine_t sigAffine;
    embedded_pairing_core_bigint_256_t r;

    hashToLength(msg, msgLen, hashedMsg, 384);
    embedded_pairing_bls12_381_g1affine_from_hash(&base, hashedMsg);
    embedded_pairing_bls12_381_g1_multiply_affine(&sigPt, &base, &sk);
    embedded_pairing_bls12_381_g1affine_from_projective(&sigAffine, &sigPt);
    embedded_pairing_bls12_381_g1_marshal(sig, &sigAffine, true);

}

/* Verify an aggregate signature using the aggregate public key. */
uint8_t Multisig_Verify(uint8_t *msg, int msgLen, uint8_t *sig) {
    uint8_t hashedMsg[384];
    embedded_pairing_bls12_381_g1_t basePt;
    embedded_pairing_bls12_381_g1affine_t base;
    embedded_pairing_bls12_381_g1affine_t sigAffine;
    embedded_pairing_bls12_381_fq12_t res1;
    embedded_pairing_bls12_381_fq12_t res2;
    embedded_pairing_core_bigint_256_t r;
    
    // e(pk, H(m))
    hashToLength(msg, msgLen, hashedMsg, 384);
    embedded_pairing_bls12_381_g1affine_from_hash(&base, hashedMsg);
    embedded_pairing_bls12_381_pairing(&res1, &base, &aggPkAffine);

    // e(g, sig)
    embedded_pairing_bls12_381_g1_unmarshal(&sigAffine, sig, true, true);
    embedded_pairing_bls12_381_pairing(&res2, &sigAffine, embedded_pairing_bls12_381_g2affine_generator);

    return embedded_pairing_bls12_381_gt_equal(&res1, &res2) ? 1 : 0;
}
