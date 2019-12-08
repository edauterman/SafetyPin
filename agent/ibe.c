#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "bls12_381/bls12_381.h"
#include "common.h"
#include "ibe.h"
#include "params.h"

void IBE_Setup(embedded_pairing_core_bigint_256_t *msk, embedded_pairing_bls12_381_g2_t *mpk) {
    /* Choose msk in Z_q^* */
//    embedded_pairing_bls12_381_zp_random(&msk, RAND_bytes);
    /* Set mpk */
    //embedded_pairing_bls12_381_g1_multiply_affine(&mpk, embedded_pairing_bls12_381_g1affine_zero, &msk);
    uint8_t hash[32];
    memset(hash, 0xff, 32);
    embedded_pairing_bls12_381_zp_from_hash(msk, hash);
    embedded_pairing_bls12_381_g2_multiply_affine(mpk, embedded_pairing_bls12_381_g2affine_zero, msk);
    //embedded_pairing_bls12_381_g2_multiply_affine(mpk, embedded_pairing_bls12_381_g2affine_generator, msk);

}

void IBE_Extract(embedded_pairing_core_bigint_256_t *msk, uint16_t index, embedded_pairing_bls12_381_g1_t *sk) {
    uint8_t indexHash[BASEFIELD_SZ_G1];
    uint8_t indexBuf[2];
    embedded_pairing_bls12_381_g1affine_t pt_affine;
    /* Map index to a point pt. */
    memcpy(indexBuf, &index, 2);
    hash_to_bytes(indexHash, BASEFIELD_SZ_G1, indexBuf, 2);
    //hashToLength(&index, sizeof(index), indexHash, BASEFIELD_SZ_G1);
    //hashToBaseField(index, indexHash);
    embedded_pairing_bls12_381_g1affine_from_hash(&pt_affine, indexHash);
    /* Set sk = pt^msk. */
    embedded_pairing_bls12_381_g1_multiply_affine(sk, &pt_affine, msk);
}

void IBE_Decrypt(embedded_pairing_bls12_381_g1_t *sk, IBE_ciphertext *c, uint8_t msg[IBE_MSG_LEN]) {
    embedded_pairing_bls12_381_g1affine_t sk_affine;
    embedded_pairing_bls12_381_g2affine_t U_affine;
    embedded_pairing_bls12_381_fq12_t U_sk;
    uint8_t U_sk_buf[embedded_pairing_bls12_381_gt_marshalled_size];
    uint8_t U_sk_buf_msg_len[IBE_MSG_LEN];
    uint8_t sigma[IBE_MSG_LEN];
    uint8_t M[IBE_MSG_LEN];
    uint8_t sigma_hash[IBE_MSG_LEN];
    uint8_t sigma_M[2 * IBE_MSG_LEN];
    uint8_t sigma_M_hash[SHA256_DIGEST_LENGTH];
    embedded_pairing_core_bigint_256_t r;
    embedded_pairing_bls12_381_g2_t U_test;

    /* \sigma = V XOR H(e(sk, U)) */
    embedded_pairing_bls12_381_g1affine_from_projective(&sk_affine, sk);
    embedded_pairing_bls12_381_g2affine_from_projective(&U_affine, &c->U);
    embedded_pairing_bls12_381_pairing(&U_sk, &sk_affine, &U_affine);
    embedded_pairing_bls12_381_gt_marshal(U_sk_buf, &U_sk);
    hash_to_bytes(U_sk_buf_msg_len, IBE_MSG_LEN, U_sk_buf, embedded_pairing_bls12_381_gt_marshalled_size);
    //hashToLength(U_sk_buf, embedded_pairing_bls12_381_gt_marshalled_size, U_sk_buf_msg_len, IBE_MSG_LEN);
    for (int i = 0; i < IBE_MSG_LEN; i++) {
        sigma[i] = U_sk_buf_msg_len[i] ^ c->V[i];
    }

    /* M = W XOR H(\sigma) */
    hash_to_bytes(sigma_hash, IBE_MSG_LEN, sigma, IBE_MSG_LEN);
    //hashToLength(sigma, IBE_MSG_LEN, sigma_hash, IBE_MSG_LEN);
    for (int i = 0; i < IBE_MSG_LEN; i++) {
        M[i] =  c->W[i] ^  sigma_hash[i];
    }

    /* r = H(\sigma, M) */
    memcpy(sigma_M, sigma, IBE_MSG_LEN);
    memcpy(sigma_M + IBE_MSG_LEN, M, IBE_MSG_LEN);
    hash_to_bytes(sigma_M_hash, SHA256_DIGEST_LENGTH, sigma_M, 2 * IBE_MSG_LEN);
    //hashToLength(sigma_M, 2 * IBE_MSG_LEN, sigma_M_hash, SHA256_DIGEST_LEN);
    embedded_pairing_bls12_381_zp_from_hash(&r, sigma_M_hash);

    /* Test u = rP */
    embedded_pairing_bls12_381_g2_multiply_affine(&U_test, embedded_pairing_bls12_381_g2affine_zero, &r);
    //embedded_pairing_bls12_381_g2_multiply_affine(&U_test, embedded_pairing_bls12_381_g2affine_generator, &r);
    if (!embedded_pairing_bls12_381_g2_equal(&U_test, &c->U)) {
        printf("--------- ERROR IN DECRYPTION ----------\n");
    }

    memcpy(msg, M, IBE_MSG_LEN);
}

int IBE_Encrypt(embedded_pairing_bls12_381_g2_t *mpk, uint16_t index, uint8_t msg[IBE_MSG_LEN], IBE_ciphertext *c) {
    int rv;
    embedded_pairing_bls12_381_g1affine_t pt_affine;
    uint8_t indexHash[BASEFIELD_SZ_G1];
    uint8_t sigma[IBE_MSG_LEN];
    uint8_t sigma_M[2 * IBE_MSG_LEN];
    uint8_t sigma_M_hash[SHA256_DIGEST_LENGTH];
    embedded_pairing_bls12_381_g2affine_t mpk_affine;
    embedded_pairing_bls12_381_fq12_t pt_mpk;
    uint8_t pt_mpk_buf[embedded_pairing_bls12_381_gt_marshalled_size];
    uint8_t pt_mpk_buf_msg_len[IBE_MSG_LEN];
    uint8_t sigma_hash[IBE_MSG_LEN];
    uint8_t indexBuf[sizeof(uint16_t)];
    embedded_pairing_core_bigint_256_t r;

    /* hash index to point */
    memcpy(indexBuf, &index, sizeof(index));
    CHECK_C (hash_to_bytes(indexHash, BASEFIELD_SZ_G1, indexBuf, sizeof(index)));
    embedded_pairing_bls12_381_g1affine_from_hash(&pt_affine, indexHash);

    /* randomly choose sigma */
    CHECK_C (RAND_bytes(sigma, IBE_MSG_LEN));

    /* r = H(\sigma, M) */
    memcpy(sigma_M, sigma, IBE_MSG_LEN);
    memcpy(sigma_M + IBE_MSG_LEN, msg, IBE_MSG_LEN);
    CHECK_C (hash_to_bytes(sigma_M_hash, SHA256_DIGEST_LENGTH, sigma_M, 2 * IBE_MSG_LEN));
    embedded_pairing_bls12_381_zp_from_hash(&r, sigma_M_hash);

    /* U = rP */
    embedded_pairing_bls12_381_g2_multiply_affine(&c->U, embedded_pairing_bls12_381_g2affine_zero, &r);
    //embedded_pairing_bls12_381_g2_multiply_affine(&c->U, embedded_pairing_bls12_381_g2affine_generator, &r);

    /* V = \sigma XOR H(e(pt, mpk)) */
    embedded_pairing_bls12_381_g2affine_from_projective(&mpk_affine, mpk);
    embedded_pairing_bls12_381_pairing(&pt_mpk, &pt_affine, &mpk_affine);
    embedded_pairing_bls12_381_gt_marshal(pt_mpk_buf, &pt_mpk);
    CHECK_C (hash_to_bytes(pt_mpk_buf_msg_len, IBE_MSG_LEN, pt_mpk_buf, embedded_pairing_bls12_381_gt_marshalled_size));
    for (int i = 0; i < IBE_MSG_LEN; i++)  {
        c->V[i] = sigma[i] ^  pt_mpk_buf_msg_len[i];
    }

    /* W = msg XOR H(\sigma) */
    CHECK_C (hash_to_bytes(sigma_hash, IBE_MSG_LEN, sigma, IBE_MSG_LEN));
    for (int i = 0; i < IBE_MSG_LEN; i++) {
        c->W[i] = msg[i] ^ sigma_hash[i];
    }

cleanup:
    return rv;
}

void IBE_MarshalCt(IBE_ciphertext *c, uint8_t buf[IBE_CT_LEN]) {
    embedded_pairing_bls12_381_g2affine_t U_affine;    
    embedded_pairing_bls12_381_g2affine_from_projective(&U_affine, &c->U);
    embedded_pairing_bls12_381_g2_marshal(buf, &U_affine, true);
    memcpy(buf + embedded_pairing_bls12_381_g2_marshalled_compressed_size, c->V, IBE_MSG_LEN);
    memcpy(buf + embedded_pairing_bls12_381_g2_marshalled_compressed_size + IBE_MSG_LEN, c->W, IBE_MSG_LEN);
}

void IBE_UnmarshalCt(uint8_t buf[IBE_CT_LEN], IBE_ciphertext *c) {
    embedded_pairing_bls12_381_g2affine_t U_affine;
    embedded_pairing_bls12_381_g2_unmarshal(&U_affine, buf, true, true); 
    embedded_pairing_bls12_381_g2_from_affine(&c->U, &U_affine);
    memcpy(c->V, buf + embedded_pairing_bls12_381_g2_marshalled_compressed_size, IBE_MSG_LEN);
    memcpy(c->W, buf + embedded_pairing_bls12_381_g1_marshalled_compressed_size + IBE_MSG_LEN, IBE_MSG_LEN);
}

void IBE_UnmarshalMpk(uint8_t buf[BASEFIELD_SZ_G2], embedded_pairing_bls12_381_g2_t *mpk) {
    embedded_pairing_bls12_381_g2affine_t mpk_affine;
    embedded_pairing_bls12_381_g2_unmarshal(&mpk_affine, buf, true, true);
    embedded_pairing_bls12_381_g2_from_affine(mpk, &mpk_affine);
}
