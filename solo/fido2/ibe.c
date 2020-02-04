#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "crypto.h"
#include "ctap.h"
#include "device.h"
#include "ibe.h"
#include "bls12_381/bls12_381.h"

embedded_pairing_core_bigint_256_t msk;
embedded_pairing_bls12_381_g2_t mpk;

void IBE_Setup() {
    /* Choose msk in Z_q^* */
    embedded_pairing_bls12_381_zp_random(&msk, ctap_generate_rng);
    /* Set mpk */
    embedded_pairing_bls12_381_g2_multiply_affine(&mpk, embedded_pairing_bls12_381_g2affine_zero, &msk);

}

void hashToLength(uint8_t *inBytes, int inLen, uint8_t *outBytes, int outLen) {
    uint16_t ctr = 0;
    int bytesFilled = 0;
    while (bytesFilled < outLen) {
        uint8_t tmp[SHA256_DIGEST_LEN];
        crypto_sha256_init();
        crypto_sha256_update(&ctr, sizeof(uint16_t));
        crypto_sha256_update(inBytes, inLen);
        crypto_sha256_final(tmp);
        
        int bytesToCopy = outLen -  bytesFilled > SHA256_DIGEST_LEN ? SHA256_DIGEST_LEN : outLen - bytesFilled;
        memcpy(outBytes + bytesFilled, tmp, bytesToCopy);
        bytesFilled += bytesToCopy;
        ctr++;
    }
}

void IBE_Extract(uint16_t index, embedded_pairing_bls12_381_g1_t *sk) {
    uint8_t indexBuf[sizeof(index)];
    uint8_t indexHash[BASEFIELD_SZ_G1];
    embedded_pairing_bls12_381_g1affine_t pt_affine;
    /* Map index to a point pt. */
    memcpy(indexBuf, &index, sizeof(index));
    hashToLength(indexBuf, sizeof(index), indexHash, BASEFIELD_SZ_G1);
    //hashToBaseField(index, indexHash);
    embedded_pairing_bls12_381_g1affine_from_hash(&pt_affine, indexHash);
    /* Set sk = pt^msk. */
    embedded_pairing_bls12_381_g1_multiply_affine(sk, &pt_affine, &msk);
}

void IBE_Decrypt(embedded_pairing_bls12_381_g1_t *sk, embedded_pairing_bls12_381_g2_t *U, uint8_t *V, uint8_t *W, uint8_t *msg, int msgLen) {
    embedded_pairing_bls12_381_g1affine_t sk_affine;
    embedded_pairing_bls12_381_g2affine_t U_affine;
    embedded_pairing_bls12_381_fq12_t U_sk;
    uint8_t U_sk_buf[embedded_pairing_bls12_381_gt_marshalled_size];
    //uint8_t U_sk_buf_msg_len[msgLen];
    //uint8_t sigma[msgLen];
    uint8_t tmp[msgLen];
    //uint8_t M[msgLen];
    //uint8_t sigma_hash[msgLen];
    uint8_t sigma_M[2 * msgLen];
    uint8_t sigma_M_hash[SHA256_DIGEST_LEN];
    embedded_pairing_core_bigint_256_t r;
    embedded_pairing_bls12_381_g2_t U_test;

    printf("starting decrypt\n");

    /* \sigma = V XOR H(e(sk, U)) */
    embedded_pairing_bls12_381_g1affine_from_projective(&sk_affine, sk);
    embedded_pairing_bls12_381_g2affine_from_projective(&U_affine, U);
    printf("before pairing\n");
    embedded_pairing_bls12_381_pairing(&U_sk, &sk_affine, &U_affine);
    printf("after pairing\n");
    embedded_pairing_bls12_381_gt_marshal(U_sk_buf, &U_sk);
    hashToLength(U_sk_buf, embedded_pairing_bls12_381_gt_marshalled_size, tmp, msgLen);
    //hashToLength(U_sk_buf, embedded_pairing_bls12_381_gt_marshalled_size, U_sk_buf_msg_len, msgLen);
    for (int i = 0; i < msgLen; i++) {
        sigma_M[i] = tmp[i] ^ V[i];
    }

    printf("finished 1\n");

    /* M = W XOR H(\sigma) */
    hashToLength(sigma_M, msgLen, tmp, msgLen);
    for (int i = 0; i < msgLen; i++) {
        sigma_M[i + msgLen] =  W[i] ^  tmp[i];
    }

    printf("finished 2\n");

    /* r = H(\sigma, M) */
    //memcpy(sigma_M, sigma, msgLen);
    //memcpy(sigma_M + msgLen, M, msgLen);
    hashToLength(sigma_M, 2 * msgLen, sigma_M_hash, SHA256_DIGEST_LEN);
    embedded_pairing_bls12_381_zp_from_hash(&r, sigma_M_hash);

    printf("finished 3\n");

    /* Test u = rP */
    embedded_pairing_bls12_381_g2_multiply_affine(&U_test, embedded_pairing_bls12_381_g2affine_zero, &r);
    if (!embedded_pairing_bls12_381_g2_equal(&U_test, U)) {
        memset(msg, 0x8, msgLen);
        printf("--------- ERROR IN DECRYPTION ----------\n");
        return;
    }

    memcpy(msg, sigma_M + msgLen, msgLen);
    printf("finished decrypt\n");
}

void IBE_MarshalCt(uint8_t *buf, int msgLen, embedded_pairing_bls12_381_g2_t *U, uint8_t *V, uint8_t *W) {
    embedded_pairing_bls12_381_g2affine_t U_affine;
    embedded_pairing_bls12_381_g2affine_from_projective(&U_affine, U);
    embedded_pairing_bls12_381_g2_marshal(&U_affine, buf, true);
    memcpy(buf + embedded_pairing_bls12_381_g2_marshalled_compressed_size, V, msgLen);
    memcpy(buf + embedded_pairing_bls12_381_g2_marshalled_compressed_size + msgLen, W, msgLen);
}

void IBE_UnmarshalCt(uint8_t *buf, int msgLen, embedded_pairing_bls12_381_g2_t *U, uint8_t *V, uint8_t *W) {
    embedded_pairing_bls12_381_g2affine_t U_affine;
    embedded_pairing_bls12_381_g2_unmarshal(&U_affine, buf, true, true);
    embedded_pairing_bls12_381_g2_from_affine(U, &U_affine);
    memcpy(V, buf + embedded_pairing_bls12_381_g2_marshalled_compressed_size, msgLen);
    memcpy(W, buf + embedded_pairing_bls12_381_g2_marshalled_compressed_size + msgLen, msgLen);
}

void IBE_MarshalMpk(uint8_t buf[BASEFIELD_SZ_G2]) {
    embedded_pairing_bls12_381_g2affine_t mpk_affine;
    embedded_pairing_bls12_381_g2affine_from_projective(&mpk_affine, &mpk);
    embedded_pairing_bls12_381_g2_marshal(&mpk_affine, buf, true);
}

void IBE_UnmarshalSk(uint8_t buf[BASEFIELD_SZ_G1], embedded_pairing_bls12_381_g1_t *sk) {
    embedded_pairing_bls12_381_g1affine_t sk_affine;
    embedded_pairing_bls12_381_g1_unmarshal(&sk_affine, buf, true, true);
    embedded_pairing_bls12_381_g1_from_affine(sk, &sk_affine);
}

// TODO: decrypt
