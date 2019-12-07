#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "bls12_381/bls12_381.h"
#include "common.h"
#include "ibe.h"
#include "params.h"

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
    embedded_pairing_bls12_381_g2_multiply_affine(&c->U, embedded_pairing_bls12_381_g2affine_generator, &r);

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
