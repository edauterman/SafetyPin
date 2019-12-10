// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

/**
 * This header provides definitions for the protocol layer for deterministically
 * seeded U2F. Official FIDO-compliant definitions located in "u2f.h".
 */
#ifndef __HSM_H_INCLUDED__
#define __HSM_H_INCLUDED__

#include "hsm.h"
#include "ibe.h"
#include "bls12_381/bls12_381.h"
#include "u2f.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEY_LEN 32
#define CT_LEN (2 * KEY_LEN + 32)

#define RESPONSE_BUFFER_SIZE 4096

#define NUM_LEAVES NUM_SUB_LEAVES
//#define NUM_LEAVES 256
#define LEVELS 5 // log2(NUM_LEAVES) + 1
#define KEY_LEVELS (LEVELS - 1) // log2(NUM_LEAVES) + 1
//#define LEVELS 16 // log2(NUM_LEAVES)

#define SUB_TREE_SIZE ((RESPONSE_BUFFER_SIZE / (4 * KEY_LEN)) - 1)
#define NUM_SUB_LEAVES ((SUB_TREE_SIZE + 1) / 2)

#define HSM_SETUP       0x70
#define HSM_RETRIEVE    0x71
#define HSM_PUNCTURE    0x72
#define HSM_DECRYPT     0x73
#define HSM_MPK         0x74

typedef struct{
    uint8_t mpk[BASEFIELD_SZ_G2];
} HSM_MPK_RESP;

typedef struct{
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];
} HSM_SETUP_RESP;

typedef struct{
    uint16_t index;
    uint8_t cts[LEVELS][CT_LEN];
    //uint16_t index;
} HSM_RETRIEVE_REQ;

typedef struct{
    uint8_t leaf[CT_LEN];
} HSM_RETRIEVE_RESP;

typedef struct {
    uint16_t index;
    uint8_t cts[KEY_LEVELS][CT_LEN];
} HSM_PUNCTURE_REQ;

typedef struct {
    uint8_t cts[KEY_LEVELS][CT_LEN];
} HSM_PUNCTURE_RESP;

typedef struct {
    uint16_t index;
    uint8_t treeCts[LEVELS][CT_LEN];
    uint8_t ibeCt[IBE_CT_LEN];
} HSM_DECRYPT_REQ;

typedef struct {
    uint8_t msg[IBE_MSG_LEN];
} HSM_DECRYPT_RESP;

/* ---------------------------------- */

typedef struct {
    struct U2Fob *device;
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];
    embedded_pairing_bls12_381_g2_t mpk;
} HSM;

HSM *HSM_new();
void HSM_free(HSM *h);

int HSM_GetMpk(HSM *h);
int HSM_Setup(HSM *h);
int HSM_Retrieve(HSM *h, uint16_t index);
int HSM_Puncture(HSM *h, uint16_t index);
int HSM_Encrypt(HSM *h, uint16_t index, uint8_t *msg, int msgLen, IBE_ciphertext *c);
int HSM_Decrypt(HSM *h, uint16_t index, IBE_ciphertext *c, uint8_t *msg, int msgLen);

#ifdef __cplusplus
}
#endif

#endif  // __DET2F_H_INCLUDED__
