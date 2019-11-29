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

#ifdef __cplusplus
extern "C" {
#endif

#define KEY_LEN 32
#define CT_LEN 64

#define RESPONSE_BUFFER_SIZE 4096

#define NUM_LEAVES NUM_SUB_LEAVES
//#define NUM_LEAVES 256
#define LEVELS 6 // log2(NUM_LEAVES) + 1
//#define LEVELS 16 // log2(NUM_LEAVES)

#define SUB_TREE_SIZE ((RESPONSE_BUFFER_SIZE / CT_LEN) - 1)
#define NUM_SUB_LEAVES ((SUB_TREE_SIZE + 1) / 2)

#define HSM_SETUP       0x70
#define HSM_RETRIEVE    0x71

typedef struct{
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];
    //uint8_t cts[LEVELS][NUM_LEAVES][32];
} HSM_SETUP_RESP;

typedef struct{
    uint16_t index;
    uint8_t cts[LEVELS][CT_LEN];
    //uint16_t index;
} HSM_RETRIEVE_REQ;

typedef struct{
    uint8_t leaf[CT_LEN];
} HSM_RETRIEVE_RESP;

#ifdef __cplusplus
}
#endif

#endif  // __DET2F_H_INCLUDED__
