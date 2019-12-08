// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <map>

#include <iostream>
#include <iomanip>

#ifdef __OS_WIN
#include <winsock2.h> // ntohl, htonl
#else
#include <arpa/inet.h> // ntohl, htonl
#endif

#include <openssl/ec.h>

#include "bls12_381/bls12_381.h"

#include "agent.h"
#include "asn1.h"
#include "common.h"
#include "hidapi.h"
#include "hsm.h"
#include "ibe.h"
#include "params.h"
#include "sig_parse.h"
#include "u2f.h"
#include "u2f_util.h"

#define EXPECTED_RET_VAL 0x9000

#define VENDOR_ID 0x0483
#define PRODUCT_ID 0xa2ca

using namespace std;

uint8_t cts[SUB_TREE_SIZE][CT_LEN];
embedded_pairing_bls12_381_g2_t mpk_;

/* Convert buffers containing x and y coordinates to EC_POINT. */
void bufs_to_pt(const_Params params, const uint8_t *x, const uint8_t *y,
                EC_POINT *pt) {
  uint8_t buf[65];
  buf[0] = 4;
  memcpy(buf + 1, x, 32);
  memcpy(buf + 1 + 32, y, 32);
  EC_POINT_oct2point(Params_group(params), pt, buf, 65, Params_ctx(params));
}

/* Convert EC_POINT to buffers containing x and y coordinates (uncompressed). */
void pt_to_bufs(const_Params params, const EC_POINT *pt, uint8_t *x,
                uint8_t *y) {
  uint8_t buf[65];
  EC_POINT_point2oct(Params_group(params), pt, POINT_CONVERSION_UNCOMPRESSED,
                     buf, 65, Params_ctx(params));
  memcpy(x, buf + 1, 32);
  memcpy(y, buf + 1 + 32, 32);
}

/* Given the path to the U2F device, initialize the agent. */
int create_agent(Agent *a, char *deviceName) {
  int rv = ERROR;

  CHECK_A (a->device = U2Fob_create());
  CHECK_A (a->params = Params_new(P256));
  
  CHECK_C (!U2Fob_open(a->device, deviceName));
  CHECK_C (!U2Fob_init(a->device));

cleanup:
  if (rv == ERROR) {
    Agent_destroy(a);
  }
  return rv;
}

/* Find a U2F device and initialize the agent. */
int Agent_init(Agent *a) {
  int rv = ERROR;
  struct hid_device_info *devs, *cur_dev;

  hid_init();
  devs = hid_enumerate(0x0, 0x0);
  cur_dev = devs;
  while (cur_dev) {
    if ((cur_dev->vendor_id == VENDOR_ID) &&
        (cur_dev->product_id == PRODUCT_ID)) {
      //fprintf(stderr, "det2f: found at %s\n", cur_dev->path);
      CHECK_C(create_agent(a, cur_dev->path));
      break;
    }
    cur_dev = cur_dev->next;
  }

cleanup:
  hid_exit();
  return rv;
}

/* Destroy current agent, including writing state to storage. */
void Agent_destroy(Agent *a) {

  if (a->device) U2Fob_destroy(a->device);
  if (a->params) Params_free(a->params);
}

int GetMpk(Agent *a) {
    int rv =  ERROR;
    HSM_MPK_RESP resp;
    string resp_str;

    CHECK_C(0 < U2Fob_apdu(a->device, 0, HSM_MPK, 0, 0,
                "", &resp_str));

    memcpy(&resp, resp_str.data(), resp_str.size());

    IBE_UnmarshalMpk(resp.mpk, &mpk_);

    printf("Got mpk\n");
cleanup:
    if (rv == ERROR) printf("MPK ERROR\n");
    return rv;
}

int Setup(Agent *a) {
    int rv =  ERROR;
    HSM_SETUP_RESP resp;
    string resp_str;

    CHECK_C(0 < U2Fob_apdu(a->device, 0, HSM_SETUP, 0, 0,
                "", &resp_str));

    memcpy(&resp, resp_str.data(), resp_str.size());
    memcpy(cts, resp.cts, SUB_TREE_SIZE * CT_LEN);

    printf("cts: ");
    for (int i = 0; i < SUB_TREE_SIZE; i++) {
        for (int j = 0; j < CT_LEN; j++) {
            printf("%x ", cts[i][j]);
        }
    }
    printf("\n");

    printf("started setup\n");
cleanup:
    if (rv == ERROR) printf("SETUP ERROR\n");
    return rv;
}

int Retrieve(Agent *a, uint16_t index) {
    int rv = ERROR;
    HSM_RETRIEVE_REQ req;
    HSM_RETRIEVE_RESP resp;
    string resp_str;
    uint16_t currIndex = index;
    uint16_t totalTraveled = 0;
    uint16_t currInterval = NUM_LEAVES;

    for (int i = 0; i < LEVELS; i++) {
        printf("currIndex = %d, totalTraveled = %d, currInterval = %d, will get %d/%d\n", currIndex, totalTraveled, currInterval, totalTraveled + currIndex, SUB_TREE_SIZE);
        
        memcpy(req.cts[LEVELS - i - 1], cts[totalTraveled + currIndex], CT_LEN);
        totalTraveled += currInterval;
        currInterval /= 2;
        currIndex /= 2;
    }

    req.index = index;

    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(a->device, 0, HSM_RETRIEVE, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));

    memcpy(&resp, resp_str.data(), resp_str.size());

    printf("finished retrieving leaf\n");
cleanup:
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

int Puncture(Agent *a, uint16_t index) {
    int rv = ERROR;
    HSM_PUNCTURE_REQ req;
    HSM_PUNCTURE_RESP resp;
    string resp_str;
    uint16_t currIndex = index;
    uint16_t totalTraveled = NUM_LEAVES;
    uint16_t currInterval = NUM_LEAVES / 2;
    size_t indexes[KEY_LEVELS];

    for (int i = 0; i < KEY_LEVELS; i++) {
        printf("currIndex = %d, totalTraveled = %d, currInterval = %d, will get %d/%d\n", currIndex, totalTraveled, currInterval, totalTraveled + currIndex, SUB_TREE_SIZE);
        
        memcpy(req.cts[KEY_LEVELS - i - 1], cts[totalTraveled + currIndex], CT_LEN);
        indexes[i] = totalTraveled + currIndex;
        totalTraveled += currInterval;
        currInterval /= 2;
        currIndex /= 2;
    }
    
    req.index = index;

    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(a->device, 0, HSM_PUNCTURE, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));

    memcpy(&resp, resp_str.data(), resp_str.size());

    for (int i = 0; i < KEY_LEVELS; i++) {
        printf("setting index %d for ct[%d]: ", indexes[i], i);
        memcpy(cts[indexes[i]], resp.cts[i], CT_LEN);
    }

    printf("finished puncturing leaf\n");
cleanup:
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}

int Encrypt(Agent *a, uint16_t index, uint8_t msg[IBE_MSG_LEN], IBE_ciphertext *c) {
    IBE_Encrypt(&mpk_, index, msg, c);
    return OKAY;
}

int Decrypt(Agent *a, uint16_t index, IBE_ciphertext *c, uint8_t msg[IBE_MSG_LEN]) {
    int rv = ERROR;
    HSM_DECRYPT_REQ req;
    HSM_DECRYPT_RESP resp;
    string resp_str;
    uint16_t currIndex = index;
    uint16_t totalTraveled = 0;
    uint16_t currInterval = NUM_LEAVES;

    for (int i = 0; i < LEVELS; i++) {
        printf("currIndex = %d, totalTraveled = %d, currInterval = %d, will get %d/%d\n", currIndex, totalTraveled, currInterval, totalTraveled + currIndex, SUB_TREE_SIZE);
        
        memcpy(req.treeCts[LEVELS - i - 1], cts[totalTraveled + currIndex], CT_LEN);
        totalTraveled += currInterval;
        currInterval /= 2;
        currIndex /= 2;
    }

    IBE_MarshalCt(c, req.ibeCt);
    req.index = index;

    CHECK_C(EXPECTED_RET_VAL == U2Fob_apdu(a->device, 0, HSM_DECRYPT, 0, 0,
                string(reinterpret_cast<char*>(&req), sizeof(req)), &resp_str));

    memcpy(&resp, resp_str.data(), resp_str.size());
    memcpy(msg, resp.msg, IBE_MSG_LEN);

    printf("finished retrieving decryption\n");
cleanup:
    if (rv != OKAY) printf("ERROR IN SENDING MSG\n");
    return rv;
}


