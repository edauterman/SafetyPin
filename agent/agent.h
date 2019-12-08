// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#ifndef _AGENT_H
#define _AGENT_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <map>

#include "ibe.h"
#include "params.h"
#include "u2f.h"

using namespace std;

typedef struct {
  /* Representation of fob used for HID transport. */
  struct U2Fob *device;
  Params params;
} Agent;

int Agent_init(Agent *a);
void Agent_destroy(Agent *a);

int GetMpk(Agent *a);
int Setup(Agent *a);
int Retrieve(Agent *a, uint16_t index);
int Puncture(Agent *a, uint16_t index);
int Encrypt(Agent *a, uint16_t index, uint8_t msg[IBE_MSG_LEN], IBE_ciphertext *c);
int Decrypt(Agent *a, uint16_t index, IBE_ciphertext *c, uint8_t msg[IBE_MSG_LEN]);

#endif

