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

#include "datacenter.h"
#include "hsm.h"
#include "ibe.h"
#include "common.h"

using namespace std;

int main(int argc, char *argv[]) {

  Datacenter *d = Datacenter_new();
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  //Datacenter_SmallSetup(d);
  Datacenter_TestSetup(d);

  Params *params = Params_new(); 

  BIGNUM *pin;
  BIGNUM *saveKey;
  BIGNUM *saveKeyTest;
  saveKey = BN_new();
  pin = BN_new();
  saveKeyTest = BN_new();
  BN_rand_range(saveKey, params->order);
  BN_rand_range(pin, params->order);
  RecoveryCiphertext *c = RecoveryCiphertext_new();

  Datacenter_Save(d, params, saveKey, 0, pin, c);
  Datacenter_Recover(d, params, saveKeyTest, 0, pin, c);

  if (BN_cmp(saveKey, saveKeyTest) != 0) {
    printf("FAIL: expected to recover:\n %s\n but recovered:\n %s\n", BN_bn2hex(saveKey), BN_bn2hex(saveKeyTest));
  } else {
    printf("SUCCESS: recovered successfully.\n");
  }

  RecoveryCiphertext_free(c);
  Datacenter_free(d);

  printf("Initialization completed. \n");

  return 0;
}
