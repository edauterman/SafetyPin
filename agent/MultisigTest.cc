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

  printf("did init\n");

  for (int i = 0; i < NUM_HSMS; i++) {
    //HSM_GetMpk(d->hsms[i]);

    uint8_t msg[SHA256_DIGEST_LENGTH];
    embedded_pairing_bls12_381_g1_t sig;
    memset(msg, 0xaa, SHA256_DIGEST_LENGTH);

    HSM_MultisigGetPk(d->hsms[i]);
    HSM_MultisigSetAggPk(d->hsms[i], &d->hsms[i]->multisigPk);
    HSM_MultisigSign(d->hsms[i], &sig, msg);
    HSM_MultisigVerify(d->hsms[i], &sig, msg);
  }  

  Datacenter_free(d);

  printf("Test completed. \n");

  return 0;
}
