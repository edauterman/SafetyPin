// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <thread>
#include <vector>
#include <sys/time.h>

#include "datacenter.h"
#include "hsm.h"
#include "ibe.h"
#include "common.h"
#include "multisig.h"
#include "bls12_381/bls12_381.h"

using namespace std;

int main(int argc, char *argv[]) {

  int numHsms = 100;
  int hsmGroupSize = 100;
  int hsmThresholdSize = 50;
  int chunkSize = 1;

  if (argc >= 2) {
    chunkSize = atoi(argv[1]);
    printf("Chunk size: %d\n", chunkSize);
  }

  Datacenter *d = Datacenter_new(numHsms, hsmGroupSize, chunkSize);
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  uint8_t logPk[COMPRESSED_PT_SZ];
  LogState *state = Log_RunSetup();
  printf("Finished log setup\n");

  embedded_pairing_bls12_381_g2_t aggPk;
  embedded_pairing_bls12_381_g2_t *multisigPks = (embedded_pairing_bls12_381_g2_t *)malloc(numHsms * sizeof(embedded_pairing_bls12_381_g2_t));
  vector<thread> t(numHsms);

  Log_Init(d->hsms[0]->params);
  Log_GetPk(d->hsms[0]->params, logPk);

  printf("Initialized log\n");

  for (int i = 0; i < numHsms; i++) {
    HSM_SetParams(d->hsms[i], hsmGroupSize, hsmThresholdSize, chunkSize, logPk);
  }

  for (int i = 0; i < numHsms; i++) {
      t[i] = thread(HSM_MultisigGetPk, d->hsms[i]);
  }
  for (int i = 0; i < numHsms; i++) {
      t[i].join();
      memcpy((uint8_t *)&multisigPks[i], (uint8_t *)&d->hsms[i]->multisigPk, sizeof(embedded_pairing_bls12_381_g2_t));
  }

  Multisig_AggPks(multisigPks, numHsms, &aggPk);

  for (int i = 0; i < numHsms; i++) {
      t[i] = thread(HSM_MultisigSetAggPk, d->hsms[i], &aggPk);
  }
  for (int i = 0; i < numHsms; i++) {
      t[i].join();
  }

  printf("Going to start log epoch verification\n");

  Datacenter_LogEpochVerification(d, state);
  
  Datacenter_free(d);

  return 0;
}
