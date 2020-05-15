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
#include <map>
#include <sys/time.h>

#include "datacenter.h"
#include "hsm.h"
#include "ibe.h"
#include "common.h"
#include "multisig.h"
#include "bls12_381/bls12_381.h"

using namespace std;

int main(int argc, char *argv[]) {

  Datacenter *d = Datacenter_new();
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  uint8_t logPk[COMPRESSED_PT_SZ];
  LogState *state = Log_RunSetup();
  printf("Finished setup\n");

  embedded_pairing_bls12_381_g2_t aggPk;
  embedded_pairing_bls12_381_g2_t multisigPks[NUM_HSMS];
  embedded_pairing_bls12_381_g1_t sigs[NUM_HSMS];
  embedded_pairing_bls12_381_g1_t aggSig;
  thread t[NUM_HSMS];

  printf("rootsTree ids = (%d, %d, %d)\n", state->rootsTree->leftID, state->rootsTree->midID, state->rootsTree->rightID);

  Log_Init(d->hsms[0]->params);
  Log_GetPk(d->hsms[0]->params, logPk);
  
  for (int i = 0; i < NUM_HSMS; i++) {
    HSM_SetParams(d->hsms[i], logPk);
    memcpy((uint8_t *)&multisigPks[i], (uint8_t *)&d->hsms[i]->multisigPk, sizeof(embedded_pairing_bls12_381_g2_t));
//    HSM_MultisigSetAggPk(d->hsms[i], &d->hsms[i]->multisigPk);
  }

  Multisig_AggPks(multisigPks, NUM_HSMS, &aggPk);

  for (int i = 0; i < NUM_HSMS; i++) {
    HSM_MultisigSetAggPk(d->hsms[i], &aggPk);
  }

  long verifySec, verifyMicro, aggSec, aggMicro;
  double verifyTime, aggTime;
  struct timeval tStart, tVerify, tEnd;

  gettimeofday(&tStart, NULL);

  printf("Going to start log epoch verification\n");

//  Datacenter_LogEpochVerification(d, &d->hsms[0]->multisigPk, state);
  Datacenter_LogEpochVerification(d, &aggPk, state, sigs);

  Datacenter_free(d);

  d = Datacenter_new();
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  gettimeofday(&tVerify, NULL);

  Multisig_AggSigs(sigs, NUM_HSMS, &aggSig);
  for (int i = 0; i < NUM_HSMS; i++) {
      t[i] = thread(HSM_MultisigVerify, d->hsms[i], &aggSig, state->rootsTree->hash);
  }
  for (int i = 0; i < NUM_HSMS; i++) {
      t[i].join();
  }

  gettimeofday(&tEnd, NULL);

    verifySec = (tVerify.tv_sec - tStart.tv_sec);
    verifyMicro = (tVerify.tv_usec - tStart.tv_usec);
    verifyTime = verifySec + (verifyMicro / 1000000.0);
    aggSec = (tEnd.tv_sec - tStart.tv_sec);
    aggMicro = (tEnd.tv_usec - tStart.tv_usec);
    aggTime = aggSec + (aggMicro / 1000000.0);

    printf("------ Transition verification time: %f, %d sec, %d micros\n", verifyTime, verifySec, verifyMicro);
    printf("------ Signature aggregation and verification: %f, %d sec, %d micros\n", aggTime, aggSec, aggMicro);

  return 0;
}
