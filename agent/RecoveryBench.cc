// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <iostream>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

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
  //Datacenter_TestSetup(d);

  Params *params = Params_new(); 

  printf("made params\n");

  uint8_t pin[PIN_LEN];
  BIGNUM *saveKey;
  BIGNUM *saveKeyTest;
  saveKey = BN_new();
  saveKeyTest = BN_new();
  printf("before save key\n");
  BN_rand_range(saveKey, params->prime);
  printf("made savekey\n");
  RecoveryCiphertext *c = RecoveryCiphertext_new();

  printf("going to run test setup\n");

  Datacenter_TestSetup(d);

  struct timeval t1, t2, t3;
  //clock_t t1 = clock();
  gettimeofday(&t1, NULL);
  Datacenter_Save(d, params, saveKey, 0, pin, c);
  gettimeofday(&t2, NULL);
  //clock_t t2 = clock();
  Datacenter_Recover(d, params, saveKeyTest, 0, pin, c);
  gettimeofday(&t3, NULL);
  //clock_t t3 = clock();

  if (BN_cmp(saveKey, saveKeyTest) != 0) {
    printf("FAIL: expected to recover:\n %s\n but recovered:\n %s\n", BN_bn2hex(saveKey), BN_bn2hex(saveKeyTest));
  } else {
    printf("SUCCESS: recovered successfully.\n");
  }

  long saveSeconds = (t2.tv_sec - t1.tv_sec);
  long saveMicros = (t2.tv_usec - t1.tv_usec);
  long recoverSeconds = (t3.tv_sec - t2.tv_sec);
  long recoverMicros = (t3.tv_usec - t2.tv_usec);
  double saveTime = saveSeconds + (saveMicros / 1000000.0);
  double recoverTime = recoverSeconds + (recoverMicros / 1000000.0);
  //double saveTime = ((double) (t2 - t1)) / CLOCKS_PER_SEC;
  //double recoverTime = ((double) (t3 - t2)) / CLOCKS_PER_SEC;
  printf("**** Save time: %f, %d seconds, %d microseconds\n", saveTime, saveSeconds, saveMicros);
  printf("**** Recover time: %f, %d seconds, %d microseconds\n", recoverTime, recoverSeconds, recoverMicros);

  string filename = "../out/recovery_" + to_string(NUM_HSMS);
  FILE *f = fopen(filename.c_str(), "w+");
  string str1 = "save time: " + to_string(saveTime) + "\n";
  fputs(str1.c_str() , f);
  string str2 = "recover time: " + to_string(recoverTime) +  "\n";
  fputs(str2.c_str(), f);
  fclose(f);

  RecoveryCiphertext_free(c);
  Datacenter_free(d);

  printf("Initialization completed. \n");

  return 0;
}
