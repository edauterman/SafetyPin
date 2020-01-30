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
#include <thread>

#include "datacenter.h"
#include "hsm.h"
#include "ibe.h"
#include "common.h"

#define NUM_RECOVERIES 10

using namespace std;

int main(int argc, char *argv[]) {

  Datacenter *d = Datacenter_new();
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  //Datacenter_SmallSetup(d);
  //Datacenter_TestSetup(d);

  Params *params[NUM_RECOVERIES];
  BIGNUM *pin[NUM_RECOVERIES];
  BIGNUM *saveKey[NUM_RECOVERIES];
  BIGNUM *saveKeyTest[NUM_RECOVERIES];
  thread t[NUM_RECOVERIES];
  RecoveryCiphertext *c[NUM_RECOVERIES];
  
  for (int i = 0; i < NUM_RECOVERIES; i++) {
    params[i] = Params_new();
    saveKey[i] = BN_new();
    pin[i] = BN_new();
    saveKeyTest[i] = BN_new();
    BN_rand_range(saveKey[i], params[i]->order);
    BN_rand_range(pin[i], params[i]->order);
    c[i] = RecoveryCiphertext_new(params[i]);
  }

  Datacenter_TestSetup(d);

  struct timeval t1, t2;
  //clock_t t1 = clock();
  for (int i = 0; i < NUM_RECOVERIES; i++) {
    Datacenter_Save(d, params[i], saveKey[i], i * HSM_GROUP_SIZE, pin[i], c[i]);
  }
  printf("Created all ciphertexts\n");
  //clock_t t2 = clock();
  gettimeofday(&t1, NULL);
  for (int i = 0; i < NUM_RECOVERIES; i++) {
    t[i] = thread(Datacenter_Recover, d, params[i], saveKeyTest[i], i * HSM_GROUP_SIZE, pin[i], c[i]);
    printf("Started %d\n", i);
  }
  for (int i = 0; i < NUM_RECOVERIES; i++) {
    t[i].join();
    printf("Finished %d\n", i);
  }
  gettimeofday(&t2, NULL);
  //clock_t t3 = clock();

  for (int i = 0; i < NUM_RECOVERIES; i++) {
    if (BN_cmp(saveKey[i], saveKeyTest[i]) != 0) {
        printf("FAIL: expected to recover:\n %s\n but recovered:\n %s\n", BN_bn2hex(saveKey[i]), BN_bn2hex(saveKeyTest[i]));
    } else {
        printf("SUCCESS: recovered successfully.\n");
    }
  }

  long recoverSeconds = (t2.tv_sec - t1.tv_sec);
  long recoverMicros = (t2.tv_usec - t1.tv_usec);
  double recoverTime = recoverSeconds + (recoverMicros / 1000000.0);
  //double saveTime = ((double) (t2 - t1)) / CLOCKS_PER_SEC;
  //double recoverTime = ((double) (t3 - t2)) / CLOCKS_PER_SEC;
  printf("**** Time for %d recoveries: %f, %d seconds, %d microseconds\n", NUM_RECOVERIES, recoverTime, recoverSeconds, recoverMicros);

  /*string filename = "../out/recovery_" + to_string(NUM_HSMS);
  FILE *f = fopen(filename.c_str(), "w+");
  string str1 = "save time: " + to_string(saveTime) + "\n";
  fputs(str1.c_str() , f);
  string str2 = "recover time: " + to_string(recoverTime) +  "\n";
  fputs(str2.c_str(), f);
  fclose(f);*/

  Datacenter_free(d);

  printf("Initialization completed. \n");

  return 0;
}
