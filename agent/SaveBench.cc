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

  //Datacenter_SmallSetup(d);
  //Datacenter_TestSetup(d);

  Params *params = Params_new(); 


  BIGNUM *pin;
  BIGNUM *saveKey;
  BIGNUM *saveKeyTest;
  saveKey = BN_new();
  pin = BN_new();
  saveKeyTest = BN_new();
  BN_rand_range(saveKey, params->order);
  BN_rand_range(pin, params->order);
  RecoveryCiphertext *c = RecoveryCiphertext_new(params);

  Datacenter_VirtualSetup(d);

  struct timeval t1, t2, t3;
  //clock_t t1 = clock();
  gettimeofday(&t1, NULL);
  Datacenter_Save(d, params, saveKey, 0, pin, c);
  gettimeofday(&t2, NULL);
  //clock_t t2 = clock();

  long saveSeconds = (t2.tv_sec - t1.tv_sec);
  long saveMicros = (t2.tv_usec - t1.tv_usec);
  double saveTime = saveSeconds + (saveMicros / 1000000.0);
  //double saveTime = ((double) (t2 - t1)) / CLOCKS_PER_SEC;
  //double recoverTime = ((double) (t3 - t2)) / CLOCKS_PER_SEC;
  printf("**** Save time: %f, %d seconds, %d microseconds\n", saveTime, saveSeconds, saveMicros);

  string filename = "../out/save_" + to_string(NUM_HSMS);
  FILE *f = fopen(filename.c_str(), "w+");
  string str1 = "save time: " + to_string(saveTime) + "\n";
  fputs(str1.c_str() , f);
  fclose(f);

  RecoveryCiphertext_free(c);
  Datacenter_free(d);

  printf("Initialization completed. \n");

  return 0;
}
