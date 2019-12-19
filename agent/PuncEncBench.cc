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

  HSM_GetMpk(d->hsms[0]);
  HSM_TestSetup(d->hsms[0]);
  
  struct timeval t1, t2, t3;
  uint8_t msg[IBE_MSG_LEN];
  uint8_t pin[PIN_LEN];
  memset(msg, 0xff, IBE_MSG_LEN);
  memset(pin, 0xff, PIN_LEN);
  IBE_ciphertext *cts[PUNC_ENC_REPL];
  for (int i = 0; i < PUNC_ENC_REPL; i++) {
    cts[i] = IBE_ciphertext_new(IBE_MSG_LEN);
  }
      
  gettimeofday(&t1, NULL);
  HSM_Encrypt(d->hsms[0], 0, msg, IBE_MSG_LEN, cts);
  gettimeofday(&t2, NULL);
  HSM_AuthDecrypt(d->hsms[0], 0, cts, msg, IBE_MSG_LEN, pin);
  gettimeofday(&t3, NULL);

  long encryptSeconds = (t2.tv_sec - t1.tv_sec);
  long encryptMicros = (t2.tv_usec - t1.tv_usec);
  long decryptSeconds = (t3.tv_sec - t2.tv_sec);
  long decryptMicros = (t3.tv_usec - t2.tv_usec);
  double encryptTime = encryptSeconds + (encryptMicros / 1000000.0);
  double decryptTime = decryptSeconds + (decryptMicros / 1000000.0);
  //double saveTime = ((double) (t2 - t1)) / CLOCKS_PER_SEC;
  //double recoverTime = ((double) (t3 - t2)) / CLOCKS_PER_SEC;
  printf("**** Encrypt time: %f, %ld seconds, %ld microseconds\n", encryptTime, encryptSeconds, encryptMicros);
  printf("**** Decrypt time: %f, %ld seconds, %ld microseconds\n", decryptTime, decryptSeconds, decryptMicros);

  string filename = "../out/punc_enc";
  FILE *f = fopen(filename.c_str(), "w+");
  string str1 = "encrypt time: " + to_string(encryptTime) + "\n";
  fputs(str1.c_str() , f); 
  string str2 = "decrypt time: " + to_string(decryptTime) +  "\n";
  fputs(str2.c_str(), f); 
  fclose(f);

  Datacenter_free(d);

  printf("Initialization completed. \n");

  return 0;
}
