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

  for (int i = 0; i < NUM_HSMS; i++) {
//    HSM_GetMpk(d->hsms[i]);

    uint8_t msg[IBE_MSG_LEN];
    uint8_t msg_test[IBE_MSG_LEN];
    IBE_ciphertext *c[PUNC_ENC_REPL];
    for (int i = 0; i < PUNC_ENC_REPL; i++)  {
        c[i] = IBE_ciphertext_new(IBE_MSG_LEN);
    }
    memset(msg, 0xff, IBE_MSG_LEN);

    //HSM_Encrypt(d->hsms[i], 1, msg, IBE_MSG_LEN, c);
    //HSM_TestSetup(d->hsms[i]);
    //HSM_SmallSetup(d->hsms[i]);
//    HSM_Retrieve(d->hsms[i], 0);
//    HSM_Retrieve(d->hsms[i], 1);
//    HSM_Puncture(d->hsms[i], 0);
//    HSM_Retrieve(d->hsms[i], 1);

    HSM_Decrypt(d->hsms[i], 1, c, msg_test, IBE_MSG_LEN);

    if (memcmp(msg, msg_test, IBE_MSG_LEN) != 0) {
        printf("Decryption did not return correct plaintext: ");
        for (int j = 0; j < IBE_MSG_LEN; j++) {
            printf("%x ", msg_test[j]);
        }
        printf("\n");
    } else {
        printf("Decryption successful.\n");
    }
    for (int i = 0; i < PUNC_ENC_REPL; i++) {
        IBE_ciphertext_free(c[i]);
    }
  }  

  Datacenter_free(d);

  printf("Test completed. \n");

  return 0;
}
