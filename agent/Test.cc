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

#include "agent.h"
#include "ibe.h"
#include "common.h"

using namespace std;

int main(int argc, char *argv[]) {

  Agent a;
  if (Agent_init(&a) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  for (int hsm = 0; hsm < NUM_HSMS; hsm++) {
    Agent_GetMpk(&a, hsm);
    Agent_Setup(&a, hsm);
    Agent_Retrieve(&a, 0, hsm);
    Agent_Retrieve(&a, 1, hsm);
    Agent_Puncture(&a, 0, hsm);
    Agent_Retrieve(&a, 1, hsm);

    uint8_t msg[IBE_MSG_LEN];
    uint8_t msg_test[IBE_MSG_LEN];
    IBE_ciphertext c;
    memset(msg, 0xff, IBE_MSG_LEN);
    Agent_Encrypt(&a, 1, msg, &c, hsm);
    Agent_Decrypt(&a, 1, &c, msg_test, hsm);

    if (memcmp(msg, msg_test, IBE_MSG_LEN) != 0) {
        printf("Decryption did not return correct plaintext: ");
        for (int i = 0; i < IBE_MSG_LEN; i++) {
            printf("%x ", msg_test[i]);
        }
        printf("\n");
    } else {
        printf("Decryption successful.\n");
    }
  }

  Agent_destroy(&a);

  printf("Initialization completed. \n");

  return 0;
}
