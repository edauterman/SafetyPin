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

  embedded_pairing_core_bigint_256_t msk;
  embedded_pairing_bls12_381_g2_t mpk;
  embedded_pairing_bls12_381_g1_t sk;
  uint8_t msg[IBE_MSG_LEN];
  uint8_t msg_test[IBE_MSG_LEN];
  IBE_ciphertext c;
  memset(msg, 0xff, IBE_MSG_LEN);
  
  IBE_Setup(&msk, &mpk);
  IBE_Extract(&msk, 1, &sk);
  IBE_Encrypt(&mpk, 1, msg, &c);
  IBE_Decrypt(&sk, &c, msg_test);

  if (memcmp(msg, msg_test, IBE_MSG_LEN) != 0) {
    printf("Decryption did not return correct plaintext: ");
    for (int i = 0; i < IBE_MSG_LEN; i++) {
        printf("%x ", msg_test[i]);
    }
    printf("\n");
  } else {
    printf("Decryption successful.\n");
  }

  return 0;
}
