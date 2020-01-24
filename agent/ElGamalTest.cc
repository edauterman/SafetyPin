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
    //HSM_GetMpk(d->hsms[i]);

    BIGNUM *x = BN_new();
    EC_POINT *msg = EC_POINT_new(d->hsms[i]->params->group);
    EC_POINT *msgTest = EC_POINT_new(d->hsms[i]->params->group);
    ElGamal_ciphertext *c = ElGamalCiphertext_new(d->hsms[i]->params);
    
    BN_rand(x, BN_num_bits(d->hsms[i]->params->order), 0, 0);
    EC_POINT_mul(d->hsms[i]->params->group, msg, x, NULL, NULL, d->hsms[i]->params->bn_ctx);
    printf("encrypted message: %s\n", EC_POINT_point2hex(d->hsms[i]->params->group, msg, POINT_CONVERSION_UNCOMPRESSED, d->hsms[i]->params->bn_ctx));

    HSM_ElGamalGetPk(d->hsms[i]);
    HSM_ElGamalEncrypt(d->hsms[i], msg, c);
    HSM_ElGamalDecrypt(d->hsms[i], msgTest, c);

    printf("encrypted message: %s\n", EC_POINT_point2hex(d->hsms[i]->params->group, msg, POINT_CONVERSION_UNCOMPRESSED, d->hsms[i]->params->bn_ctx));
    printf("decrypted message: %s\n", EC_POINT_point2hex(d->hsms[i]->params->group, msgTest, POINT_CONVERSION_UNCOMPRESSED, d->hsms[i]->params->bn_ctx));
  }  

  Datacenter_free(d);

  printf("Test completed. \n");

  return 0;
}
