#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <map>

#include "datacenter.h"
#include "hsm.h"
#include "ibe.h"
#include "common.h"

/* Test ElGamal encryption on HSM. */

using namespace std;

int main(int argc, char *argv[]) {

  Datacenter *d = Datacenter_new();
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  for (int i = 0; i < NUM_HSMS; i++) {
    BIGNUM *msg = BN_new();
    BIGNUM *msgTest = BN_new();
    ElGamal_ciphertext *c = ElGamalCiphertext_new(d->hsms[i]->params);
    
    BN_rand(msg, BN_num_bits(d->hsms[i]->params->order), 0, 0);

    HSM_ElGamalGetPk(d->hsms[i]);
    HSM_ElGamalEncrypt(d->hsms[i], msg, c);
    HSM_ElGamalDecrypt(d->hsms[i], msgTest, c);

    printf("msg: %s\n", BN_bn2hex(msg));
    printf("msgTest: %s\n", BN_bn2hex(msgTest));
  }  

  Datacenter_free(d);

  printf("Test completed. \n");

  return 0;
}
