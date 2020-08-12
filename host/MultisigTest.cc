#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <map>
#include <thread>

#include "datacenter.h"
#include "hsm.h"
#include "ibe.h"
#include "common.h"

using namespace std;

/* Check multisignature functionality on HSM. */

int main(int argc, char *argv[]) {

  int numHsms = 1;
  int hsmGroupSize = 1;

  Datacenter *d = Datacenter_new(numHsms, hsmGroupSize);
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  for (int i = 0; i < numHsms; i++) {

    uint8_t msg[SHA256_DIGEST_LENGTH];
    embedded_pairing_bls12_381_g1_t sig;
    memset(msg, 0xaa, SHA256_DIGEST_LENGTH);

    HSM_MultisigGetPk(d->hsms[i]);
    HSM_MultisigSetAggPk(d->hsms[i], &d->hsms[i]->multisigPk);
    HSM_MultisigSign(d->hsms[i], &sig, msg);
    HSM_MultisigVerify(d->hsms[i], &sig, msg);
  }  

  Datacenter_free(d);

  printf("Test completed. \n");

  return 0;
}
