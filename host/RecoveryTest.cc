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

  int numHsms = 10;
  int hsmGroupSize = 10;

  Datacenter *d = Datacenter_new(numHsms, hsmGroupSize);
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  //Datacenter_SmallSetup(d);
  Datacenter_TestSetup(d);

  Params *params = Params_new(); 

  BIGNUM *pin;
  BIGNUM *saveKey;
  BIGNUM *saveKeyTest;
  saveKey = BN_new();
  pin = BN_new();
  saveKeyTest = BN_new();
  BN_rand_range(saveKey, params->order);
  BN_rand_range(pin, params->order);
  RecoveryCiphertext *c = RecoveryCiphertext_new(params, hsmGroupSize);
  LogProof **logProofs = (LogProof **)malloc(hsmGroupSize * sizeof(LogProof *));
  for (int i = 0; i < hsmGroupSize; i++) {
    logProofs[i] = LogProof_new();
  }

  Datacenter_Save(d, params, saveKey, 0, pin, c);
  Datacenter_GenerateLogProofs(d, params, logProofs, pin, c);
  Datacenter_Recover(d, params, saveKeyTest, 0, pin, c, logProofs);

  if (BN_cmp(saveKey, saveKeyTest) != 0) {
    printf("FAIL: expected to recover:\n %s\n but recovered:\n %s\n", BN_bn2hex(saveKey), BN_bn2hex(saveKeyTest));
  } else {
    printf("SUCCESS: recovered successfully.\n");
  }

  RecoveryCiphertext_free(c, hsmGroupSize);
  Datacenter_free(d);

  printf("Initialization completed. \n");

  return 0;
}
