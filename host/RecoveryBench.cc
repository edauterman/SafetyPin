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

/* Benchmark entire recovery process. */

using namespace std;

int main(int argc, char *argv[]) {
  
  int numHsms = 100;
  int hsmGroupSize = 100;

  if (argc >= 3) {
    numHsms = atoi(argv[1]);
    hsmGroupSize = atoi(argv[2]);
    printf("Number of HSMs: %d, HSM group size: %d\n", numHsms, hsmGroupSize);
  }
 

  Datacenter *d = Datacenter_new(numHsms, hsmGroupSize);
  printf("did datacenter new\n");
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  printf("init'd datacenter\n");
  Params *params = Params_new(); 


  BIGNUM *pin;
  BIGNUM *saveKey;
  BIGNUM *saveKeyTest;
  saveKey = BN_new();
  pin = BN_new();
  saveKeyTest = BN_new();
  BN_rand_range(saveKey, params->order);
  BN_rand_range(pin, params->order);
  RecoveryCiphertext *c = RecoveryCiphertext_new(params,  hsmGroupSize);
  LogProof **logProofs = (LogProof **)malloc(hsmGroupSize * sizeof(LogProof *));
  for (int i = 0; i < hsmGroupSize; i++) {
    logProofs[i] = LogProof_new();
  }

  Datacenter_TestSetup(d);

  struct timeval t1, t2, t3, t4;
  gettimeofday(&t1, NULL);
  Datacenter_Save(d, params, saveKey, 0, pin, c);
  gettimeofday(&t2, NULL);
  Datacenter_GenerateLogProofs(d, params, logProofs, pin, c);
  gettimeofday(&t3, NULL);
  Datacenter_Recover(d, params, saveKeyTest, 0, pin, c, logProofs);
  gettimeofday(&t4, NULL);

  if (BN_cmp(saveKey, saveKeyTest) != 0) {
    printf("FAIL: expected to recover:\n %s\n but recovered:\n %s\n", BN_bn2hex(saveKey), BN_bn2hex(saveKeyTest));
  } else {
    printf("SUCCESS: recovered successfully.\n");
  }

  long saveSeconds = (t2.tv_sec - t1.tv_sec);
  long saveMicros = (t2.tv_usec - t1.tv_usec);
  long recoverSeconds = (t4.tv_sec - t3.tv_sec);
  long recoverMicros = (t4.tv_usec - t3.tv_usec);
  double saveTime = saveSeconds + (saveMicros / 1000000.0);
  double recoverTime = recoverSeconds + (recoverMicros / 1000000.0);
  printf("**** Save time: %f, %d seconds, %d microseconds\n", saveTime, saveSeconds, saveMicros);
  printf("**** Recover time: %f, %d seconds, %d microseconds\n", recoverTime, recoverSeconds, recoverMicros);

  RecoveryCiphertext_free(c, hsmGroupSize);
  Datacenter_free(d);

  printf("Initialization completed. \n");

  return 0;
}
