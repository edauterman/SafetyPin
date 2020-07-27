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

  Datacenter *d = Datacenter_new();
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

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
  LogProof *logProofs[HSM_GROUP_SIZE];
  for (int i = 0; i < HSM_GROUP_SIZE; i++) {
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

  string filename = "../out/recovery_" + to_string(NUM_HSMS);
  FILE *f = fopen(filename.c_str(), "w+");
  string str1 = "save time: " + to_string(saveTime) + "\n";
  fputs(str1.c_str() , f);
  string str2 = "recover time: " + to_string(recoverTime) +  "\n";
  fputs(str2.c_str(), f);
  fclose(f);

  RecoveryCiphertext_free(c);
  Datacenter_free(d);

  printf("Initialization completed. \n");

  return 0;
}
