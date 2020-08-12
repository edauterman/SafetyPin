#include <iostream>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/rand.h>

#include "baseline.h"
#include "datacenter.h"
#include "hsm.h"
#include "ibe.h"
#include "common.h"

/* Benchmark save/recover for baseline (ElGamal encrypt to HSM). */

using namespace std;

int main(int argc, char *argv[]) {

  int numHsms = 10;
  int hsmGroupSize = 10;

  Datacenter *d = Datacenter_new(numHsms, hsmGroupSize);
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  Params *params = Params_new(); 

  ElGamal_ciphertext *elGamalCt = ElGamalCiphertext_new(d->hsms[0]->params);
  uint8_t aesCt[SHA256_DIGEST_LENGTH + KEY_LEN];
  uint8_t pinHash[SHA256_DIGEST_LENGTH];
  uint8_t key[KEY_LEN];
  uint8_t keyOut[KEY_LEN];
  RAND_bytes(pinHash, SHA256_DIGEST_LENGTH);
  RAND_bytes(key, KEY_LEN);
  RAND_bytes(keyOut, KEY_LEN);

  Baseline_Init(d->hsms[0]);

  struct timeval t1, t2, t3;
  gettimeofday(&t1, NULL);
  Baseline_Save(d->hsms[0], elGamalCt, aesCt, pinHash, key);
  gettimeofday(&t2, NULL);
  Baseline_Recover(d->hsms[0], keyOut, elGamalCt, aesCt, pinHash);
  gettimeofday(&t3, NULL);

  if (memcmp(key, keyOut, KEY_LEN) != 0) {
    printf("FAIL: recovered incorrect key.\n");
  } else {
    printf("SUCCESS: recovered successfully.\n");
  }

  printf("key: ");
  for (int i = 0; i < KEY_LEN; i++) {
    printf("%02x", key[i]);
  }
  printf("\n");

  printf("key received: ");
  for (int i = 0; i < KEY_LEN; i++) {
    printf("%02x", keyOut[i]);
  }
  printf("\n");

  long saveSeconds = (t2.tv_sec - t1.tv_sec);
  long saveMicros = (t2.tv_usec - t1.tv_usec);
  long recoverSeconds = (t3.tv_sec - t2.tv_sec);
  long recoverMicros = (t3.tv_usec - t2.tv_usec);
  double saveTime = saveSeconds + (saveMicros / 1000000.0);
  double recoverTime = recoverSeconds + (recoverMicros / 1000000.0);
  printf("**** Save time: %f, %d seconds, %d microseconds\n", saveTime, saveSeconds, saveMicros);
  printf("**** Recover time: %f, %d seconds, %d microseconds\n", recoverTime, recoverSeconds, recoverMicros);

  Datacenter_free(d);

  printf("Initialization completed. \n");

  return 0;
}
