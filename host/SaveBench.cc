#include <iostream>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/rand.h>

#include "datacenter.h"
#include "hsm.h"
#include "ibe.h"
#include "common.h"

/* Measure time to generate a recovery ciphertext (does not interact with HSMs.) */

using namespace std;

int main(int argc, char *argv[]) {

  int numHsms = 10;
  int hsmGroupSize = 10;

  Datacenter *d = Datacenter_new(numHsms, hsmGroupSize);

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

  Datacenter_VirtualSetup(d);

  struct timeval t1, t2, t3, t4;
  gettimeofday(&t1, NULL);
  Datacenter_Save(d, params, saveKey, 0, pin, c);
  gettimeofday(&t2, NULL);

  uint8_t key[32];
  RAND_bytes(key, 32);
  uint8_t pt[32];
  memset(pt, 0xff, 32);
  uint8_t iv[32];
  uint8_t ct[32];

  gettimeofday(&t3, NULL);
  aesEncrypt(key, pt, 32, iv, ct);
  gettimeofday(&t4, NULL);


  long saveSeconds = (t2.tv_sec - t1.tv_sec);
  long saveMicros = (t2.tv_usec - t1.tv_usec);
  double saveTime = saveSeconds + (saveMicros / 1000000.0);
  long shortSeconds = (t4.tv_sec - t3.tv_sec);
  long shortMicros = (t4.tv_usec - t3.tv_usec);
  double shortTime = shortSeconds + (shortMicros / 1000000.0);
  printf("**** Save time: %f, %d seconds, %d microseconds\n", saveTime, saveSeconds, saveMicros);
  printf("**** Google/Apple save time: %f, %d seconds, %d microseconds\n", shortTime, shortSeconds, shortMicros);

  RecoveryCiphertext_free(c, hsmGroupSize);
  Datacenter_free(d);

  printf("Initialization completed. \n");

  return 0;
}
