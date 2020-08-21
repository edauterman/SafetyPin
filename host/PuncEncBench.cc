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

/* Measure time to encrypt and decrypt using puncturable encryption scheme. */

using namespace std;

int main(int argc, char *argv[]) {

  int numHsms = 100;
  int hsmGroupSize = 1;
  int chunkSize = 1;
  int hsmNum = 0;

  if (argc >= 2) {
    hsmNum = atoi(argv[1]);
    printf("HSM #%d\n", hsmNum);
  }

  Datacenter *d = Datacenter_new(numHsms, hsmGroupSize, chunkSize);
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  Datacenter_TestSetup(d);

  struct timeval startFull, endFull, startOnlySymKey, endOnlySymKey, startOnlyIO, endOnlyIO;
  BIGNUM *msg = BN_new();
  BIGNUM *msgTest = BN_new();
  uint8_t logPk[COMPRESSED_PT_SZ];
  BN_rand_range(msg, d->hsms[0]->params->order);
  ElGamal_ciphertext *cts[PUNC_ENC_REPL];
  for (int i = 0; i < PUNC_ENC_REPL; i++) {
    cts[i] = ElGamalCiphertext_new(d->hsms[0]->params);
  }

  Log_GetPk(d->hsms[hsmNum]->params, logPk);

  HSM_SetParams(d->hsms[hsmNum], d->hsmGroupSize, d->hsmThresholdSize, d->chunkSize, logPk, d->puncMeasureWithPubKey, d->puncMeasureWithSymKey);
  printf("going to start encrypt\n");  
  HSM_Encrypt(d->hsms[hsmNum], 1, msg, cts);
  printf("finished encrypt, going to auth decrypt\n");
  gettimeofday(&startFull, NULL);
  HSM_AuthDecrypt(d->hsms[hsmNum], 1, cts, msgTest);
  gettimeofday(&endFull, NULL);
  printf("finished auth decrypt\n");

  Datacenter_SetPuncMeasureParams(d, 0, 1);
  HSM_SetParams(d->hsms[hsmNum], d->hsmGroupSize, d->hsmThresholdSize, d->chunkSize, logPk, d->puncMeasureWithPubKey, d->puncMeasureWithSymKey);
  printf("going to start encrypt\n");  
  HSM_Encrypt(d->hsms[hsmNum], 2, msg, cts);
  printf("finished encrypt, going to auth decrypt\n");
  gettimeofday(&startOnlySymKey, NULL);
  HSM_AuthDecrypt(d->hsms[hsmNum], 2, cts, msgTest);
  gettimeofday(&endOnlySymKey, NULL);
  printf("finished auth decrypt\n");

  Datacenter_SetPuncMeasureParams(d, 0, 0);
  HSM_SetParams(d->hsms[hsmNum], d->hsmGroupSize, d->hsmThresholdSize, d->chunkSize, logPk, d->puncMeasureWithPubKey, d->puncMeasureWithSymKey);
  printf("going to start encrypt\n");  
  HSM_Encrypt(d->hsms[hsmNum], 0, msg, cts);
  printf("finished encrypt, going to auth decrypt\n");
  gettimeofday(&startOnlyIO, NULL);
  HSM_AuthDecrypt(d->hsms[hsmNum], 0, cts, msgTest);
  gettimeofday(&endOnlyIO, NULL);
  printf("finished auth decrypt\n");


  long fullSeconds = (endFull.tv_sec - startFull.tv_sec);
  long fullMicros = (endFull.tv_usec - startFull.tv_usec);
  long onlySymKeySeconds = (endOnlySymKey.tv_sec - startOnlySymKey.tv_sec);
  long onlySymKeyMicros = (endOnlySymKey.tv_usec - startOnlySymKey.tv_usec);
  long onlyIOSeconds = (endOnlyIO.tv_sec - startOnlyIO.tv_sec);
  long onlyIOMicros = (endOnlyIO.tv_usec - startOnlyIO.tv_usec);
  double fullTime = fullSeconds + (fullMicros / 1000000.0);
  double onlySymKeyTime = onlySymKeySeconds + (onlySymKeyMicros / 1000000.0);
  double onlyIOTime = onlyIOSeconds + (onlyIOMicros / 1000000.0);
  
  double pubKeyOpsTime = fullTime - onlySymKeyTime;
  double symKeyOpsTime = onlySymKeyTime - onlyIOTime;

  printf("**** Public key ops time: %f sec\n", pubKeyOpsTime);
  printf("**** Symmetric key ops time: %f sec\n", symKeyOpsTime);
  printf("**** IO time: %f sec\n", onlyIOTime);
  printf("**** Full time: %f sec\n", fullTime);

  Datacenter_free(d);

  printf("Initialization completed. \n");

  return 0;
}
