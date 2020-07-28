#include <iostream>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include "datacenter.h"
#include "hsm.h"
#include "ibe.h"
#include "common.h"

/* Benchmark retrieving and puncturing leaf from puncturable encryption tree. */

using namespace std;

int main(int argc, char *argv[]) {

  Datacenter *d = Datacenter_new();
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  HSM_TestSetup(d->hsms[0]);
  
  struct timeval t1, t2, t3;

  gettimeofday(&t1, NULL);
  HSM_Retrieve(d->hsms[0], 0);
  gettimeofday(&t2, NULL);
  HSM_Puncture(d->hsms[0], 0);
  gettimeofday(&t3, NULL);


  struct timeval t4, t5, t6;
  BIGNUM *msg = BN_new();
  BIGNUM *msgTest = BN_new();
  BN_rand_range(msg, d->hsms[0]->params->order);
  ElGamal_ciphertext *cts[PUNC_ENC_REPL];
  for (int i = 0; i < PUNC_ENC_REPL; i++) {
    cts[i] = ElGamalCiphertext_new(d->hsms[0]->params);
  }
    
  gettimeofday(&t4, NULL);
  HSM_Encrypt(d->hsms[0], 0, msg, cts);
  gettimeofday(&t5, NULL);
  HSM_AuthDecrypt(d->hsms[0], 0, cts, msgTest);
  gettimeofday(&t6, NULL);


  long retrieveSeconds = (t2.tv_sec - t1.tv_sec);
  long retrieveMicros = (t2.tv_usec - t1.tv_usec);
  long punctureSeconds = (t3.tv_sec - t2.tv_sec);
  long punctureMicros = (t3.tv_usec - t2.tv_usec);
  double retrieveTime = retrieveSeconds + (retrieveMicros / 1000000.0);
  double punctureTime = punctureSeconds + (punctureMicros / 1000000.0);
  printf("**** Retrieve time: %f, %ld seconds, %ld microseconds\n", retrieveTime, retrieveSeconds, retrieveMicros);
  printf("**** Puncture time: %f, %ld seconds, %ld microseconds\n", punctureTime, punctureSeconds, punctureMicros);


  long encryptSeconds = (t5.tv_sec - t4.tv_sec);
  long encryptMicros = (t5.tv_usec - t4.tv_usec);
  long decryptSeconds = (t6.tv_sec - t5.tv_sec);
  long decryptMicros = (t6.tv_usec - t5.tv_usec);
  double encryptTime = encryptSeconds + (encryptMicros / 1000000.0);
  double decryptTime = decryptSeconds + (decryptMicros / 1000000.0);
  printf("**** Encrypt time: %f, %ld seconds, %ld microseconds\n", encryptTime, encryptSeconds, encryptMicros);
  printf("**** Decrypt time: %f, %ld seconds, %ld microseconds\n", decryptTime, decryptSeconds, decryptMicros);



  string filename = "../out/tree";
  FILE *f = fopen(filename.c_str(), "w+");
  string str1 = "retrieve time: " + to_string(retrieveTime) + "\n";
  fputs(str1.c_str() , f); 
  string str2 = "puncture time: " + to_string(punctureTime) +  "\n";
  fputs(str2.c_str(), f); 
  fclose(f);

  Datacenter_free(d);

  printf("Initialization completed. \n");

  return 0;
}
