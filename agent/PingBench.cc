// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <iostream>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <math.h>

#include "datacenter.h"
#include "hsm.h"
#include "ibe.h"
#include "common.h"

#define NUM_ROUNDS 1000
#define NUM_ITERS 250

using namespace std;

int main(int argc, char *argv[]) {

  Datacenter *d = Datacenter_new();
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  long macMicrosArr[NUM_ROUNDS];
  double mean = 0.0;
  double stddev = 0.0;
  double sum = 0.0;
  long maxMicros = -1;
  long minMicros = -1;

  struct timeval t1, t2;
  uint8_t nonce[NONCE_LEN];
  uint8_t mac[SHA256_DIGEST_LENGTH];

  for (int i = 0; i < NUM_ROUNDS / NUM_ITERS; i++) {
      Datacenter *d = Datacenter_new();
      if (Datacenter_init(d) != OKAY) {
        printf("No device found. Exiting.\n");
        return 0;
      }
 
      for (int j = 0; j < NUM_ITERS; j++) {

        gettimeofday(&t1, NULL);
        HSM_Mac(d->hsms[0], d->hsms[0], nonce, mac);
        gettimeofday(&t2, NULL);

        printf("nonce: ");
        for (int i = 0; i < NONCE_LEN; i++) {
            printf("%x", nonce[i]);
        }
        printf("\n");

        printf("MAC: ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%x", mac[i]);
        }
        printf("\n");

        long macSeconds = (t2.tv_sec - t1.tv_sec);
        long macMicros = (t2.tv_usec - t1.tv_usec);
        double macTime = macSeconds + (macMicros / 1000000.0);
        //double saveTime = ((double) (t2 - t1)) / CLOCKS_PER_SEC;
        //double recoverTime = ((double) (t3 - t2)) / CLOCKS_PER_SEC;
        printf("**** MAC time: %f, %ld seconds, %ld microseconds\n", macTime, macSeconds, macMicros);
        if (macMicros < 0) {
            macMicros = (macSeconds * 1000000) + macMicros;
        }
        macMicrosArr[i * NUM_ITERS + j] = macMicros;
        mean += ((double)macMicros) / ((double)NUM_ROUNDS);
        printf("Current mean: %f\n", mean);
    
        if (maxMicros < 0 || maxMicros < macMicros) maxMicros = macMicros;
        if (minMicros < 0 || minMicros > macMicros) minMicros = macMicros;  
    }
    Datacenter_free(d);
    printf("Unplug and replug and then enter char to continue...\n");
    int ch = getchar();
    printf("... continuing\n");
    
  }

  for (int i = 0; i < NUM_ROUNDS; i++) {
    double diff = macMicrosArr[i] - mean;
    diff *= diff;
    sum += (diff / NUM_ROUNDS);
    printf("sum[%d] = %f, diff = %f, val = %ld\n", i, sum, diff, macMicrosArr[i]);
  }
  stddev = sqrt(sum);

  printf("Mean: %f micros\n", mean);
  printf("Standard deviation: %f\n", stddev);
  printf("Max latency: %ld micros\n", maxMicros);
  printf("Min latency: %ld micros\n", minMicros);


  Datacenter_free(d);

  return 0;
}
