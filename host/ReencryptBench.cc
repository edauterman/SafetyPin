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
#include <thread>

using namespace std;

int main(int argc, char *argv[]) {

  int numHsms = 1;
  int hsmGroupSize = 1;
  int chunkSize = 1;

  Datacenter *d = Datacenter_new(numHsms, hsmGroupSize, chunkSize);
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  struct timeval t1, t2;

  gettimeofday(&t1, NULL);

  for (int i = 0; i < 16448; i++) {
      HSM_LongMsg(d->hsms[0]);
  }

  gettimeofday(&t2, NULL);

  long seconds = (t2.tv_sec - t1.tv_sec);
  long micros = (t2.tv_usec - t1.tv_usec);
  double time = seconds + (micros / 1000000.0);
  printf("**** Reencrypt time: %f, %ld seconds, %ld microseconds\n", time, seconds, micros);

  Datacenter_free(d);

  return 0;
}
