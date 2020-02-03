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

#include "datacenter.h"
#include "hsm.h"
#include "ibe.h"
#include "common.h"

using namespace std;

int main(int argc, char *argv[]) {

  Datacenter *d = Datacenter_new();
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  struct timeval t1, t2;

  printf("size of puncture req: %d\n", sizeof(HSM_PUNCTURE_REQ));
  printf("size of puncture resp: %d\n", sizeof(HSM_PUNCTURE_RESP));

  gettimeofday(&t1, NULL);
  //HSM_LongMsg(d->hsms[0]);
  gettimeofday(&t2, NULL);

  printf("long message time: %ld sec, %d micros\n", t2.tv_sec - t1.tv_sec, t2.tv_usec - t1.tv_usec);

  HSM_MicroBench(d->hsms[0]);

  Datacenter_free(d);

  printf("Done with microbenchmarks. \n");

  return 0;
}
