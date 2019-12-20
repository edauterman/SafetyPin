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
      
  gettimeofday(&t1, NULL);
  HSM_Setup(d->hsms[0]);
  gettimeofday(&t2, NULL);

  long setupSeconds = (t2.tv_sec - t1.tv_sec);
  long setupMicros = (t2.tv_usec - t1.tv_usec);
  double setupTime = setupSeconds + (setupMicros / 1000000.0);
  //double saveTime = ((double) (t2 - t1)) / CLOCKS_PER_SEC;
  //double recoverTime = ((double) (t3 - t2)) / CLOCKS_PER_SEC;
  printf("**** Setup time: %f, %ld seconds, %ld microseconds\n", setupTime, setupSeconds, setupMicros);

  string filename = "../out/tree_build";
  FILE *f = fopen(filename.c_str(), "w+");
  string str1 = "setup time: " + to_string(setupTime) + "\n";
  fputs(str1.c_str() , f); 
  fclose(f);

  Datacenter_free(d);

  return 0;
}
