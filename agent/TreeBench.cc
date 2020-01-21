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

  struct timeval s1, s2;

  gettimeofday(&s1, NULL);
  HSM_GetMpk(d->hsms[0]);
  gettimeofday(&s2, NULL);
  printf("*** Get mpk time: %ld micros\n", s2.tv_usec - s1.tv_usec);
  HSM_TestSetup(d->hsms[0]);
  
  struct timeval t1, t2, t3;

  HSM_Retrieve(d->hsms[0], 0);
  gettimeofday(&t1, NULL);
  HSM_Retrieve(d->hsms[0], 0);
  gettimeofday(&t2, NULL);
  HSM_Puncture(d->hsms[0], 0);
  gettimeofday(&t3, NULL);

  long retrieveSeconds = (t2.tv_sec - t1.tv_sec);
  long retrieveMicros = (t2.tv_usec - t1.tv_usec);
  long punctureSeconds = (t3.tv_sec - t2.tv_sec);
  long punctureMicros = (t3.tv_usec - t2.tv_usec);
  double retrieveTime = retrieveSeconds + (retrieveMicros / 1000000.0);
  double punctureTime = punctureSeconds + (punctureMicros / 1000000.0);
  //double saveTime = ((double) (t2 - t1)) / CLOCKS_PER_SEC;
  //double recoverTime = ((double) (t3 - t2)) / CLOCKS_PER_SEC;
  printf("**** Retrieve time: %f, %ld seconds, %ld microseconds\n", retrieveTime, retrieveSeconds, retrieveMicros);
  printf("**** Puncture time: %f, %ld seconds, %ld microseconds\n", punctureTime, punctureSeconds, punctureMicros);

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
