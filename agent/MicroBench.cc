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

/* Run microbenchmarks on HSM. Results printed using debug output when using HID. */

using namespace std;

int main(int argc, char *argv[]) {

  Datacenter *d = Datacenter_new();
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  HSM_MicroBench(d->hsms[0]);

  Datacenter_free(d);

  printf("Done with microbenchmarks. \n");

  return 0;
}
