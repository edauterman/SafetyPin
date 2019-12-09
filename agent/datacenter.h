#ifndef _DATACENTER_H
#define _DATACENTER_H

#include "hsm.h"

#define NUM_HSMS 1

typedef struct {
    HSM *hsms[NUM_HSMS];
} Datacenter;

Datacenter *Datacenter_new();
void Datacenter_free(Datacenter *d);

int Datacenter_init(Datacenter *d);
void Datacenter_destroy(Datacenter *d);

#endif
