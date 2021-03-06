#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <map>
#include <sys/time.h>

#include "datacenter.h"
#include "hsm.h"
#include "ibe.h"
#include "common.h"

/* Check that log inclusion proofs verify. */

using namespace std;

int main(int argc, char *argv[]) {

  int numHsms = 10;
  int hsmGroupSize = 10;
  int chunkSize = 1;

  Datacenter *d = Datacenter_new(numHsms, hsmGroupSize, chunkSize);
  if (Datacenter_init(d) != OKAY) {
    printf("No device found. Exiting.\n");
    return 0;
  }

  uint8_t logPk[COMPRESSED_PT_SZ];
  LogProof *p = LogProof_new();
  BIGNUM *msg = BN_new();

  Log_Init(d->hsms[0]->params);
  Log_GetPk(d->hsms[0]->params, logPk);

  for (int i = 0; i < numHsms; i++) {
    ElGamal_ciphertext *c = ElGamalCiphertext_new(d->hsms[i]->params); 
    uint8_t hsms[HSM_MAX_GROUP_SIZE];
    BIGNUM *msg = BN_new();
    BN_rand(msg, BN_num_bits(d->hsms[i]->params->order), 0, 0);
    HSM_ElGamalGetPk(d->hsms[i]);
    HSM_ElGamalEncrypt(d->hsms[i], msg, c);

    HSM_SetParams(d->hsms[i], numHsms, hsmGroupSize, chunkSize, logPk, 1, 1);
    Log_Prove(d->hsms[i]->params, p, c, hsms, hsmGroupSize);
    HSM_LogProof(d->hsms[i], c, hsms, p);    
  }  

  Datacenter_free(d);

  printf("Test completed. \n");

  return 0;
}
