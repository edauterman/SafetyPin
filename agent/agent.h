#ifndef _AGENT_H
#define _AGENT_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <map>

#include "bls12_381/bls12_381.h"
#include "ibe.h"
#include "hsm.h"
#include "params.h"
#include "u2f.h"

#define NUM_HSMS 1

using namespace std;

typedef struct {
    struct U2Fob *device;
    uint8_t cts[SUB_TREE_SIZE][CT_LEN];
    embedded_pairing_bls12_381_g2_t mpk;
} HSM;

typedef struct {
  /* Representation of fob used for HID transport. */
  HSM hsms[NUM_HSMS];
} Agent;

int Agent_init(Agent *a);
void Agent_destroy(Agent *a);

int Agent_GetMpk(Agent *a, int hsmID);
int Agent_Setup(Agent *a, int hsmID);
int Agent_Retrieve(Agent *a, uint16_t index, int hsmID);
int Agent_Puncture(Agent *a, uint16_t index,  int hsmID);
int Agent_Encrypt(Agent *a, uint16_t index, uint8_t msg[IBE_MSG_LEN], IBE_ciphertext *c, int hsmID);
int Agent_Decrypt(Agent *a, uint16_t index, IBE_ciphertext *c, uint8_t msg[IBE_MSG_LEN], int hsmID);

#endif

