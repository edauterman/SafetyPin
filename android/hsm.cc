#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <map>
#include <mutex>

#include <iostream>
#include <iomanip>

#ifdef __OS_WIN
#include <winsock2.h> // ntohl, htonl
#else
#include <arpa/inet.h> // ntohl, htonl
#endif

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#include "bls12_381/bls12_381.h"

#include "hsm.h"
#include "common.h"
#include "elgamal.h"
#include "hsm.h"
#include "ibe.h"
#include "params.h"
#include "punc_enc.h"

#define EXPECTED_RET_VAL 0x9000

using namespace std;

static bool isSmall;

HSM *HSM_new() {
    int rv = ERROR;
    HSM *h = NULL;

    CHECK_A (h = (HSM *)malloc(sizeof(HSM)));
    CHECK_A (h->params = Params_new());
    CHECK_A (h->elGamalPk = EC_POINT_new(h->params->group));

cleanup:
    return h;
}

void HSM_free(HSM *h) {
    Params_free(h->params);
    free(h);
}

int HSM_Encrypt(HSM *h, uint32_t tag, uint8_t *msg, int msgLen, IBE_ciphertext *c[PUNC_ENC_REPL]) {
    int rv;
    uint32_t indexes[PUNC_ENC_REPL];

    CHECK_C (PuncEnc_GetIndexesForTag(h->params, tag, indexes));

    for (int i = 0; i < PUNC_ENC_REPL; i++)  {
        IBE_Encrypt(&h->mpk, &h->mpkPrepared, indexes[i], msg, msgLen, c[i]);
    }    
cleanup:
    return rv;
}

int HSM_ElGamalEncrypt(HSM *h, EC_POINT *msg, ElGamal_ciphertext *c) {
    int rv;
    CHECK_C (ElGamal_Encrypt(h->params, msg, h->elGamalPk, c));

cleanup:
    if (rv == ERROR) printf("ERROR IN ENCRYPT\n");
    return rv;
}

