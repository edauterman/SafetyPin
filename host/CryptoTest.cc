// Copyright 2018 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

#include "hsm.h"
#include "elgamal.h"
#include "elgamal_shamir.h"
#include "params.h"
#include "ibe.h"
#include "common.h"
#include "multisig.h"
#include "merkle_tree.h"
#include "shamir.h"

using namespace std;

void IBETest() {
  printf("----- IBE TEST ----- \n");
  embedded_pairing_core_bigint_256_t msk;
  embedded_pairing_bls12_381_g2_t mpk;
  embedded_pairing_bls12_381_g1_t sk;
  uint8_t msg[IBE_MSG_LEN];
  uint8_t msg_test[IBE_MSG_LEN];
  uint8_t cBuf[IBE_CT_LEN];
  IBE_ciphertext *c = IBE_ciphertext_new(IBE_MSG_LEN);
  IBE_ciphertext *cTest = IBE_ciphertext_new(IBE_MSG_LEN);
  memset(msg, 0xff, IBE_MSG_LEN);

  IBE_Setup(&msk, &mpk);
  IBE_Extract(&msk, 1, &sk);
  IBE_Encrypt(&mpk, 1, msg, IBE_MSG_LEN, c);
  IBE_Decrypt(&sk, c, msg_test, IBE_MSG_LEN);

  IBE_MarshalCt(cBuf, IBE_MSG_LEN, c);
  IBE_UnmarshalCt(cBuf, IBE_MSG_LEN, cTest);
  IBE_Decrypt(&sk, cTest, msg_test, IBE_MSG_LEN);

  if (memcmp(msg, msg_test, IBE_MSG_LEN) != 0) {
    printf("Decryption did not return correct plaintext: ");
    for (int i = 0; i < IBE_MSG_LEN; i++) {
        printf("%x ", msg_test[i]);
    }
    printf("\n");
  } else {
    printf("Decryption successful.\n");
  }

  IBE_ciphertext_free(c);
}

void ShamirTest() {
    int rv = ERROR;
    int t = 2;
    int n = 6;
    BIGNUM *prime = NULL;
    BIGNUM *secret = NULL;
    BIGNUM *secret_test = NULL;
    ShamirShare *shares[n];
    ShamirShare *sharesOut[2 * t];
    uint8_t order[2 * t];
    Params *params;

    printf("----- SHAMIR SECRET SHARING TEST -----\n");

    CHECK_A (prime = BN_new());
    CHECK_A (secret = BN_new());
    CHECK_A (secret_test = BN_new());
    CHECK_A (params = Params_new());
    
    for (int i = 0; i < n; i++) {
        CHECK_A (shares[i] = ShamirShare_new());
    }

    BN_hex2bn(&prime, "CC71BAE525F36E3D3EB843232F9101BD");
//    BN_hex2bn(&prime, "EC35D1D9CD0BEC4A13186ED1DDFE0CF3");
    CHECK_C (BN_rand_range(secret, prime));

    CHECK_C (Shamir_CreateShares(t, n, secret, prime, shares, NULL));
    CHECK_C (Shamir_ValidateShares(t, n, shares, prime));
    CHECK_C (Shamir_ReconstructShares(t, n, shares, prime, secret_test));
    if (BN_cmp(secret, secret_test) != 0) {
        printf("Shamir secret sharing FAILED\n");
        printf("secret: %s\n", BN_bn2hex(secret));
        printf("reconstructed secret: %s\n", BN_bn2hex(secret_test));
    } else {
        printf("Shamir secret sharing successful: %s\n", BN_bn2hex(secret_test));
    }
    
    CHECK_C (Shamir_ReconstructSharesWithValidation(t, n, shares, prime, secret_test));
    //printf("before find valid shares\n");
    CHECK_C (Shamir_FindValidShares(t, n, shares, sharesOut, order, prime, secret_test));
    printf("after find valid shares\n");
    printf("order of valid shares: "); 
    for (int i = 0; i < 2 * t; i++) {
        printf("%d ", order[i]);
    }
    printf("\n");

    CHECK_C (Shamir_CreateShares(1, 2, secret, prime, shares, NULL));
    CHECK_C (Shamir_ValidateShares(t, n, shares, prime) == ERROR);

    if (BN_cmp(secret, secret_test) != 0) {
        printf("Shamir secret sharing FAILED\n");
        printf("secret: %s\n", BN_bn2hex(secret));
        printf("reconstructed secret: %s\n", BN_bn2hex(secret_test));
    } else {
        printf("Shamir secret sharing successful.\n");
    }

cleanup:
    if (rv == ERROR) printf("FAILED Shamir secret sharing tests\n");
    BN_free(prime);
    BN_free(secret);
    BN_free(secret_test);
    for (int i = 0; i < n; i++) {
        ShamirShare_free(shares[i]);
    }
}

void ElGamalTest() {
    printf("----- EL GAMAL TEST -----\n");
    Params *params = Params_new();
    BIGNUM *sk = BN_new();
    EC_POINT *pk = EC_POINT_new(params->group);
    ElGamal_ciphertext *c = ElGamalCiphertext_new(params);
    BIGNUM *msg = BN_new();
    BIGNUM *msgTest = BN_new();

    BN_rand_range(sk, params->order);
    BN_rand_range(msg, params->order);
    EC_POINT_mul(params->group, pk, sk, NULL, NULL, params->bn_ctx);

    ElGamal_Encrypt(params, msg, pk, NULL, NULL, c);
    ElGamal_Decrypt(params, msgTest, sk, c);

    printf("msg: %s\n", BN_bn2hex(msg));
    printf("msgTest: %s\n", BN_bn2hex(msgTest));
}    

void ElGamalShamirTest() {
    printf("----- EL GAMAL SHAMIR TEST ------ \n");
    Params *params = Params_new();
    int t = 3;
    int n = 10;
    uint8_t msg[32];
    uint8_t msgTest[32];
    BIGNUM *sks[n];
    EC_POINT *pks[n];
    ShamirShare *msgShares[n];
    LocationHidingCt *locationHidingCt;

    for (int i = 0; i < n; i++) {
        sks[i] = BN_new();
        pks[i] = EC_POINT_new(params->group);
        BN_rand_range(sks[i], params->order);
        EC_POINT_mul(params->group, pks[i], sks[i], NULL, NULL, params->bn_ctx);
        msgShares[i] = ShamirShare_new();
    }
    locationHidingCt = LocationHidingCt_new(params, n);

    memset(msg, 0xff, 32);

    ElGamalShamir_CreateShares(params, t, n, msg, pks, locationHidingCt, NULL);

    for (int i = 0; i < n; i++) {
        ElGamal_Decrypt(params, msgShares[i]->y, sks[i], locationHidingCt->shares[i]->ct);
        msgShares[i]->x = BN_dup(locationHidingCt->shares[i]->x);
    }

    ElGamalShamir_ReconstructShares(params, t, n, locationHidingCt, msgShares, msgTest);
    
    printf("msg: ");
    for (int i = 0; i < 32; i++) printf("%02x", msg[i]);
    printf("\n");
    printf("msgTest: ");
    for (int i = 0; i < 32; i++) printf("%02x", msgTest[i]);
    printf("\n");
    if (memcmp(msg, msgTest, 32) == 0) {
        printf("Reconstruction successful\n");
    }
}

void MultisigTest() {
    printf("----- MULTISIG TEST ------ \n");
    embedded_pairing_core_bigint_256_t sk[2];
    embedded_pairing_bls12_381_g2_t pk[2];
    embedded_pairing_bls12_381_g2_t aggPk;
    uint8_t msg[32];
    embedded_pairing_bls12_381_g1_t sig[2];
    embedded_pairing_bls12_381_g1_t aggSig;

    memset(msg, 0xaa, 32);
    Multisig_Setup(&sk[0], &pk[0]);
    Multisig_Sign(&sk[0], msg, 32, &sig[0]);
    if (Multisig_Verify(&pk[0], msg, 32, &sig[0])) {
        printf("Single signer multisig successfully verifies.\n");
    } else {
        printf("FAIL: Single signer multisig does not verify.\n");
    }
   
    Multisig_Setup(&sk[1], &pk[1]);
    Multisig_Sign(&sk[1], msg, 32, &sig[1]);
    if (Multisig_Verify(&pk[1], msg, 32, &sig[1])) {
        printf("Single signer multisig successfully verifies.\n");
    } else {
        printf("FAIL: Single signer multisig does not verify.\n");
    }
    
    Multisig_AggPks(pk, 2, &aggPk);
    Multisig_AggSigs(sig, 2, &aggSig);

    if (Multisig_Verify(&aggPk, msg, 32, &aggSig)) {
        printf("Multiple signer multisig successfully verifies.\n");
    } else {
        printf("FAIL: Multiple signer multisig does not verify.\n");
    }

}

void MerkleTreeTest() {
    printf("----- MERKLE TREE TEST ------ \n");
    uint64_t ids[32];
    uint8_t **values = (uint8_t **)malloc(32 * sizeof(uint8_t *));
    for (uint64_t i = 0; i < 32; i++) {
        ids[i] = i;
        values[i] = (uint8_t *)malloc(SHA256_DIGEST_LENGTH);
        memset(values[i], 0xaa, SHA256_DIGEST_LENGTH);
    }
    printf("going to create tree\n");
    Node *head = MerkleTree_CreateTree(ids, values, 32);
    printf("finished creating tree\n");
    MerkleProof *proof = MerkleTree_GetProof(head, 2);
    printf("Got proof\n");
    if (MerkleTree_VerifyProof(head, proof, values[1], 2) == OKAY) {
        printf("Merkle proof verifies.\n");
    } else {
        printf("FAIL: Merkle proof doesn't verify.\n");
    }
    uint8_t newValue[SHA256_DIGEST_LENGTH];
    memset(newValue, 0xaa, SHA256_DIGEST_LENGTH);
    MerkleTree_InsertLeaf(head, 32, newValue);
    MerkleTree_InsertLeaf(head, 33, newValue);
    MerkleTree_InsertLeaf(head, 34, newValue);
    proof = MerkleTree_GetProof(head, 1);
    printf("Got proof\n");
    if (MerkleTree_VerifyProof(head, proof, newValue, 1) == OKAY) {
        printf("Merkle proof verifies.\n");
    } else {
        printf("FAIL: Merkle proof doesn't verify.\n");
    }
    proof = MerkleTree_GetProof(head, 33);
    printf("Got proof\n");
    if (MerkleTree_VerifyProof(head, proof, newValue, 33) == OKAY) {
        printf("Merkle proof verifies.\n");
    } else {
        printf("FAIL: Merkle proof doesn't verify.\n");
    }
    proof = MerkleTree_GetEmptyProof(head, 256);
    printf("Got empty proof\n");
    if (MerkleTree_VerifyEmptyProof(head, proof, 256) == OKAY) {
        printf("Merkle proof verifies.\n");
    } else {
        printf("FAIL: Merkle proof doesn't verify.\n");
    }
}

int main(int argc, char *argv[]) {
  IBETest();
  ShamirTest();
  ElGamalTest();
  ElGamalShamirTest();
  MultisigTest();
  MerkleTreeTest();
  return 0;
}
