#ifndef __HSM_H_INCLUDED__
#define __HSM_H_INCLUDED__

#include <openssl/sha.h>

#include "ibe.h"
#include "bls12_381/bls12_381.h"
#include "params.h"
#include "elgamal.h"
#include "shamir.h"

#ifdef __cplusplus
extern "C" {
#endif

//#define HID

#define NUM_HSMS 1
#define HSM_GROUP_SIZE 3
//#define HSM_GROUP_SIZE 5
#define HSM_THRESHOLD_SIZE 1

//#define HSM_MAX_GROUP_SIZE 3
//#define HSM_MAX_GROUP_SIZE 6
#define HSM_MAX_GROUP_SIZE 100
//#define HSM_MAX_THRESHOLD_SIZE 1 
//#define HSM_MAX_THRESHOLD_SIZE 2
#define HSM_MAX_THRESHOLD_SIZE 34

#define KEY_LEN 32
#define LEAF_LEN (2 * KEY_LEN)
#define CT_LEN (2 * KEY_LEN + 32)

#define COMPRESSED_PT_SZ 33
#define FIELD_ELEM_LEN 32
#define ELGAMAL_CT_LEN (2 * COMPRESSED_PT_SZ)
#define ELGAMAL_PT_LEN COMPRESSED_PT_SZ
#define ELGAMAL_PK_LEN COMPRESSED_PT_SZ

#define PUNC_ENC_REPL 80
//#define PUNC_ENC_REPL 1
#define NUM_ATTEMPTS 1

#define AES_CT_LEN ((3 * FIELD_ELEM_LEN) + (3 * NUM_ATTEMPTS * FIELD_ELEM_LEN))

#define RESPONSE_BUFFER_SIZE 4096

#define NUM_LEAVES 524288
//#define NUM_LEAVES 16384
//#define NUM_LEAVES NUM_SUB_LEAVES
//#define NUM_LEAVES 256
#define LEVELS 20 // log2(NUM_LEAVES) + 1
//#define LEVELS 15 // log2(NUM_LEAVES) + 1
#define KEY_LEVELS (LEVELS - 1) // log2(NUM_LEAVES) + 1
#define SUB_TREE_LEVELS 5
//#define LEVELS 16 // log2(NUM_LEAVES)

#define SUB_TREE_SIZE ((RESPONSE_BUFFER_SIZE / (4 * KEY_LEN)) - 1)
#define TREE_SIZE (NUM_LEAVES * 2 - 1)
#define NUM_SUB_LEAVES ((SUB_TREE_SIZE + 1) / 2)
#define NUM_INTERMEDIATE_KEYS (NUM_SUB_LEAVES * 2)

#define HSM_SETUP           0x70
#define HSM_RETRIEVE        0x71
#define HSM_PUNCTURE        0x72
#define HSM_DECRYPT         0x73
#define HSM_MPK             0x74
#define HSM_SMALL_SETUP     0x75
#define HSM_AUTH_DECRYPT    0x76
#define HSM_TEST_SETUP      0x77
#define HSM_MICROBENCH      0x78
#define HSM_LONGMSG         0x79
#define HSM_MAC             0x7a
#define HSM_GET_NONCE       0x7b
#define HSM_RET_MAC         0x7c
#define HSM_RESET           0x7d
#define HSM_ELGAMAL_PK      0x7e
#define HSM_ELGAMAL_DECRYPT 0x7f
#define HSM_AUTH_MPC_DECRYPT_1_COMMIT   0x80
#define HSM_AUTH_MPC_DECRYPT_1_OPEN     0x81
#define HSM_AUTH_MPC_DECRYPT_2_COMMIT   0x82
#define HSM_AUTH_MPC_DECRYPT_2_OPEN     0x83
#define HSM_AUTH_MPC_DECRYPT_3          0x84
#define HSM_SET_MAC_KEYS                0x85
#define HSM_SET_PARAMS                  0x86
#define HSM_LOG_PROOF                   0x87
#define HSM_BASELINE                    0x88

#define LEVEL_0 0
#define LEVEL_1 1
#define LEVEL_2 2
#define LEVEL_3 3
#define LEVEL_DONE -1

#define LEVEL_1_OFFSET ((524288 + 262144 + 131072 + 65536 + 32768) * CT_LEN)
#define LEVEL_2_OFFSET (LEVEL_1_OFFSET + ((16384 + 8192 + 4096 + 2048 + 1024) * CT_LEN))
#define LEVEL_3_OFFSET (LEVEL_1_OFFSET + LEVEL_2_OFFSET +  ((512 + 256 + 128 + 64 + 32) * CT_LEN))
#define LEVEL_1_NUM_LEAVES 16384 
#define LEVEL_2_NUM_LEAVES 512
//#define LEVEL_1_NUM_LEAVES 1024 
#define LEVEL_3_NUM_LEAVES 16
//#define LEVEL_2_NUM_LEAVES 32

#define NONCE_LEN 16 

typedef struct {
    Params *params;
    embedded_pairing_bls12_381_g2_t mpk;
    embedded_pairing_bls12_381_g2prepared_t mpkPrepared;
    EC_POINT *elGamalPk;
    uint8_t id;
} HSM;

HSM *HSM_new();
void HSM_free(HSM *h);

int HSM_Encrypt(HSM *h, uint32_t tag, uint8_t *msg, int msgLen, IBE_ciphertext *c[PUNC_ENC_REPL]);
int HSM_ElGamalEncrypt(HSM *h, EC_POINT *msg, ElGamal_ciphertext *c);
#ifdef __cplusplus
}
#endif

#endif  // __DET2F_H_INCLUDED__
