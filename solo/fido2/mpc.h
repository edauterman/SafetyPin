#ifndef _MPC_H_
#define _MPC_H_

void MPC_SetMacKeys(uint8_t *macKeysIn);

void MPC_Step1(uint8_t *dShareBuf, uint8_t *eShareBuf, uint8_t dMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t eMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t *msg, uint8_t *recoveryPinShareBuf, uint8_t *hsms);
//void MPC_Step1(uint8_t *dShareBuf, uint8_t *eShareBuf, uint8_t *dMacs, uint8_t *eMacs, uint8_t *msg, uint8_t *recoveryPinShareBuf, uint8_t *hsms);
int MPC_Step2(uint8_t *resultShareBuf, uint8_t resultMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t *dBuf, uint8_t *eBuf, uint8_t dShareBufs[HSM_HONEST_MAJORITY][FIELD_ELEM_LEN], uint8_t eShareBufs[HSM_HONEST_MAJORITY][FIELD_ELEM_LEN], uint8_t dShareXBufs[HSM_HONEST_MAJORITY], uint8_t eShareXBufs[HSM_HONEST_MAJORITY], uint8_t dMacs[HSM_HONEST_MAJORITY][SHA256_DIGEST_LEN], uint8_t eMacs[HSM_HONEST_MAJORITY][SHA256_DIGEST_LEN], uint8_t *validHsms, uint8_t *allHsms);
//int MPC_Step2(uint8_t *resultShareBuf, uint8_t **resultMacs, uint8_t *dBuf, uint8_t *eBuf, uint8_t **dShareBufs, uint8_t **eShareBufs, uint8_t **dMacs, uint8_t **eMacs, uint8_t *validHsms, uint8_t *allHsms);
int MPC_Step3(uint8_t *returnMsg, uint8_t *resultBuf, uint8_t resultShareBufs[HSM_HONEST_MAJORITY][FIELD_ELEM_LEN], uint8_t resultSharesX[HSM_HONEST_MAJORITY], uint8_t **resultMacs[HSM_HONEST_MAJORITY][SHA256_DIGEST_LEN], uint8_t *validHsms);

#endif
