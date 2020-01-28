#ifndef _MPC_H_
#define _MPC_H_

void MPC_SetMacKeys(uint8_t *macKeysIn);

void MPC_Step1(uint8_t *dShareBuf, uint8_t *eShareBuf, uint8_t dMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t eMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t *msg, uint8_t *recoveryPinShareBuf, uint8_t *hsms);
//void MPC_Step1(uint8_t *dShareBuf, uint8_t *eShareBuf, uint8_t *dMacs, uint8_t *eMacs, uint8_t *msg, uint8_t *recoveryPinShareBuf, uint8_t *hsms);
int MPC_Step2(uint8_t *resultShareBuf, uint8_t resultMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t *dBuf, uint8_t *eBuf, uint8_t dShareBufs[2 * HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t eShareBufs[2 * HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t dSharesX[2 * HSM_THRESHOLD_SIZE], uint8_t eSharesX[2 * HSM_THRESHOLD_SIZE], uint8_t dMacs[2 * HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t eMacs[2 * HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t *validHsms, uint8_t *allHsms);
//int MPC_Step2(uint8_t *resultShareBuf, uint8_t **resultMacs, uint8_t *dBuf, uint8_t *eBuf, uint8_t **dShareBufs, uint8_t **eShareBufs, uint8_t **dMacs, uint8_t **eMacs, uint8_t *validHsms, uint8_t *allHsms);
int MPC_Step3(uint8_t *returnMsg, uint8_t *resultBuf, uint8_t resultShareBufs[2 * HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t resultSharesX[2 * HSM_THRESHOLD_SIZE], uint8_t **resultMacs[2 * HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t *validHsms);

#endif
