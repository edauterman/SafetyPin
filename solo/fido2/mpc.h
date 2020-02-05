#ifndef _MPC_H_
#define _MPC_H_

void MPC_SetMacKeys(uint8_t *macKeysIn);
void MPC_SetParams(uint8_t groupSize, uint8_t thresholdSize);

void MPC_Step1_Commit(uint8_t *dCommit, uint8_t *eCommit, uint8_t *msgIn, uint8_t *recoveryPinShareBuf, uint8_t *aesCt, uint8_t *aesCtTag);
void MPC_Step1_Open(uint8_t *dShareBuf_out, uint8_t *eShareBuf_out, uint8_t *dOpening_out, uint8_t *eOpening_out, uint8_t dMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t eMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t dCommits[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t eCommits[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t *hsms);
int MPC_Step2_Commit(uint8_t *resultCommit, uint8_t *dBuf, uint8_t *eBuf, uint8_t dShareBufs[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t eShareBufs[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t dOpenings[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t eOpenings[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t dMacs[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t eMacs[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t *hsms);
int MPC_Step2_Open(uint8_t *resultShareBuf_out, uint8_t *resultOpening_out, uint8_t resultMacs[HSM_GROUP_SIZE][SHA256_DIGEST_LEN], uint8_t resultCommits[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t *hsms);
int MPC_Step3(uint8_t *returnMsg, uint8_t *resultBuf, uint8_t resultShareBufs[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t resultOpenings[HSM_THRESHOLD_SIZE][FIELD_ELEM_LEN], uint8_t resultMacs[HSM_THRESHOLD_SIZE][SHA256_DIGEST_LEN], uint8_t *hsms);

#endif
