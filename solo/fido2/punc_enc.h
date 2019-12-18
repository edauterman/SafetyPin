#ifndef _PUNC_ENC_H_
#define _PUNC_ENC_H

#include "hsm.h"

void PuncEnc_Init();
void PuncEnc_BuildSubTree(uint8_t leaves[NUM_SUB_LEAVES][LEAF_LEN], uint8_t cts[SUB_TREE_SIZE][CT_LEN]);
void PuncEnc_BuildSmallTree(uint8_t cts[SUB_TREE_SIZE][CT_LEN]);
void PuncEnc_TestSetup(uint8_t newMsk[KEY_LEN], uint8_t newHmacKey[KEY_LEN]);
void PuncEnc_FillLeaves(uint8_t leaves[NUM_SUB_LEAVES][LEAF_LEN]);
int PuncEnc_RetrieveLeaf(uint8_t cts[LEVELS][CT_LEN], uint16_t index, uint8_t leaf[CT_LEN]);
void PuncEnc_PunctureLeaf(uint8_t oldCts[KEY_LEVELS][CT_LEN], uint16_t index, uint8_t newCts[KEY_LEVELS][CT_LEN]);

#endif
