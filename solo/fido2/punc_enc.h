#ifndef _PUNC_ENC_H_
#define _PUNC_ENC_H

#include "hsm.h"

void PuncEnc_BuildSubTree(uint8_t leaves[NUM_SUB_LEAVES][CT_LEN], uint8_t cts[SUB_TREE_SIZE][CT_LEN], uint8_t finalKey[KEY_LEN]);
void PuncEnc_FillLeaves(uint8_t leaves[NUM_SUB_LEAVES][CT_LEN], int start);
void PuncEnc_SetMsk(uint8_t newMsk[KEY_LEN]);
void PuncEnc_RetrieveLeaf(uint8_t cts[LEVELS][CT_LEN], uint16_t index, uint8_t leaf[CT_LEN]);
void PuncEnc_PunctureLeaf(uint8_t oldCts[KEY_LEVELS][CT_LEN], uint16_t index, uint8_t newCts[KEY_LEVELS][CT_LEN]);

#endif
