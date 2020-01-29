#ifndef _uECC_H_
#define _uECC_H_

#include "../crypto/micro-ecc/uECC_vli.h"

typedef uECC_word_t fieldElem[8];
typedef uECC_word_t ecPoint[16];

void uECC_setZero(fieldElem vli);
void uECC_setOne(fieldElem vli);
void uECC_setWord(fieldElem vli, uECC_word_t word);

/* Constant-time comparison function - secure way to compare long integers */
/* Returns one if left == right, zero otherwise */
uECC_word_t uECC_equal(const fieldElem left,
                        const fieldElem right);

/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
void uECC_modAdd(uECC_word_t *result,
                     const fieldElem left,
                     const fieldElem right);

/* Computes result = (left - right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
void uECC_modSub(uECC_word_t *result,
                     const fieldElem left,
                     const fieldElem right);

/* Computes result = (left * right) % mod.
   Currently only designed to work for mod == curve->p or curve_n. */
void uECC_modMult(fieldElem result,
                    const fieldElem left,
                    const fieldElem right);

void uECC_modNeg(fieldElem result,
                     const fieldElem input);

/* Computes result = (1 / input) % mod.*/
void uECC_modInv(fieldElem result,
                    const uECC_word_t *input);

/* Converts an integer in uECC native format to big-endian bytes. */
void uECC_fieldElemToBytes(uint8_t *bytes, const fieldElem native);
/* Converts big-endian bytes to an integer in uECC native format. */
void uECC_bytesToFieldElem(fieldElem native, const uint8_t *bytes);
/* Converts an integer in uECC native format to big-endian bytes. */
void uECC_pointToBytesUncompressed(uint8_t *bytes, const ecPoint native);
/* Converts big-endian bytes to an integer in uECC native format. */
void uECC_bytesToPointUncompressed(ecPoint native, const uint8_t *bytes);
/* Converts an integer in uECC native format to big-endian bytes. */
void uECC_pointToBytesCompressed(uint8_t *bytes, const ecPoint native);
/* Converts big-endian bytes to an integer in uECC native format. */
void uECC_bytesToPointCompressed(ecPoint native, const uint8_t *bytes);

/* Multiplies a point by a scalar. Points are represented by the X coordinate followed by
   the Y coordinate in the same array, both coordinates are curve->num_words long. Note
   that scalar must be curve->num_n_words long (NOT curve->num_words). */
void uECC_pointMult(ecPoint result,
                     const ecPoint point,
                     const fieldElem scalar);

void uECC_basePointMult(ecPoint result,
                     const fieldElem scalar);

void uECC_pointAdd(ecPoint result,
                    const ecPoint a,
                    const ecPoint b);

void uECC_randInt(fieldElem vli);
#endif
