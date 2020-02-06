#include <stdio.h>

#include "../crypto/micro-ecc/uECC_vli.h"
#include "../crypto/micro-ecc/uECC.h"
#include "uECC.h"

/* Set curve to use. */
uECC_Curve curve;

void uECC_init() {
    curve =  uECC_secp256r1();
}

void uECC_setZero(fieldElem vli) {
    uECC_vli_clear(vli, uECC_curve_num_n_words(curve));
}

void uECC_setOne(fieldElem vli) {
    uECC_vli_clear(vli, uECC_curve_num_n_words(curve));
    vli[0] = 1;
}

void uECC_setWord(fieldElem vli, uECC_word_t word) {
    uECC_vli_clear(vli, uECC_curve_num_n_words(curve));
    vli[0] = word;
}

/* Constant-time comparison function - secure way to compare long integers */
/* Returns one if left == right, zero otherwise */
uECC_word_t uECC_equal(const fieldElem left,
                        const fieldElem right) {
    return uECC_vli_equal(left, right, uECC_curve_num_n_words(curve));
}

/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
void uECC_modAdd(fieldElem result,
                     const fieldElem left,
                     const fieldElem right) {
    uECC_vli_modAdd(result, left, right, uECC_curve_n(curve), uECC_curve_num_n_words(curve));
}

/* Computes result = (left - right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
void uECC_modSub(fieldElem result,
                     const fieldElem left,
                     const fieldElem right) {
    uECC_vli_modSub(result, left, right, uECC_curve_n(curve), uECC_curve_num_n_words(curve));
}

/* Computes result = (left * right) % mod.
   Currently only designed to work for mod == curve->p or curve_n. */
void uECC_modMult(fieldElem result,
                      const fieldElem left,
                      const fieldElem right) {
    uECC_vli_modMult(result, left, right, uECC_curve_n(curve), uECC_curve_num_n_words(curve));
    //uECC_vli_modMult_fast(result, left, right, curve);
}

void uECC_modNeg(fieldElem result,
                     const fieldElem input) {
    uECC_vli_modSub(result, uECC_curve_n(curve), input, uECC_curve_n(curve), uECC_curve_num_n_words(curve));
}

/* Computes result = (1 / input) % mod.*/
void uECC_modInv(fieldElem result,
                     const fieldElem input) {
    uECC_vli_modInv(result, input, uECC_curve_n(curve), uECC_curve_num_n_words(curve));
}

/* Converts an integer in uECC native format to big-endian bytes. */
/* Buffer should be length 32. */
void uECC_fieldElemToBytes(uint8_t *bytes, const fieldElem native) {
    uECC_vli_nativeToBytes(bytes, 32, native);
}

/* Converts big-endian bytes to an integer in uECC native format. */
/* Buffer should be length 32. */
void uECC_bytesToFieldElem(fieldElem native, const uint8_t *bytes) {
    uECC_vli_bytesToNative(native, bytes, 32);
}

/* Converts an integer in uECC native format to big-endian bytes. */
/* Buffer should be length 64. */
void uECC_pointToBytesUncompressed(uint8_t *bytes, const ecPoint native) {
    uint8_t tmp[64];
    uECC_vli_nativeToBytes(tmp, 64, native);
    memcpy(bytes, tmp + 32, 32);
    memcpy(bytes + 32, tmp, 32);
}

/* Converts big-endian bytes to an integer in uECC native format. */
/* Buffer should be length 64. */
void uECC_bytesToPointUncompressed(ecPoint native, const uint8_t *bytes) {
    uint8_t tmp[64];
    memcpy(tmp + 32, bytes, 32);
    memcpy(tmp, bytes + 32, 32);
    uECC_vli_bytesToNative(native, tmp, 64);
}

/* Converts an integer in uECC native format to big-endian bytes. */
/* Buffer should be length 64. */
void uECC_pointToBytesCompressed(uint8_t *bytes, const ecPoint native) {
    uint8_t tmp[64];
    uECC_pointToBytesUncompressed(tmp, native);
    //uECC_vli_nativeToBytes(tmp, 64, native);
    uECC_compress(tmp, bytes, curve);
}

/* Converts big-endian bytes to an integer in uECC native format. */
/* Buffer should be length 64. */
void uECC_bytesToPointCompressed(ecPoint native, const uint8_t *bytes) {
    uint8_t tmp[64];
    uECC_decompress(bytes, tmp, curve);
    //uECC_vli_bytesToNative(native, tmp, 64);
    uECC_bytesToPointUncompressed(native, tmp);
}



/* Multiplies a point by a scalar. Points are represented by the X coordinate followed by
   the Y coordinate in the same array, both coordinates are curve->num_words long. Note
   that scalar must be curve->num_n_words long (NOT curve->num_words). */
void uECC_pointMult(ecPoint result,
                     const ecPoint point,
                     const fieldElem scalar) {
    uECC_point_mult(result, point, scalar, curve);
}

void uECC_basePointMult(ecPoint result,
                     const fieldElem scalar) {
    uECC_point_mult(result, uECC_curve_G(curve), scalar, curve);
}

void uECC_pointAdd(ecPoint result,
                    const ecPoint a,
                    const ecPoint b) {
    uECC_point_add(result, a, b, curve);
}

void uECC_randInt(fieldElem vli) {
    uECC_generate_random_int(vli, uECC_curve_n(curve), uECC_curve_num_n_words(curve));
}

int uECC_ecdsaVerify(const uint8_t *public_key,
                     const uint8_t *message_hash,
                     unsigned hash_size,
                     const uint8_t *signature) {
    uint8_t pk[64];
    uECC_decompress(public_key, pk, curve);
    return uECC_verify(pk, message_hash, hash_size, signature, curve);
}
