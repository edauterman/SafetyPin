#include "bls12_381/bls12_381.h"
#include "multisig.h"
#include "ibe.h"

embedded_pairing_core_bigint_256_t sk;
embedded_pairing_bls12_381_g2_t pk;
embedded_pairing_bls12_381_g2_t aggPk;
embedded_pairing_bls12_381_g2affine_t aggPkAffine;
embedded_pairing_bls12_381_g2affine_t pkAffine;

void Multisig_Setup() {
    uint8_t hash[32];
    memset(hash, 0xff, 32);
    /* USING A DUMMY MSK ONLY FOR TESTING PURPOSES. */
    embedded_pairing_bls12_381_zp_from_hash(&sk, hash);
    embedded_pairing_bls12_381_g2_multiply_affine(&pk, embedded_pairing_bls12_381_g2affine_generator, &sk);
}

void Multisig_GetPk(uint8_t *pkBuf) {
    /*uint8_t hash[32];
    memset(hash, 0xff, 32);
    /* USING A DUMMY MSK ONLY FOR TESTING PURPOSES. */
    /*embedded_pairing_bls12_381_zp_from_hash(&sk, hash);
    embedded_pairing_bls12_381_g2_multiply_affine(&pk, embedded_pairing_bls12_381_g2affine_generator, &sk);
    */
    embedded_pairing_bls12_381_g2affine_from_projective(&pkAffine, &pk);
    memset(pkBuf, 0, embedded_pairing_bls12_381_g2_marshalled_compressed_size);
    embedded_pairing_bls12_381_g2_marshal(pkBuf, &pkAffine, true);

 /*   printf("pk: ");
    for (int i = 0; i < embedded_pairing_bls12_381_g2_marshalled_compressed_size; i++) printf("%02x", pkBuf[i]);
    printf("\n");*/
}

void Multisig_SetAggPk(uint8_t *aggPkBuf) {
    embedded_pairing_bls12_381_g2_unmarshal(&aggPkAffine, aggPkBuf, true, true);
    embedded_pairing_bls12_381_g2_from_affine(&aggPk, &aggPkAffine);
}

void Multisig_Sign(uint8_t *msg, int msgLen, uint8_t *sig) { 
    embedded_pairing_bls12_381_g1affine_t base;
    uint8_t hashedMsg[2 * embedded_pairing_bls12_381_g1_marshalled_uncompressed_size];
    embedded_pairing_bls12_381_g1_t sigPt;
    embedded_pairing_bls12_381_g1_t basePt;
    embedded_pairing_bls12_381_g1affine_t sigAffine;
    embedded_pairing_core_bigint_256_t r;

    /*
    printf("msg: ");
    for (int i = 0; i < msgLen; i++) printf("%02x", msg[i]);
    printf("\n");
*/
    hashToLength(msg, msgLen, hashedMsg, 2 * embedded_pairing_bls12_381_g1_marshalled_uncompressed_size);
/*    printf("hashed: ");
    for (int i = 0; i < 2 * embedded_pairing_bls12_381_g1_marshalled_uncompressed_size; i++) printf("%02x", hashedMsg[i]);
    printf("\n");

    embedded_pairing_bls12_381_g1affine_from_hash(&base, hashedMsg);
    uint8_t baseBuf[embedded_pairing_bls12_381_g1_marshalled_uncompressed_size];
    embedded_pairing_bls12_381_g1_marshal(baseBuf, &base, false);
    printf("*** basePt: ");
    for (int i = 0; i < embedded_pairing_bls12_381_g1_marshalled_uncompressed_size; i++) printf("%02x", baseBuf[i]);
    printf("\n");
*/


    embedded_pairing_bls12_381_zp_from_hash(&r, msg);
    embedded_pairing_bls12_381_g1_multiply_affine(&basePt, embedded_pairing_bls12_381_g1affine_generator, &r);
    embedded_pairing_bls12_381_g1affine_from_projective(&base, &basePt);
    

    //    embedded_pairing_bls12_381_g1affine_from_hash(&base, hashedMsg);
    embedded_pairing_bls12_381_g1_multiply_affine(&sigPt, &base, &sk);
    embedded_pairing_bls12_381_g1affine_from_projective(&sigAffine, &sigPt);
    embedded_pairing_bls12_381_g1_marshal(sig, &sigAffine, true);
/*
    uint8_t testBuf[embedded_pairing_bls12_381_g1_marshalled_compressed_size];
    embedded_pairing_bls12_381_g1_marshal(testBuf, &base, true);
    printf("hashed msg as point: ");
    for (int i = 0; i < embedded_pairing_bls12_381_g1_marshalled_compressed_size; i++) printf("%02x", testBuf[i]);
    printf("\n");



    printf("sig: ");
    for (int i = 0; i < embedded_pairing_bls12_381_g1_marshalled_compressed_size; i++) printf("%02x", sig[i]);
    printf("\n");

    uint8_t pkBuf[embedded_pairing_bls12_381_g2_marshalled_compressed_size];
    embedded_pairing_bls12_381_g2_multiply_affine(&pk, embedded_pairing_bls12_381_g2affine_generator, &sk);
    embedded_pairing_bls12_381_g2affine_from_projective(&pkAffine, &pk);
    memset(pkBuf, 0, embedded_pairing_bls12_381_g2_marshalled_compressed_size);
    embedded_pairing_bls12_381_g2_marshal(pkBuf, &pkAffine, true);
    printf("pk computed from sk in sign: ");
    for (int i = 0; i < embedded_pairing_bls12_381_g2_marshalled_compressed_size; i++) printf("%02x", pkBuf[i]);
    printf("\n");
*/

}

uint8_t Multisig_Verify(uint8_t *msg, int msgLen, uint8_t *sig) {
    uint8_t hashedMsg[2 * embedded_pairing_bls12_381_g1_marshalled_uncompressed_size];
    embedded_pairing_bls12_381_g1_t basePt;
    embedded_pairing_bls12_381_g1affine_t base;
    embedded_pairing_bls12_381_g1affine_t sigAffine;
    embedded_pairing_bls12_381_fq12_t res1;
    embedded_pairing_bls12_381_fq12_t res2;
    embedded_pairing_core_bigint_256_t r;
/*
    printf("sig: ");
    for (int i = 0; i < embedded_pairing_bls12_381_g1_marshalled_compressed_size; i++) printf("%02x", sig[i]);
    printf("\n");



    printf("msg: ");
    for (int i = 0; i < msgLen; i++) printf("%02x", msg[i]);
    printf("\n");
*/
    // e(pk, H(m))
    hashToLength(msg, msgLen, hashedMsg, 2 * embedded_pairing_bls12_381_g1_marshalled_uncompressed_size);
/*    printf("hashed: ");
    for (int i = 0; i < 2 * embedded_pairing_bls12_381_g1_marshalled_uncompressed_size; i++) printf("%02x", hashedMsg[i]);
    printf("\n");
*/
    embedded_pairing_bls12_381_zp_from_hash(&r, msg);
    embedded_pairing_bls12_381_g1_multiply_affine(&basePt, embedded_pairing_bls12_381_g1affine_generator, &r);
    embedded_pairing_bls12_381_g1affine_from_projective(&base, &basePt);


    //embedded_pairing_bls12_381_g1affine_from_hash(&base, hashedMsg);
    embedded_pairing_bls12_381_g2_multiply_affine(&pk, embedded_pairing_bls12_381_g2affine_generator, &sk);
    embedded_pairing_bls12_381_g2affine_from_projective(&pkAffine, &pk);
    embedded_pairing_bls12_381_pairing(&res1, &base, &pkAffine);

/*    uint8_t testBuf[embedded_pairing_bls12_381_g1_marshalled_compressed_size];
    embedded_pairing_bls12_381_g1_marshal(testBuf, &base, true);
    printf("hashed msg as point: ");
    for (int i = 0; i < embedded_pairing_bls12_381_g1_marshalled_compressed_size; i++) printf("%02x", testBuf[i]);
    printf("\n");
*/


    // e(g, sig)
    embedded_pairing_bls12_381_g1_unmarshal(&sigAffine, sig, true, true);
    embedded_pairing_bls12_381_pairing(&res2, &sigAffine, embedded_pairing_bls12_381_g2affine_generator);

    // Check if equal
    
/*    uint8_t res1Buf[embedded_pairing_bls12_381_gt_marshalled_size];
    uint8_t res2Buf[embedded_pairing_bls12_381_gt_marshalled_size];
    embedded_pairing_bls12_381_gt_marshal(res1Buf, &res1);
    embedded_pairing_bls12_381_gt_marshal(res2Buf, &res2);
   
    printf("res1: ");
    for (int i = 0; i < embedded_pairing_bls12_381_gt_marshalled_size; i++) printf("%02x", res1Buf[i]);
    printf("\n");

    printf("res2: ");
    for (int i = 0; i < embedded_pairing_bls12_381_gt_marshalled_size; i++) printf("%02x", res2Buf[i]);
    printf("\n");



    if (!embedded_pairing_bls12_381_gt_equal(&res1, &res2)) printf("NOT EQUAL\n");
    else printf("WOW IT VERIFIED THE FIRST TIME\n");
  */  
    
    //-----------------------------------------
    
/*    embedded_pairing_bls12_381_g1_t sigPt;

    printf("msg: ");
    for (int i = 0; i < msgLen; i++) printf("%02x", msg[i]);
    printf("\n");

    /*hashToLength(msg, msgLen, hashedMsg, 2 * embedded_pairing_bls12_381_g1_marshalled_uncompressed_size);
    printf("hashed: ");
    for (int i = 0; i < 2 * embedded_pairing_bls12_381_g1_marshalled_uncompressed_size; i++) printf("%02x", hashedMsg[i]);
    printf("\n");


    embedded_pairing_bls12_381_g1affine_from_hash(&base, hashedMsg);
    */
    /*embedded_pairing_bls12_381_g1_multiply_affine(&sigPt, &base, &sk);
    embedded_pairing_bls12_381_g1affine_from_projective(&sigAffine, &sigPt);

    embedded_pairing_bls12_381_g1_marshal(testBuf, &base, true);
    printf("hashed msg as point: ");
    for (int i = 0; i < embedded_pairing_bls12_381_g1_marshalled_compressed_size; i++) printf("%02x", testBuf[i]);
    printf("\n");

    // e(pk, H(m))
    embedded_pairing_bls12_381_pairing(&res1, &base, &pkAffine);



     // e(g, sig)
    embedded_pairing_bls12_381_g1_unmarshal(&sigAffine, sig, true, true);
    embedded_pairing_bls12_381_pairing(&res2, &sigAffine, embedded_pairing_bls12_381_g2affine_generator);

    // Check if equal
    
    embedded_pairing_bls12_381_gt_marshal(res1Buf, &res1);
    embedded_pairing_bls12_381_gt_marshal(res2Buf, &res2);
   
  /*  printf("res1: ");
    for (int i = 0; i < embedded_pairing_bls12_381_gt_marshalled_size; i++) printf("%02x", res1Buf[i]);
    printf("\n");

    printf("res2: ");
    for (int i = 0; i < embedded_pairing_bls12_381_gt_marshalled_size; i++) printf("%02x", res2Buf[i]);
    printf("\n");
*/

/*
    if (!embedded_pairing_bls12_381_gt_equal(&res1, &res2)) printf("NOT EQUAL WITHOUT MARSHAL\n");
    else printf("WOW IT DID VERIFY\n");
 
*/
    return embedded_pairing_bls12_381_gt_equal(&res1, &res2) ? 1 : 0;
}
