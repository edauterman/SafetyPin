// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "cbor.h"
#include "cdc.h"
#include "device.h"
#include "ctaphid.h"
//#include "bsp.h"
#include "util.h"
#include "log.h"
#include "ctap.h"
#include "crypto.h"
#include "bls12_381/bls12_381.h"
#include "ibe.h"
#include "punc_enc.h"
#include "hsm.h"
#include "uECC.h"
#include "../crypto/micro-ecc/uECC.h"
#include APP_CONFIG

#if !defined(TEST)

int main(int argc, char *argv[])
{
    uint8_t msg[64];
    uint32_t t1 = 0;
    uint8_t cdc_msg[CDC_FRAME_SZ];
    //uint8_t cdc_msg[CDC_MAX_PACKET_SZ];
    //uint8_t output_msg[1024];

    set_logging_mask(
		/*0*/
		//TAG_GEN|
		// TAG_MC |
		// TAG_GA |
		//TAG_WALLET |
		//TAG_STOR |
		//TAG_NFC_APDU |
		//TAG_NFC |
		//TAG_CP |
		// TAG_CTAP|
		//TAG_HID|
		TAG_U2F|
		//TAG_PARSE |
		//TAG_TIME|
		// TAG_DUMP|
		TAG_GREEN|
		TAG_RED|
        //TAG_EXT|
        //TAG_CCID|
		TAG_ERR
	);

    device_init(argc, argv);

    memset(msg,0,64);
    memset(cdc_msg, 0, sizeof(cdc_msg));

    IBE_Setup();
    PuncEnc_Init();
    uECC_init();
    ElGamal_Init();
    ctap_generate_rng(pingKey, KEY_LEN);

    printf1(TAG_GREEN, "starting!\n");

    uint32_t t_old = millis();
    uint32_t t_new = millis();

#ifndef IS_BOOTLOADER
    printf("not is bootloader\n");
#else
    printf("is bootloader\n");
#endif

    printf("after\n");

    /*for (int i = 0; i < sizeof(cdc_msg); i++) {
        if (i % 4 == 0) output_msg[i] = 0x11;
        else if (i % 4 == 1) output_msg[i] = 0x22;
        else if (i % 4 == 2) output_msg[i] = 0x33;
        else output_msg[i] = 0x44;
    }*/
    //memset(output_msg, 0x11, sizeof(output_msg));



    while(1)
    {
        t_old = t_new;
        t_new = millis();
        if (millis() - t1 > HEARTBEAT_PERIOD)
        {
            heartbeat();
            t1 = millis();
/*            fieldElem x1;
            fieldElem x2;
            ecPoint gx1;
            ecPoint gx2;
            ecPoint gx3;
            uint8_t x1Buf[32];
            uint8_t x2Buf[32];
            uint8_t gx1Buf[64];
            uint8_t gx2Buf[64];
            uint8_t gx3Buf[64];
            
            //uECC_bytesToNative(x, input, 32);
            //printf("did bytes to native\n");
            uECC_randInt(x1);
            printf("did rand int\n");
            uECC_fieldElemToBytes(x1Buf, x1);
            uECC_basePointMult(gx1, x1);
            printf("did base point mul\n");
            uECC_pointToBytes(gx1Buf, gx1);
            printf("did native to bytes\n");
            printf("x1: ");
            for (int i = 0; i < 32; i++) {
                printf("%02x", x1Buf[i]);
            }
            printf("\n");
            printf("g^x1: ");
            for (int i = 0; i < 64; i++) {
                printf("%02x", gx1Buf[i]);
                if (i == 31) printf(" ");
            }
            printf("\n");
            
            //printf("did bytes to native\n");
            uECC_randInt(x2);
            printf("did rand int\n");
            uECC_fieldElemToBytes(x2Buf, x2);
            uECC_basePointMult(gx2, x2);
            printf("did base point mul\n");
            uECC_pointToBytes(gx2Buf, gx2);
            printf("did native to bytes\n");
            printf("x2: ");
            for (int i = 0; i < 32; i++) {
                printf("%02x", x2Buf[i]);
            }
            printf("\n");
            printf("g^x2: ");
            for (int i = 0; i < 64; i++) {
                printf("%02x", gx2Buf[i]);
                if (i == 31) printf(" ");
            }
            printf("\n");

            uECC_pointAdd(gx3, gx1, gx2);
            uECC_pointToBytes(gx3Buf, gx3);
            printf("g^x3: ");
            for (int i = 0; i < 64; i++) {
                printf("%02x", gx3Buf[i]);
                if (i == 31) printf(" ");
            }
            printf("\n");

*/
            /*uECC_compute_public_key(input, output, uECC_secp256k1());
            printf("g^x1 other way: ");
            for (int i = 0; i < 64; i++) {
                printf("%02x", output[i]);
                if (i == 31) printf(" ");
            }
            printf("\n");
            */
        }

        device_manage();

        uint32_t t0 = millis();
        if (usbhid_recv(msg) > 0)
        {
            uint32_t t1 = millis();
            ctaphid_handle_packet(msg);
            uint32_t t2 = millis();
            memset(msg, 0, sizeof(msg));
                //}
        }
        int remaining, rhead, whead;
        if (usbcdc_recv(cdc_msg, &remaining, &rhead, &whead) > 0) {
            cdc_handle_packet((struct CDCFrame *)cdc_msg, remaining, rhead, whead);
            memset(cdc_msg, 0, sizeof(cdc_msg));
        }

        ctaphid_check_timeouts();

    }

    // Should never get here
    usbhid_close();
    printf1(TAG_GREEN, "done\n");
    return 0;
}

#endif
