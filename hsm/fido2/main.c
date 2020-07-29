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
#include "../safetypin/cdc.h"
#include "device.h"
#include "ctaphid.h"
//#include "bsp.h"
#include "util.h"
#include "log.h"
#include "ctap.h"
#include "crypto.h"
#include "bls12_381/bls12_381.h"
#include "../safetypin/ibe.h"
#include "../safetypin/punc_enc.h"
#include "../safetypin/hsm.h"
#include "../safetypin/multisig.h"
#include "../safetypin/uECC.h"
#include "../crypto/micro-ecc/uECC.h"
#include APP_CONFIG

#if !defined(TEST)

int main(int argc, char *argv[])
{
    uint8_t msg[64];
    uint32_t t1 = 0;
    uint8_t cdc_msg[CDC_FRAME_SZ];

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
    Multisig_Setup();
    ctap_generate_rng(pingKey, KEY_LEN);


    printf1(TAG_GREEN, "starting!\n");

    uint32_t t_old = millis();
    uint32_t t_new = millis();

#ifndef IS_BOOTLOADER
    printf("not is bootloader\n");
#else
    printf("is bootloader\n");
#endif

    while(1)
    {
        t_old = t_new;
        t_new = millis();
        if (millis() - t1 > HEARTBEAT_PERIOD)
        {
            heartbeat();
            t1 = millis();
        }

        device_manage();

        uint32_t t0 = millis();
        if (usbhid_recv(msg) > 0)
        {
            uint32_t t1 = millis();
            ctaphid_handle_packet(msg);
            uint32_t t2 = millis();
            memset(msg, 0, sizeof(msg));
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
