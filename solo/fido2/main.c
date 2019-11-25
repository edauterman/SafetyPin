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
#include "device.h"
#include "ctaphid.h"
//#include "bsp.h"
#include "util.h"
#include "log.h"
#include "ctap.h"
#include "crypto.h"
#include "bls12_381/bls12_381.h"
#include APP_CONFIG

#if !defined(TEST)


int main(int argc, char *argv[])
{
    uint8_t hidmsg[64];
    uint32_t t1 = 0;

    set_logging_mask(
		/*0*/
		//TAG_GEN|
		// TAG_MC |
		// TAG_GA |
		TAG_WALLET |
		TAG_STOR |
		//TAG_NFC_APDU |
		TAG_NFC |
		//TAG_CP |
		// TAG_CTAP|
		//TAG_HID|
		TAG_U2F|
		//TAG_PARSE |
		//TAG_TIME|
		// TAG_DUMP|
		TAG_GREEN|
		TAG_RED|
        TAG_EXT|
        TAG_CCID|
		TAG_ERR
	);

    device_init(argc, argv);

    memset(hidmsg,0,sizeof(hidmsg));

    printf1(TAG_GREEN, "starting!!!\n");

    while(1)
    {
        if (millis() - t1 > HEARTBEAT_PERIOD)
        {
            printf1(TAG_GREEN, "heartbeat\n");
            heartbeat();
            t1 = millis();

            uint8_t pubkey[32];
            uint8_t privkey[64];
            uint8_t shared_secret[32];
            uint32_t before1 = millis();
            crypto_ecc256_make_key_pair(pubkey, privkey);
            uint32_t before2 = millis();
            printf1(TAG_GREEN, "key pair: %d\n", before2 - before1);
            crypto_ecc256_shared_secret(pubkey, privkey, shared_secret);
            uint32_t after = millis();
            printf1(TAG_GREEN, "shared secret: %d\n", after - before2);
            uint32_t before3 = millis();
            //embedded_pairing_bls12_381_g1_t result;
            //embedded_pairing_bls12_381_g1_add(&result, embedded_pairing_bls12_381_g1_zero, embedded_pairing_bls12_381_g1_zero);

            //embedded_pairing_bls12_381_g1_t a;
            //embedded_pairing_bls12_381_g1affine_t a_affine;
            //embedded_pairing_bls12_381_g2_t b;
            //embedded_pairing_bls12_381_g2affine_t b_affine;
            embedded_pairing_bls12_381_fq12_t c_affine;
            embedded_pairing_bls12_381_pairing(&c_affine, embedded_pairing_bls12_381_g1affine_zero, embedded_pairing_bls12_381_g2affine_zero);
            uint32_t after3 = millis();
            printf1(TAG_GREEN, "pairing: %d\n", after3 - before3);
        }

        device_manage();

        if (usbhid_recv(hidmsg) > 0)
        {
            ctaphid_handle_packet(hidmsg);
            memset(hidmsg, 0, sizeof(hidmsg));
        }
        else
        {
        }
        ctaphid_check_timeouts();

    }

    // Should never get here
    usbhid_close();
    printf1(TAG_GREEN, "done\n");
    return 0;
}

#endif
