// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _CDC_H_H
#define _CDC_H_H

#include "device.h"
#include "ctap_errors.h"

#define CDC_MAX_PACKET_SZ  64
#define CDC_FRAME_SZ 64
#define CDC_PAYLOAD_SZ 59

struct CDCFrame {
    uint16_t discard;
    uint8_t msgType;
    uint8_t seqNo;
    uint8_t sessionNum;
    uint8_t payload[CDC_PAYLOAD_SZ];
};

void cdc_handle_packet(struct CDCFrame *frame, int remaining, int rhead, int whead);

#endif
