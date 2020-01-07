// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device.h"
#include "cdc.h"
#include "hsm.h"

uint8_t msgBuf[CDC_BUFFER_LEN];
int currSessionNum;

static int ceil(double x) {
    if ((int) x < x) return x + 1;
    else return x;
}

// Buffer data and send in HID_MESSAGE_SIZE chunks
// if len == 0, FLUSH
static void cdc_write(uint8_t *data, int len)
{
    for (int i = 0; i < ceil((double)len / CDC_PAYLOAD_SZ); i++) {
        struct CDCFrame frame;
        frame.sessionNum = currSessionNum;
        /* Don't need to set msg type for responses. */
        frame.seqNo = i;
        int bytesToWrite = len - (i * CDC_PAYLOAD_SZ) < CDC_PAYLOAD_SZ ? len - (i * CDC_PAYLOAD_SZ) : CDC_PAYLOAD_SZ;
        memset(frame.payload, 0, CDC_PAYLOAD_SZ);
        memcpy(frame.payload, data + i * CDC_PAYLOAD_SZ, bytesToWrite);
        // Assume all messages <=  CDC_PACKET_SZ
        usbcdc_send((uint8_t *)&frame, CDC_FRAME_SZ);
    }
}


void cdc_handle_packet(struct CDCFrame *frame)
{
    currSessionNum = frame->sessionNum;
    memcpy(msgBuf + frame->seqNo * CDC_PAYLOAD_SZ, frame->payload, CDC_PAYLOAD_SZ);
    int reqLen = HSM_GetReqLenFromMsgType(frame->msgType);
    if ((frame->seqNo + 1) * CDC_PAYLOAD_SZ >= reqLen) { 
        int sendLen;
        uint8_t rsp[CDC_BUFFER_LEN];
        HSM_Handle(frame->msgType, msgBuf, rsp, &sendLen);
        cdc_write(rsp, sendLen);
    }
}
