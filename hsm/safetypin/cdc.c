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

#define CDC_BUF_SZ 5000

#ifndef HID
uint8_t inOutBuf[5000];
#else
uint8_t inOutBuf[128];
#endif

uint8_t currSessionNum = 0;

static int ceil(double x) {
    if ((int) x < x) return (int)x + 1;
    else return x;
}

/* Send data in CDC_PAYLOAD_SZ chunks. */
static void cdc_write(uint8_t *data, int len, uint8_t msgType, uint8_t sessionNum)
{
    int numRounds = len == 0 ? 1 : ceil((double)len / CDC_PAYLOAD_SZ);
    for (int i = 0; i < numRounds; i++) {
        struct CDCFrame frame;
        memset((uint8_t *)&frame, 0, CDC_FRAME_SZ);
        frame.sessionNum = sessionNum;
        /* Don't need to set msg type for responses. */
        frame.seqNo = i;
        int bytesToWrite = len - (i * CDC_PAYLOAD_SZ) < CDC_PAYLOAD_SZ ? len - (i * CDC_PAYLOAD_SZ) : CDC_PAYLOAD_SZ;
        memset(frame.payload, 0, CDC_PAYLOAD_SZ);
        memcpy(frame.payload, data + i * CDC_PAYLOAD_SZ, bytesToWrite);
        frame.msgType = msgType;
        // Assume all messages <=  CDC_PACKET_SZ
        usbcdc_send((uint8_t *)&frame, CDC_FRAME_SZ);
    }
}

/* Process an incoming packet. */
void cdc_handle_packet(struct CDCFrame *frame, int remaining, int rhead, int whead)
{
    if (frame->msgType == HSM_RESET) {
        cdc_write(inOutBuf, 0, frame->msgType, 0);
        currSessionNum = 0;
        return;
    }
    if (frame->sessionNum != currSessionNum) {
        return;
    }

    if ((frame->seqNo + 1) * CDC_PAYLOAD_SZ > CDC_BUF_SZ) {
        return;
    }

    memcpy(inOutBuf + frame->seqNo * CDC_PAYLOAD_SZ, frame->payload, CDC_PAYLOAD_SZ);
    int reqLen = HSM_GetReqLenFromMsgType(frame->msgType);
    if ((frame->seqNo + 1) * CDC_PAYLOAD_SZ >= reqLen) { 
        int sendLen;
        uint8_t sessionNum = currSessionNum;
        currSessionNum = (currSessionNum + 1) % 256;
        HSM_Handle(frame->msgType, inOutBuf, inOutBuf, &sendLen);
        cdc_write(inOutBuf, sendLen, frame->msgType, sessionNum);
    }
}
