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

//uint8_t msgBuf[1024];
//uint8_t msgBuf[1];
//uint8_t msgBuf[3500];

//uint8_t msgBuf[3000]; // not used

//uint8_t rsp[1024];

//uint8_t inOutBuf[1];
uint8_t inOutBuf[5000];

// THIS IS THE ONE
//uint8_t inOutBuf[10800];

//uint8_t inOutBuf[9100];
//uint8_t inOutBuf[1];

//uint8_t rsp[1];
//uint8_t rsp[3500];
uint8_t currSessionNum = 0;

static int ceil(double x) {
    if ((int) x < x) return (int)x + 1;
    else return x;
}

// Buffer data and send in HID_MESSAGE_SIZE chunks
// if len == 0, FLUSH
static void cdc_write(uint8_t *data, int len, uint8_t msgType, uint8_t sessionNum)
{
    int numRounds = len == 0 ? 1 : ceil((double)len / CDC_PAYLOAD_SZ);
    for (int i = 0; i < numRounds; i++) {
        struct CDCFrame frame;
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


void cdc_handle_packet(struct CDCFrame *frame, int remaining, int rhead, int whead)
{
    if (frame->msgType == HSM_RESET) {
        cdc_write(inOutBuf, 0, frame->msgType, currSessionNum);
        currSessionNum = 0;
        return;
    }
    if (frame->sessionNum != currSessionNum) {
        //if ((currSessionNum != 0xff) && (frame->sessionNum != 0)) return;
        return;
    }
    //currSessionNum = frame->sessionNum;
    memcpy(inOutBuf + frame->seqNo * CDC_PAYLOAD_SZ, frame->payload, CDC_PAYLOAD_SZ);
    int reqLen = HSM_GetReqLenFromMsgType(frame->msgType);
/*    if (frame->msgType == HSM_RETRIEVE) {
        uint8_t rsp[59];
        memset(rsp, frame->seqNo, 59);
        rsp[0] = (uint8_t)remaining;
        rsp[1] = (uint8_t)rhead;
        rsp[2] = (uint8_t)whead;
        int tmpSessionNum = currSessionNum;
        currSessionNum = -1;
        cdc_write(rsp, 59, frame->msgType);
        currSessionNum = tmpSessionNum;
    }*/
    //if (frame->seqNo == 36) { 
    //if (frame->seqNo == 36) { 
    //if (frame->seqNo == 0) { 
    if ((frame->seqNo + 1) * CDC_PAYLOAD_SZ >= reqLen) { 
        int sendLen;
        //uint8_t rsp[500];
        //uint8_t rsp[CDC_BUFFER_LEN];
        //if (frame->msgType != HSM_DECRYPT) {
        //HSM_Handle(frame->msgType, msgBuf, rsp, &sendLen);
   /*     if (frame->msgType == HSM_DECRYPT) {
            memset(rsp, 0xff, IBE_MSG_LEN);
            sendLen = IBE_MSG_LEN;
        } else {
            HSM_Handle(frame->msgType, msgBuf, rsp, &sendLen);
        }*/
        //if (frame->msgType != HSM_RETRIEVE) {
        uint8_t sessionNum = currSessionNum;
        currSessionNum = (currSessionNum + 1) % 256;
        HSM_Handle(frame->msgType, inOutBuf, inOutBuf, &sendLen);
        cdc_write(inOutBuf, sendLen, frame->msgType, sessionNum);
        //} else {
        //    cdc_write(msgBuf, reqLen, frame->msgType);
        //}
        //cdc_write(rsp, sendLen, frame->msgType);
        //}
        //currSessionNum = (currSessionNum + 1) % 256; /*else {
        /*    cdc_write(msgBuf, reqLen, frame->msgType);
        }*/
    }
}
