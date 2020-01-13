#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/time.h>
#include <sys/select.h>

#include "common.h"
#include "hsm.h"
#include "usb.h"

using namespace std;

UsbDevice *UsbDevice_new(const char *handle) {
    int rv = ERROR;
    UsbDevice *dev;

    CHECK_A (dev = (UsbDevice *)malloc(sizeof(UsbDevice)));
    dev->fd = open(handle, O_RDWR | O_NOCTTY | O_SYNC);
    CHECK_C (dev->fd != -1);

    struct termios tty;
    tcgetattr(dev->fd, &tty);

    tty.c_cflag |= (CLOCAL | CREAD);    /* ignore modem controls */
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;         /* 8-bit characters */
    tty.c_cflag &= ~PARENB;     /* no parity bit */
    tty.c_cflag &= ~CSTOPB;     /* only need 1 stop bit */
    tty.c_cflag &= ~CRTSCTS;    /* no hardware flowcontrol */

    cfmakeraw(&tty);

    tty.c_oflag &= ~OPOST;
    tty.c_oflag &= ~ONLCR;

    //tty.c_cc[VMIN] = 1;

    CHECK_C (tcsetattr(dev->fd, TCSANOW, &tty) == 0);
    tcflush(dev->fd, TCOFLUSH);
    tcflush(dev->fd, TCIFLUSH);

    cfsetispeed(&tty, B115200);
    //cfsetispeed(&tty, B9600);
    cfsetospeed(&tty, B115200);
    //cfsetospeed(&tty, B9600);

    dev->sessionCtr = 0;

cleanup:
    if (rv == ERROR) {
        printf("Error opening device: %s\n", handle);
        UsbDevice_free(dev);
        return NULL;
    }
    return dev;
}

void UsbDevice_free(UsbDevice *dev) {
    if (dev->fd) close(dev->fd);
    free(dev);
}

int send(UsbDevice *dev, uint8_t msgType, uint8_t *req, int reqLen, bool isInitial) {
    int rv = OKAY;
    int bytesWritten = 0;
    int i = 0;
    uint8_t sessionNum = dev->sessionCtr;
    printf("sessionNum = %d\n", sessionNum);
    printf("req len = %d\n", reqLen);
    fd_set fds;
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(dev->fd, &fds);
    
    while (bytesWritten <= reqLen) {
        CDCFrame frame;
        int bytesToWrite = reqLen - bytesWritten < CDC_PAYLOAD_SZ ? reqLen - bytesWritten : CDC_PAYLOAD_SZ;
        memset(frame.payload, 0, CDC_PAYLOAD_SZ);
        if (reqLen > 0) {
            memcpy(frame.payload, req + bytesWritten, bytesToWrite);
        }
        frame.msgType = msgType;
        frame.seqNo = i;
        frame.sessionNum = sessionNum;
        printf("seqno =  %d\n", frame.seqNo);
        printf("sending frame: ");
        for (int i = 0; i < CDC_FRAME_SZ; i++) {
            printf("%x", ((uint8_t *)&frame)[i]);
        }
        printf("\n");
        int numSent = 0;
        while (numSent < CDC_FRAME_SZ) {
            FD_ZERO(&fds);
            FD_SET(dev->fd, &fds);
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
           
            printf("waiting to write seqno = %d\n", frame.seqNo); 
//            int selectRes = select(dev->fd + 1, NULL, &fds, NULL, &timeout);
    //        if (selectRes > 0) {
                numSent += write(dev->fd, (uint8_t *)&frame + numSent, CDC_FRAME_SZ - numSent);
                //tcdrain(dev->fd);
                printf("numSent =  %d\n", numSent);
         //   }
 //           if (selectRes <= 0) {
      //          printf("going to flush\n");
     //           tcflush(dev->fd, TCIOFLUSH);
        //        printf("flushed\n");
   //         }

            // this doesn't seem to actually  make a difference... 
            if (!isInitial) continue;
            FD_ZERO(&fds);
            FD_SET(dev->fd, &fds);
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
            uint8_t buf[CDC_FRAME_SZ];
            /*while (select(dev->fd + 1, &fds, NULL, NULL, &timeout) > 0) {
                read(dev->fd, buf, CDC_FRAME_SZ);
            }*/
            //tcdrain(dev->fd);
            tcflush(dev->fd, TCIFLUSH);
        }
        bytesWritten += CDC_PAYLOAD_SZ;
        i++;
    }
    //tcdrain(dev->fd);
cleanup:
    return rv;

}

int UsbDevice_exchange(UsbDevice *dev, uint8_t msgType, uint8_t *req, int reqLen, uint8_t *resp, int respLen) {
    int rv = OKAY;

    tcflush(dev->fd, TCIOFLUSH);
    /* Send. */
    send(dev, msgType, req, reqLen, true);

    /* Receive. */
//    if (msgType == HSM_DECRYPT) respLen = reqLen;
    fd_set fds;
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(dev->fd, &fds);
    uint8_t sessionNum = dev->sessionCtr;
    int bytesRead = 0;
    if (respLen == 0) rv = OKAY;
    printf("respLen = %d\n", respLen);
    while (bytesRead < respLen || respLen == 0) {
        CDCFrame frame;
        int framePointer = 0;
        while (framePointer < CDC_FRAME_SZ) {
            FD_ZERO(&fds);
            FD_SET(dev->fd, &fds);
    
            printf("bytesRead = %d, framePointer = %d\n", bytesRead, framePointer);
            int selectRes = select(dev->fd + 1, &fds, NULL, NULL, &timeout);
            if (selectRes <= 0) {
                printf("*** SELECT ERR: %d\n", selectRes);
                tcflush(dev->fd, TCIOFLUSH);
                send(dev, msgType, req, reqLen, false);
                continue;
            }
            //if (selectRes <= 0) send(dev, msgType, req, reqLen, false);
            //if (selectRes <= 0) printf("*** just resent\n");
            //CHECK_C (selectRes > 0);
            printf("will read\n");
            int numBytes = read(dev->fd, (uint8_t *)&frame + framePointer, CDC_FRAME_SZ);
            printf("num bytes read: %d\n", numBytes);
            //printf("current frame after receiving %d bytes: ", numBytes);
            //for (int i = 0; i < CDC_FRAME_SZ; i++) {
            //    printf("%x", ((uint8_t *)&frame)[i]);
            //}
            //printf("\n");

            framePointer += numBytes;
        }
        printf("received session num %d, should be %d\n", frame.sessionNum, sessionNum);
        printf("received frame with msgType %x, sessionNum %d, seqno %d: ", frame.msgType, frame.sessionNum, frame.seqNo);
        for (int i = 0; i < CDC_PAYLOAD_SZ; i++) {
            printf("%x", frame.payload[i]);
        }
        printf("\n");
        if (frame.sessionNum != sessionNum) continue;
        if (respLen > 0) {
            int bytesToCopy = respLen - (frame.seqNo * CDC_PAYLOAD_SZ) < CDC_PAYLOAD_SZ ? respLen - (frame.seqNo * CDC_PAYLOAD_SZ) : CDC_PAYLOAD_SZ;
            memcpy(resp + frame.seqNo * CDC_PAYLOAD_SZ, frame.payload, bytesToCopy);
            //if (msgType != HSM_DECRYPT) memcpy(resp + frame.seqNo * CDC_PAYLOAD_SZ, frame.payload, bytesToCopy);
            printf("copied %d bytes to %d seqno\n", bytesToCopy, frame.seqNo);
        }
        bytesRead = (frame.seqNo + 1) * CDC_PAYLOAD_SZ;
        printf("new bytes read = %d from seqno %d\n", bytesRead, frame.seqNo);
        //printf("finished frame %d, read %d bytes\n", frame.seqNo, bytesRead);
        if (respLen == 0) break;
    }
    dev->sessionCtr++;

    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    uint8_t buf[CDC_FRAME_SZ];
    while (select(dev->fd + 1, &fds, NULL, NULL, &timeout) > 0) {
        read(dev->fd, buf, CDC_FRAME_SZ);
    }
    //tcdrain(dev->fd);
    //tcflush(dev->fd, TCIOFLUSH);

cleanup:
    if (rv == ERROR) printf("Error in message exchange.\n");
    return rv;
}
