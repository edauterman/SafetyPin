#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/time.h>
#include <sys/select.h>

#include "common.h"
#include "usb.h"

using namespace std;

UsbDevice *UsbDevice_new(const char *handle) {
    int rv = ERROR;
    UsbDevice *dev;

    CHECK_A (dev = (UsbDevice *)malloc(sizeof(UsbDevice)));
    dev->fd = open(handle, O_RDWR | O_NOCTTY);
    printf("fd =  %d\n", dev->fd);
    CHECK_C (dev->fd != -1);
    printf("got past open\n");

    struct termios tty;
    tcgetattr(dev->fd, &tty);

    tty.c_cflag |= (CLOCAL | CREAD);    /* ignore modem controls */
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;         /* 8-bit characters */
    tty.c_cflag &= ~PARENB;     /* no parity bit */
    tty.c_cflag &= ~CSTOPB;     /* only need 1 stop bit */
    tty.c_cflag &= ~CRTSCTS;    /* no hardware flowcontrol */

    CHECK_C (tcsetattr(dev->fd, TCSANOW, &tty) == 0);
    printf("got past set attr\n");
    tcflush(dev->fd, TCOFLUSH);
    tcflush(dev->fd, TCIFLUSH);

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

int UsbDevice_exchange(UsbDevice *dev, uint8_t msgType, uint8_t *req, int reqLen, uint8_t *resp, int respLen) {
    int rv = ERROR;

    /* Send. */
    int bytesWritten = 0;
    int i = 0;
    uint8_t sessionNum = dev->sessionCtr;
    printf("sessionNum = %d\n", sessionNum);
    printf("req len = %d\n", reqLen);
    while (bytesWritten < reqLen) {
        CDCFrame frame;
        int bytesToWrite = reqLen - bytesWritten < CDC_PAYLOAD_SZ ? reqLen - bytesWritten : CDC_PAYLOAD_SZ;
        memset(frame.payload, 0, CDC_PAYLOAD_SZ);
        if (reqLen > 0) {
            memcpy(frame.payload, req + bytesWritten, bytesToWrite);
        }
        frame.msgType = msgType;
        frame.seqNo = i;
        frame.sessionNum = sessionNum;
        printf("sending frame: ");
        for (int i = 0; i < CDC_FRAME_SZ; i++) {
            printf("%x", ((uint8_t *)&frame)[i]);
        }
        printf("\n");
        int numSent = 0;
        while (numSent < CDC_FRAME_SZ) {
            numSent += write(dev->fd, (uint8_t *)&frame + numSent, CDC_FRAME_SZ);
        }
        bytesWritten += CDC_PAYLOAD_SZ;
        i++;
    }

    /* Receive. */
    fd_set fds;
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(dev->fd, &fds);
    int bytesRead = 0;
    while (bytesRead < respLen) {
        CDCFrame frame;
        int framePointer = 0;
        while (framePointer < CDC_FRAME_SZ) {
            CHECK_C (select(dev->fd + 1, &fds, NULL, NULL, &timeout) > 0);
            int numBytes = read(dev->fd, (uint8_t *)&frame + framePointer, CDC_FRAME_SZ);
            printf("current frame after receiving %d bytes: ", numBytes);
            for (int i = 0; i < CDC_FRAME_SZ; i++) {
                printf("%x", ((uint8_t *)&frame)[i]);
            }
            printf("\n");

            framePointer += numBytes;
        }
        if (frame.sessionNum != sessionNum) continue;
        if (respLen > 0) {
            int bytesToCopy = respLen - (frame.seqNo * CDC_PAYLOAD_SZ) < CDC_PAYLOAD_SZ ? respLen - (frame.seqNo * CDC_PAYLOAD_SZ) : CDC_PAYLOAD_SZ;
            memcpy(resp + frame.seqNo * CDC_PAYLOAD_SZ, frame.payload, bytesToCopy);
        }
        bytesRead = (frame.seqNo + 1) * CDC_PAYLOAD_SZ;
        printf("finished frame %d, read %d bytes\n", frame.seqNo, bytesRead);
    }
    dev->sessionCtr++;
cleanup:
    if (rv == ERROR) printf("Error in message exchange.\n");
    return rv;
}
