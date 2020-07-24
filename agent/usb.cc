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
/*    tcflush(dev->fd, TCOFLUSH);
    tcflush(dev->fd, TCIFLUSH);

    cfsetispeed(&tty, B115200);
    //cfsetispeed(&tty, B9600);
    cfsetospeed(&tty, B115200);
    //cfsetospeed(&tty, B9600);
*/
    dev->sessionCtr = 0;
    printf("going to exchange with %s\n", handle);
    printf("fd = %d\n", dev->fd);
    if (dev->fd) UsbDevice_exchange(dev, HSM_RESET, NULL, 0, NULL, 0);
    printf("reset\n");

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
    if (dev->fd) UsbDevice_exchange(dev, HSM_RESET, NULL, 0, NULL, 0);
    if (dev->fd) close(dev->fd);
    free(dev);
}

int send(UsbDevice *dev, uint8_t msgType, uint8_t *req, int reqLen, bool isInitial) {
    int rv = OKAY;
    int bytesWritten = 0;
    int i = 0;
    uint8_t sessionNum = dev->sessionCtr;
    debug_print("sessionNum = %d\n", sessionNum);
    debug_print("req len = %d\n", reqLen);
    fd_set fds;
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(dev->fd, &fds);
    
    while (bytesWritten <= reqLen) {
        CDCFrame frame;
	memset((uint8_t *)&frame, 0, CDC_FRAME_SZ);
	int bytesToWrite = reqLen - bytesWritten < CDC_PAYLOAD_SZ ? reqLen - bytesWritten : CDC_PAYLOAD_SZ;
        memset(frame.payload, 0, CDC_PAYLOAD_SZ);
        if (reqLen > 0) {
            memcpy(frame.payload, req + bytesWritten, bytesToWrite);
        }
        frame.msgType = msgType;
        frame.seqNo = i;
        frame.sessionNum = sessionNum;
        debug_print("seqno =  %d\n", frame.seqNo);
        debug_print("sending frame: ");
        for (int i = 0; i < CDC_FRAME_SZ; i++) {
            debug_print("%x", ((uint8_t *)&frame)[i]);
        }
        debug_print("\n");
        int numSent = 0;
        while (numSent < CDC_FRAME_SZ) {
            FD_ZERO(&fds);
            FD_SET(dev->fd, &fds);
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
           
            debug_print("waiting to write seqno = %d\n", frame.seqNo); 
//            int selectRes = select(dev->fd + 1, NULL, &fds, NULL, &timeout);
    //        if (selectRes > 0) {
                numSent += write(dev->fd, (uint8_t *)&frame + numSent, CDC_FRAME_SZ - numSent);
                //tcdrain(dev->fd);
//                printf("numSent =  %d\n", numSent);
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
            // WAS COMMENTED IN (BELOW)
	    //tcflush(dev->fd, TCIFLUSH);
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

    // WAS COMMENTED IN (BELOW)
//    tcflush(dev->fd, TCIOFLUSH);
    /* Send. */
    send(dev, msgType, req, reqLen, true);

    /* Receive. */
//    if (msgType == HSM_DECRYPT) respLen = reqLen;
    fd_set fds;
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(dev->fd, &fds);
    uint8_t sessionNum = dev->sessionCtr;
    int bytesRead = 0;
    if (respLen == 0) rv = OKAY;
    debug_print("respLen = %d\n", respLen);
    while (bytesRead < respLen || respLen == 0) {
        CDCFrame frame;
        int framePointer = 0;
	int ctr = 0;
	while (framePointer < CDC_FRAME_SZ) {
            FD_ZERO(&fds);
            FD_SET(dev->fd, &fds);
    
            debug_print("bytesRead = %d, framePointer = %d\n", bytesRead, framePointer);
            int selectRes = select(dev->fd + 1, &fds, NULL, NULL, &timeout);
            if (selectRes <= 0) {
		if (ctr == 0) {
			printf("ERROR for fd %d, msg code %d, reqLen %d, framePtr = %d/64\n", dev->fd, msgType, reqLen, framePointer);
			if (msgType != HSM_LOG_ROOTS_PROOF) {
				printf("NOT TYPE LOG_ROOTS_PROOF\n");
			} else {
			HSM_LOG_ROOTS_PROOF_REQ *logReq = (HSM_LOG_ROOTS_PROOF_REQ *)req;
			printf("headOld: ");
			for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
				printf("%02x", logReq->headOld[i]);
			}
			printf("\n");
			printf("headNew: ");
			for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
				printf("%02x", logReq->headNew[i]);
			}
			printf("\n");
			printf("rootProofOld: ");
			for (int i = 0; i < MAX_PROOF_LEVELS; i++) {
				for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
					printf("%02x", logReq->rootProofOld[i][j]);
				}
				printf("    ");
			}
			printf("\n");
			printf("rootProofNew: ");
			for (int i = 0; i < MAX_PROOF_LEVELS; i++) {
				for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
					printf("%02x", logReq->rootProofNew[i][j]);
				}
				printf("    ");
			}
			printf("\n");
			printf("idsOld: ");
			for (int i = 0; i < MAX_PROOF_LEVELS; i++) {
				printf("%02x", logReq->idsOld[i]);
			}
			printf("\n");
			printf("idsNew: ");
			for (int i = 0; i < MAX_PROOF_LEVELS; i++) {
				printf("%02x", logReq->idsNew[i]);
			}
			printf("\n");
			printf("idNew: %d\n", logReq->idNew);
			printf("lenNew: %d\n", logReq->lenNew);
			printf("idOld: %d\n", logReq->idOld);
			printf("lenOld: %d\n", logReq->lenOld);
			}

		}
		ctr++;
                debug_print("*** SELECT ERR: %d\n", selectRes);
                // NEXT TWO LINES WERE IN
                //tcflush(dev->fd, TCIOFLUSH);
                //send(dev, msgType, req, reqLen, false);
                continue;
            }
            //if (selectRes <= 0) send(dev, msgType, req, reqLen, false);
            //if (selectRes <= 0) printf("*** just resent\n");
            //CHECK_C (selectRes > 0);
            debug_print("will read\n");
            int numBytes = read(dev->fd, (uint8_t *)&frame + framePointer, CDC_FRAME_SZ);
            debug_print("num bytes read: %d\n", numBytes);
            debug_print("current frame after receiving %d bytes: ", numBytes);
            for (int i = 0; i < CDC_FRAME_SZ; i++) {
	            debug_print("%x", ((uint8_t *)&frame)[i]);
            }
            debug_print("\n");

            framePointer += numBytes;
        }
        debug_print("received session num %d, should be %d\n", frame.sessionNum, sessionNum);
        debug_print("received frame with msgType %x, sessionNum %d, seqno %d: ", frame.msgType, frame.sessionNum, frame.seqNo);
        for (int i = 0; i < CDC_PAYLOAD_SZ; i++) {
            debug_print("%x", frame.payload[i]);
        }
        debug_print("\n");
        if (frame.sessionNum != sessionNum && frame.msgType != HSM_RESET) continue;
        if (respLen > 0) {
            int bytesToCopy = respLen - (frame.seqNo * CDC_PAYLOAD_SZ) < CDC_PAYLOAD_SZ ? respLen - (frame.seqNo * CDC_PAYLOAD_SZ) : CDC_PAYLOAD_SZ;
            memcpy(resp + frame.seqNo * CDC_PAYLOAD_SZ, frame.payload, bytesToCopy);
            //if (msgType != HSM_DECRYPT) memcpy(resp + frame.seqNo * CDC_PAYLOAD_SZ, frame.payload, bytesToCopy);
//            printf("copied %d bytes to %d seqno\n", bytesToCopy, frame.seqNo);
        }
        bytesRead = (frame.seqNo + 1) * CDC_PAYLOAD_SZ;
//        printf("new bytes read = %d from seqno %d\n", bytesRead, frame.seqNo);
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
