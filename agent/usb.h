#ifndef __USB_H_INCLUDED__
#define __USB_H_INCLUDED__

#include <stdint.h>

#define CDC_FRAME_SZ 64
#define CDC_PAYLOAD_SZ 59

typedef struct {
    int fd;
    int sessionCtr;
} UsbDevice;

typedef struct {
    uint16_t discard;
    uint8_t msgType;
    uint8_t seqNo;
    uint8_t sessionNum;
    uint8_t payload[CDC_PAYLOAD_SZ];
} CDCFrame;

UsbDevice *UsbDevice_new(const char *handle);
void UsbDevice_free(UsbDevice *dev);

int UsbDevice_exchange(UsbDevice *dev, uint8_t msgType, uint8_t *req, int reqLen, uint8_t *resp, int respLen);
#endif
