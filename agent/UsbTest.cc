#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>

#include <libusb-1.0/libusb.h>

void libusbSend() {
    int res;
    bool kernelDriverDetached = false;
    res = libusb_init(0);
    if (res != 0) {
        printf("error init libusb\n");
    }

    libusb_device_handle *handle = libusb_open_device_with_vid_pid(0, 0x0483, 0xa2ca);
    if (!handle) {
        printf("error with handle\n");
    }

    if (libusb_kernel_driver_active(handle, 0)) {
        printf("going to detach kernel driver\n");
        res =  libusb_detach_kernel_driver(handle, 0);
        if (res != 0) {
            printf("error detaching kernel driver\n");
        } else {
            kernelDriverDetached = true;
        }
    }

    res = libusb_claim_interface(handle, 0); //  0  for  in
    if (res != 0) {
        printf("error claiming interface, %d\n", res);
    }
    uint8_t buf[64];
    buf[58] = 0;
    buf[60] = 0x02;
    buf[61] = 0x0f;
    buf[62] = 0;

    int actual_len;
    res = libusb_bulk_transfer(handle, 2 | LIBUSB_ENDPOINT_OUT, buf, 64, &actual_len, 0);
    //res = libusb_bulk_transfer(handle, 0x82, buf, 64, &actual_len, 0);
    if (res != 0 || actual_len != 64) {
        printf("error with bulk transfer, only sent %d, res = %d\n", actual_len, res);
    }

    if (kernelDriverDetached) {
        libusb_attach_kernel_driver(handle, 0);
    }

    libusb_close(handle);
}

int main(int argc, char *argv[]) {
    const char *device = "/dev/cu.usbmodem208532CA31412";
    int fd =  open(device, O_RDWR |  O_NOCTTY);
    if (fd == -1) {
        printf("ERROR OPENING\n");
    }
    uint8_t msg[64];
    memset(msg, 0xff, sizeof(msg));
    if (write(fd, msg, sizeof(msg)) == -1)  {
        printf("error with write\n");
    }
    fd_set fds;
    struct timeval timeout;

    timeout.tv_sec = 5;
    timeout.tv_usec =  0;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
//    sleep(5);
    int selectRes =  select(fd + 1, &fds, NULL, NULL, &timeout);
    printf("selectRes = %d\n", selectRes);
    if (selectRes > 0) {
        int res = read(fd, msg, sizeof(msg));
        printf("res = %d\n", res);
    } else {
        printf("ERROR - timeout in read\n");
    }

    printf("msg received: ");
    for (int i = 0; i < sizeof(msg); i++) {
        printf("%x", msg[i]);
    }
    printf("\n");

    printf("done\n");
}
