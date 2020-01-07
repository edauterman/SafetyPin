#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
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

    struct termios tty1;
    tcgetattr(0, &tty1);
    printf("baud rate in: %o\n", cfgetispeed(&tty1));
    printf("baud rate out: %o\n", cfgetospeed(&tty1));

    struct termios tty;
    tcgetattr(fd, &tty);
//    cfsetospeed(&tty, B9600);
    //if (cfsetospeed(&tty, cfgetispeed(&tty1)) < 0) printf("error setting out baudrate\n");
//    if (cfsetospeed(&tty, B115200) < 0) printf("error setting out baudrate\n");
//    cfsetispeed(&tty, B9600);
//    if (cfsetispeed(&tty, cfgetospeed(&tty1)) < 0) printf("error setting in baudrate\n");
//    if (cfsetispeed(&tty, B115200) < 0) printf("error setting in baudrate\n");

/*    tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;
    tty.c_iflag &= ~IGNBRK;
    tty.c_iflag = 0;
    tty.c_oflag = 0;

    tty.c_iflag &= ~(IXON | IXOFF | IXANY);
    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_cflag &= ~(PARENB | PARODD);
    tty.c_cflag &= CSTOPB;
    tty.c_cflag &= ~CRTSCTS;
*/

    tty.c_cflag |= (CLOCAL | CREAD);    /* ignore modem controls */
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;         /* 8-bit characters */
    tty.c_cflag &= ~PARENB;     /* no parity bit */
    tty.c_cflag &= ~CSTOPB;     /* only need 1 stop bit */
    tty.c_cflag &= ~CRTSCTS;    /* no hardware flowcontrol */

//    tty.c_cflag &= CS8 | ~PARENB;
    /* setup for non-canonical mode */
//    tty.c_iflag &= ~(ICRNL | IXON | IXANY | IMAXBEL | BRKINT);
    //tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
//    tty.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
    //tty.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    //tty.c_oflag &= ~(OPOST | ONLCR | OXTABS);
    //tty.c_cc[VMIN] = 1;
    //tty.c_cc[VTIME] = 1;
    if (tcsetattr(fd, TCSANOW, &tty) !=  0) {
        printf("error in tcsetattr\n");
    }
    tcflush(fd, TCOFLUSH);
    tcflush(fd, TCIFLUSH);


    uint8_t msg[1024];
    //uint8_t msg[1024];
//    memset(msg, 0xff, sizeof(msg));

    memset(msg, 0x11, 256);
    memset(msg + 256, 0x22, 256);
    memset(msg + 512, 0x33, 256);
    memset(msg + 768, 0x44, 256);

    printf("outgoing msg: ");
    for (int i = 0; i < sizeof(msg); i++) {
        if (i % 64 == 0) msg[i] = 0xff;
        if (i % 64 == 1) msg[i] = 0xff;
        if (i % 64 == 2) msg[i] = i/64;
        printf("%x", msg[i]);
    }
    printf("\n");

    int bytesWritten = 0;
    struct timeval t1, t2, t3, t4, t5;
    while (bytesWritten < sizeof(msg)) {
        //gettimeofday(&t1, NULL);
        int res = write(fd, msg + bytesWritten, sizeof(msg) - bytesWritten < 64 ? sizeof(msg) - bytesWritten : 64);
//        usleep(400);
        //gettimeofday(&t2, NULL);
        //printf("wrote %d bytes in %ld seconds, %d micros\n", res, t2.tv_sec - t1.tv_sec, t2.tv_usec - t1.tv_usec);
        bytesWritten += res;
    }
//    write(fd, msg, sizeof(msg));
    fd_set fds;
    struct timeval timeout;

    timeout.tv_sec = 5;
    timeout.tv_usec =  0;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
//    sleep(5);
    gettimeofday(&t3, NULL);
    int bytesRead = 0;
    //printf("selectRes = %d\n", selectRes);
    gettimeofday(&t4, NULL);

    while (bytesRead < sizeof(msg)) {
        int selectRes =  select(fd + 1, &fds, NULL, NULL, &timeout);
        if (selectRes <= 0) printf("error with select: %d\n", selectRes);
        //int res = read(fd, msg + bytesRead, sizeof(msg) - bytesRead  < 64 ? sizeof(msg) - bytesRead : 64);
        int res = read(fd, msg + bytesRead, sizeof(msg) - bytesRead < 64 ? sizeof(msg) - bytesRead : 64);
        printf("res = %d\n", res);
        //if (res <= 0) printf("reading err: res = %d\n", res);
        bytesRead += res;
    }
    gettimeofday(&t5, NULL);
    printf("time to read: %ld seconds, %d micros\n", t5.tv_sec - t4.tv_sec, t5.tv_usec - t4.tv_usec);
    printf("total time to read (with wait): %ld seconds, %d micros\n", t5.tv_sec - t3.tv_sec, t5.tv_usec - t3.tv_usec);

    printf("msg received: ");
    for (int i = 0; i < sizeof(msg); i++) {
        if ((i % 64 != 0) && (i % 64 != 1)) printf("%x", msg[i]);
    }
    printf("\n");

/*    selectRes =  select(fd + 1, &fds, NULL, NULL, &timeout);
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
*/


    printf("done\n");
    close(fd);
}
