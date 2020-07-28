# HSM 

The implementation for the HSM is built on [SoloKeys](https://solokeys.com). The code added to support the SafetyPin protocol is largely in `fido2/`. Instructions for setup and pointers to additional documentation from the original SoloKey README are included below.

To switch between USB CDC (faster but no debugging output) and USB HID (slower but has debugging support), comment or uncomment the `#define HID` in `fido2/device.h` and `targets/stm32l432/src/fifo.h`. With USB HID enabled, you can view debug statements by building with the option `build firmward-debug-2` and running `solo monitor` (after having installed the Solo develloper tools).

When testing and benchmarking, make sure to leave your firmware unlocked (otherwise you will never be able to load new code on to the key). If you find that a key is non-responsive in HID mode, try opening the serial port. If you find that a key is non-responsive and will not enter bootloader mode from the command line, remove the key, press and hold down the button, insert it into the USB port, and continue holding the button until a light begins to flash (the key has now booted in bootloader mode).

The Solo Hacker is available [here](https://solokeys.com/products/solo-hacker).
If using a large number of HSMs (e.g. 100), I recommend the USB PCIe Controller card available [here](https://www.bhphotovideo.com/c/product/1190384-REG/highpoint_ru1144d_rocketu_1144d_four_usb.html).


## Installing the toolchain

In order to compile ARM code, you need the ARM compiler and other things like bundling bootloader and firmware require the `solo-python` python package. Check our [documentation](https://docs.solokeys.io/solo/) for details

## Installing the toolkit and compiling in Docker 
Alternatively, you can use Docker to create a container with the toolchain.
You can run:

```bash
# Build the toolchain container
make docker-build-toolchain 

# Build all versions of the firmware in the "builds" folder
make docker-build-all
```

The `builds` folder will contain all the variation on the firmware in `.hex` files.

## Build locally

If you have the toolchain installed on your machine you can build the firmware with: 

```bash
cd targets/stm32l432
make cbor
make build-hacker       // alternatively, use make firmware-debug-2 to view debug statements
cd ../..

make venv
source venv/bin/activate
solo program aux enter-bootloader
solo program bootloader targets/stm32l432/solo.hex
```

Check out the [official documentation](https://docs.solokeys.io/solo/) for SoloKeys for more details.
