# SafetyPin

These instructions are for setting up your own SafetyPin evaluation and NOT for artifact evaluation.

## Setup
Follow the instructions for setup for the [host](host/) and the [hsm](hsm/). See instructions for running tests and benchmarks [here](host/).

If you change any constants that are defined on both the host and the HSM, make sure to update the constants in both places.
Constants in `host/[hsm.h, datacenter.h]` and `solo/fido2/hsm.h` with the same name must have the same values.

The system can use USB CDC (faster, but no debugging console) or USB HID (slower but has debuggning option). To switch between HID and CDC, make sure that the `HID` constant is set or not set in `host/hsm.h`, `hsm/fido2/device.h`, and `hsm/targets/stm32l432`. Do not read from the debug serial port using another process (e.g. by running `solo monitor`) when in CDC mode.

## Hardware
This system uses the Solo Hacker available [here](https://solokeys.com/products/solo-hacker).
If using a large number of HSMs (e.g. 100), I recommend the USB PCIe Controller card available [here](https://www.bhphotovideo.com/c/product/1190384-REG/highpoint_ru1144d_rocketu_1144d_four_usb.html).

