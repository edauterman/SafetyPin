# SafetyPin

SafetyPin is a system for encrypted backups that provides a strong defense against hardware compromise. The system only requires users to remember a short PIN and defends against brute-force PIN-guessing attacks while protecting against an attacker that can adaptively compromise many hardware elements. 

The implementation is split into two components:
- **HSM**: The HSMs (hardware security modules) are used to store user secrets. We implement the HSM functionality on Solokeys.
- **Host**: The host is not run on any special hardware and simply coordinates the HSMs.

**WARNING**: This is an academic proof-of-concept prototype and has not received careful code review. This implementation is NOT ready for production use.

This prototype is released under the Apache v2 license (see [License](#license)).

## Setup
Follow the instructions for setup for the [host](host/README.md) and the [hsm](hsm/README.md). See instructions for running tests and benchmarks [here](host/README.md).

If you change any constants that are defined on both the host and the HSM, make sure to update the constants in both places.
Constants in `host/[hsm.h, datacenter.h]` and `solo/fido2/hsm.h` with the same name must have the same values.

The system can use USB CDC (faster, but no debugging console) or USB HID (slower but has debuggning option). To switch between HID and CDC, make sure that the `HID` constant is set or not set in `host/hsm.h`, `hsm/fido2/device.h`, and `hsm/targets/stm32l432`. Do not read from the debug serial port using another process (e.g. by running `solo monitor`) when in CDC mode.

## Hardware
This system uses the Solo Hacker available [here](https://solokeys.com/products/solo-hacker).
If using a large number of HSMs (e.g. 100), I recommend the USB PCIe Controller card available [here](https://www.bhphotovideo.com/c/product/1190384-REG/highpoint_ru1144d_rocketu_1144d_four_usb.html).

## Acknowledgements
The code for the HSMs was adapted from the [SoloKey project](https://github.com/solokeys/solo).
The original source of the `jedi-pairing` library is available [here](https://github.com/ucbrise/jedi-pairing). Some of the USB HID code is based on [u2f-ref-code](https://github.com/google/u2f-ref-code).

