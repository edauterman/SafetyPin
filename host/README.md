## Setup
1. `git clone https://github.com/signal11/hidapi`
2. `sudo apt-get install libudev-dev libcrypto++-dev libssl-dev`
3. In `jedi-pairing`, run `make`.
4. Set the `handles` array in `datacenter.cc` to the correct device names in `/dev/`.
4. Build with `make`. 

The original source of the `jedi-pairing` library is available [here](https://github.com/ucbrise/jedi-pairing). Some of the USB HID code is based on [u2f-ref-code](https://github.com/google/u2f-ref-code).

## Tests
`./ElGamalTest`
Tests Hashed-ElGamal encryption with HSM.

`./MultisigTest`
Tests aggregate signature scheme with HSM.

`./LogTest`
Tests verifying that a recovery attempt is correctly logged.

`./CryptoTest`
Tests native crypto.

`./RecoveryTest`
Tests entire recovery flow.

## Benchmarks
`./MicroBench`
Runs microbenchmarks on HSM, prints to debug interface in HID.

`./PuncEncBench`
Benchmarks puncturable encryption scheme.

`./TreeBench`
Benchmarks accessing and deleting leaf in puncturable encryption tree.

`./TreeBuildBench`
Benchmarks time to build puncturable encryption tree.

`./SaveBench`
Benchmarks time to generate a recovery ciphertext.

`./RecoveryBench`
Benchmarks entire recovery flow.

`./LogEpochBench`
Benchmarks time to verify log at end of an epoch.

## Notes

By default, the library runs using USB CDC for performance. To enable HID
for debugging purposes, uncomment `#define HID` in `hsm.h` (make sure the HID
interace is also enabled on the HSM). 
To turn on debug print statements, change `#define DEBUG` from 0 to 1 in `common.h`.
