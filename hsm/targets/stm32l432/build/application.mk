include build/common.mk

# ST related
SRC = src/main.c src/init.c src/redirect.c src/flash.c src/rng.c src/led.c src/device.c
SRC += src/fifo.c src/crypto.c src/attestation.c src/nfc.c src/ams.c src/sense.c
SRC += src/startup_stm32l432xx.s src/system_stm32l4xx.c
SRC += $(DRIVER_LIBS) $(USB_LIB)

# FIDO2 lib
SRC += ../../fido2/apdu.c ../../fido2/util.c ../../fido2/u2f.c ../../fido2/test_power.c
SRC += ../../fido2/stubs.c ../../fido2/log.c  ../../fido2/ctaphid.c  ../../fido2/ctap.c
SRC += ../../fido2/ctap_parse.c ../../fido2/main.c
SRC += ../../fido2/version.c
SRC += ../../fido2/data_migration.c
SRC += ../../fido2/extensions/extensions.c ../../fido2/extensions/solo.c
SRC += ../../fido2/extensions/wallet.c

# SafetyPin lib
SRC += ../../safetypin/hsm.c ../../safetypin/punc_enc.c ../../safetypin/ibe.c ../../safetypin/cdc.c  ../../safetypin/shamir.c ../../crypto/cifra/src/arm/unacl/scalarmult.c ../../safetypin/uECC.c ../../safetypin/elgamal.c ../../safetypin/log_proof.c ../../safetypin/multisig.c

# Crypto libs
SRC += ../../crypto/sha256/sha256.c ../../crypto/micro-ecc/uECC.c ../../crypto/tiny-AES-c/aes.c ../../crypto/cifra/src/aes.c ../../crypto/cifra/src/modes.c ../../crypto/cifra/src/gcm.c ../../crypto/cifra/src/gf128.c ../../crypto/cifra/src/ccm.c
SRC += ../../crypto/cifra/src/sha512.c ../../crypto/cifra/src/blockwise.c
#LDFLAGS += ../../crypto/jedi-pairing/pairing.a

OBJ1=$(SRC:.c=.o)
OBJ=$(OBJ1:.s=.o)

INC = -Isrc/ -Isrc/cmsis/ -Ilib/ -Ilib/usbd/ -I../../fido2/ -I../../fido2/extensions
INC += -I../../tinycbor/src -I../../crypto/sha256 -I../../crypto/micro-ecc
INC += -I../../crypto/tiny-AES-c
INC += -I../../crypto/cifra/src -I../../crypto/cifra/src/ext
INC += -I../../crypto/jedi-pairing/include

SEARCH=-L../../tinycbor/lib

ifndef LDSCRIPT
LDSCRIPT=linker/stm32l4xx.ld
endif

CFLAGS= $(INC)

TARGET=solo
HW=-mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb

# Solo or Nucleo board
CHIP=STM32L432xx

ifndef DEBUG
DEBUG=0
endif

DEFINES = -DDEBUG_LEVEL=$(DEBUG) -D$(CHIP) -DAES256=1  -DUSE_FULL_LL_DRIVER -DAPP_CONFIG=\"app.h\" $(EXTRA_DEFINES)

CFLAGS=$(INC) -c $(DEFINES)   -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -fdata-sections -ffunction-sections \
	-fomit-frame-pointer $(HW) -g $(VERSION_FLAGS)
LDFLAGS_LIB=$(HW) $(SEARCH) -specs=nano.specs  -specs=nosys.specs  -Wl,--gc-sections -lnosys -L../../crypto/jedi-pairing/pairing.a
LDFLAGS=$(HW) $(LDFLAGS_LIB) -T$(LDSCRIPT) -Wl,-Map=$(TARGET).map,--cref -Wl,-Bstatic -ltinycbor -Bstatic -L../../crypto/jedi-pairing/pairing.a -lm
#LDFLAGS=$(HW) $(LDFLAGS_LIB) -T$(LDSCRIPT) -Wl,-Map=$(TARGET).map,--cref -Wl,-Bstatic -ltinycbor -Bstatic

ECC_CFLAGS = $(CFLAGS) -DuECC_PLATFORM=5 -DuECC_OPTIMIZATION_LEVEL=4 -DuECC_SQUARE_FUNC=1 -DuECC_SUPPORT_COMPRESSED_POINT=0


.PRECIOUS: %.o

all: $(TARGET).elf
	$(SZ) $^

%.o: %.c
	$(CC) $^ $(HW)  -Os $(CFLAGS) $(LDFLAGS) -o $@

../../crypto/micro-ecc/uECC.o: ../../crypto/micro-ecc/uECC.c
	$(CC) $^ $(HW)  -O3 $(ECC_CFLAGS) -o $@

%.o: %.s
#	$(CC) $^ $(HW)  -Os $(CFLAGS) $(LDFLAGS) -o $@
	$(CC) $^ ../../crypto/jedi-pairing/pairing.a $(HW)  -Os $(CFLAGS) $(LDFLAGS) -o $@

%.elf: $(OBJ)
	#$(CC) $^ $(HW) $(LDFLAGS) -o $@
	$(CC) $^ ../../crypto/jedi-pairing/pairing.a $(HW) $(LDFLAGS) -o $@
	@echo "Built version: $(VERSION_FLAGS)"

%.hex: %.elf
	$(SZ) $^
	$(CP) -O ihex $^ $(TARGET).hex

clean:
	rm -f *.o src/*.o *.elf  bootloader/*.o $(OBJ)


cbor:
	cd ../../tinycbor/ && make clean
	cd ../../tinycbor/ && make CC="$(CC)" AR=$(AR) \
LDFLAGS="$(LDFLAGS_LIB)" \
CFLAGS="$(CFLAGS) -Os"
