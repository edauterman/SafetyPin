#define uECC_arch_other 0
#define uECC_x86        1
#define uECC_x86_64     2
#define uECC_arm        3
#define uECC_arm_thumb  4
#define uECC_arm_thumb2 5
#define uECC_arm64      6
#define uECC_avr        7

ecc_platform=2

src = $(wildcard pc/*.c) $(wildcard fido2/*.c) $(wildcard fido2/extensions/*.c) \
	$(wildcard crypto/sha256/*.c) crypto/tiny-AES-c/aes.c

obj = $(src:.c=.o) crypto/micro-ecc/uECC.o

LIBCBOR = tinycbor/lib/libtinycbor.a

ifeq ($(shell uname -s),Darwin)
  export LDFLAGS = -Wl,-dead_strip
else
  export LDFLAGS = -Wl,--gc-sections
endif
LDFLAGS += $(LIBCBOR)

VERSION_FULL:=$(shell git describe)
VERSION:=$(shell python -c 'print("$(VERSION_FULL)".split("-")[0])')
VERSION_MAJ:=$(shell python -c 'print("$(VERSION)".split(".")[0])')
VERSION_MIN:=$(shell python -c 'print("$(VERSION)".split(".")[1])')
VERSION_PAT:=$(shell python -c 'print("$(VERSION)".split(".")[2])')

VERSION_FLAGS= -DSOLO_VERSION_MAJ=$(VERSION_MAJ) -DSOLO_VERSION_MIN=$(VERSION_MIN) \
	-DSOLO_VERSION_PATCH=$(VERSION_PAT) -DSOLO_VERSION=\"$(VERSION_FULL)\"

CFLAGS = -O2 -fdata-sections -ffunction-sections $(VERSION_FLAGS) -g

INCLUDES = -I./tinycbor/src -I./crypto/sha256 -I./crypto/micro-ecc/ -Icrypto/tiny-AES-c/ -I./fido2/ -I./pc -I./fido2/extensions
INCLUDES += -I./crypto/cifra/src

CFLAGS += $(INCLUDES)
# for crypto/tiny-AES-c
CFLAGS += -DAES256=1 -DAPP_CONFIG=\"app.h\" -DSOLO_EXPERIMENTAL=1

name = main

.PHONY: all $(LIBCBOR) black blackcheck cppcheck wink fido2-test clean full-clean travis test clean version
all: main

tinycbor/Makefile crypto/tiny-AES-c/aes.c:
	git submodule update --init

.PHONY: cbor
cbor: $(LIBCBOR)

$(LIBCBOR):
	cd tinycbor/ && $(MAKE) clean && $(MAKE)  LDFLAGS='' -j8

version:
	@git describe

test: venv
	$(MAKE) clean
	$(MAKE) -C . main
	$(MAKE) clean
	$(MAKE) -C ./targets/stm32l432 test PREFIX=$(PREFIX) "VENV=$(VENV)" VERSION_FULL=${VERSION_FULL}
	$(MAKE) clean
	$(MAKE) cppcheck

$(name): $(obj) $(LIBCBOR)
	$(CC) $(LDFLAGS) -o $@ $(obj) $(LDFLAGS)

crypto/micro-ecc/uECC.o: ./crypto/micro-ecc/uECC.c
	$(CC) -c -o $@ $^ -O2 -fdata-sections -ffunction-sections -DuECC_PLATFORM=$(ecc_platform) -I./crypto/micro-ecc/

venv:
	python3 -m venv venv
	venv/bin/pip -q install --upgrade pip
	venv/bin/pip -q install --upgrade -r tools/requirements.txt
	venv/bin/pip -q install --upgrade black

# selectively reformat our own code
black: venv
	venv/bin/black --skip-string-normalization --check tools/

wink: venv
	venv/bin/solo key wink

fido2-test: venv
	venv/bin/python tools/ctap_test.py

update:
	git fetch --tags
	git checkout master
	git rebase origin/master
	git submodule update --init --recursive

DOCKER_TOOLCHAIN_IMAGE := "solokeys/solo-firmware-toolchain"

docker-build-toolchain:
	docker build -t $(DOCKER_TOOLCHAIN_IMAGE) .
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${VERSION}
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${VERSION_MAJ}
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${VERSION_MAJ}.${VERSION_MIN}

uncached-docker-build-toolchain:
	docker build --no-cache -t $(DOCKER_TOOLCHAIN_IMAGE) .
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${VERSION}
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${VERSION_MAJ}
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${VERSION_MAJ}.${VERSION_MIN}

docker-build-all: 
	docker run --rm -v "$(CURDIR)/builds:/builds" \
					-v "$(CURDIR):/solo" \
				    $(DOCKER_TOOLCHAIN_IMAGE) "solo/in-docker-build.sh" ${VERSION_FULL}

CPPCHECK_FLAGS=--quiet --error-exitcode=2

cppcheck:
	cppcheck $(CPPCHECK_FLAGS) crypto/aes-gcm
	cppcheck $(CPPCHECK_FLAGS) crypto/sha256
	cppcheck $(CPPCHECK_FLAGS) fido2
	cppcheck $(CPPCHECK_FLAGS) pc

clean:
	rm -f *.o main.exe main $(obj)
	for f in crypto/tiny-AES-c/Makefile tinycbor/Makefile ; do \
	    if [ -f "$$f" ]; then \
	    	(cd `dirname $$f` ; git checkout -- .) ;\
	    fi ;\
	done

full-clean: clean
	rm -rf venv

test-docker:
	rm -rf builds/*
	$(MAKE) uncached-docker-build-toolchain
	# Check if there are 4 docker images/tas named "solokeys/solo-firmware-toolchain"
	NTAGS=$$(docker images | grep -c "solokeys/solo-firmware-toolchain") && [ $$NTAGS -eq 4 ]
	$(MAKE) docker-build-all

travis:
	$(MAKE) test VENV=". ../../venv/bin/activate;"
	$(MAKE) test-docker
	$(MAKE) black