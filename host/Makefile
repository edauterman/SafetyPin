all: CryptoTest TreeBench RecoveryTest RecoveryBench PuncEncBench MicroBench ElGamalTest SaveBench LogTest BaselineBench MultisigTest LogEpochBench ReencryptBench

.PHONY: clean

clean:
	rm -f *.o

#CC ?= gcc
#CXX ?= g++
CC ?= clang
CXX ?= clang++
PKG_CONFIG ?= pkg-config

LEVELS=22

UNAME := $(shell uname)

ifeq ($(UNAME), Linux)

HIDAPI_PKG:=hidapi-hidraw
HIDAPI_LDLIBS:=$(shell $(PKG_CONFIG) --libs $(HIDAPI_PKG))
ifeq ($(HIDAPI_LDLIBS),)
# Use local source code
HIDAPI:=hid.o
HIDAPI_CPPFLAGS:=-Ihidapi/hidapi
HIDAPI_CFLAGS:=-Ihidapi/hidapi
hid.o: hidapi/linux/hid.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o hid.o hidapi/linux/hid.c

else
# Use hidapi library
HIDAPI:=
HIDAPI_CPPFLAGS:=$(shell $(PKG_CONFIG) --cflags-only-I $(HIDAPI_PKG))
endif # hidapi library

CPPFLAGS+=$(HIDAPI_CPPFLAGS) -D__OS_LINUX -Ijedi-pairing/include -fno-stack-protector -DLEVELS=$(LEVELS)
CFLAGS+=$(HIDAPI_CFLAGS) -D__OS_LINUX -Ijedi-pairing/include -fno-stack-protector -DLEVELS=$(LEVELS)
LDLIBS+=-lrt -ludev $(HIDAPI_LDLIBS) -Ljedi-pairing/pairing.a
endif  # Linux

ifeq ($(UNAME), Darwin)

CFLAGS+=-Ihidapi/hidapi -D__OS_MAC -Ijedi-pairing/include -DLEVELS=$(LEVELS) 
CPPFLAGS+=-Ihidapi/hidapi -D__OS_MAC -Ijedi-pairing/include  -DLEVELS=$(LEVELS) 
LDLIBS+=-framework IOKit -framework CoreFoundation -Ljedi-pairing/pairing.a
HIDAPI=hid.o
hid.o: hidapi/mac/hid.c
	$(CC) -c $(CFLAGS) -o hid.o hidapi/mac/hid.c

CPPFLAGS+=-std=c++11 -stdlib=libc++
endif  # Darwin

# utility tools.
u2f_util.o: u2f_util.cc u2f_util.h u2f.h u2f_hid.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) -Wall -o u2f_util.o u2f_util.cc

params.o: params.c params.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o params.o params.c -lssl -lcrypto -lpthread

ibe.o: ibe.c ibe.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o ibe.o ibe.c -lssl -lcrypto  -lpthread

shamir.o: shamir.cc shamir.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o shamir.o shamir.cc -lssl -lcrypto -lpthread

hsm.o: hsm.cc hsm.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o hsm.o hsm.cc -lssl -lcrypto -lpthread

punc_enc.o: punc_enc.c punc_enc.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o punc_enc.o punc_enc.c -lssl -lcrypto -lpthread

datacenter.o: datacenter.cc datacenter.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o datacenter.o datacenter.cc -lssl -lcrypto  -lpthread

usb.o: usb.cc usb.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o usb.o usb.cc -lssl -lcrypto -lpthread

elgamal.o: elgamal.cc elgamal.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o elgamal.o elgamal.cc -lssl -lcrypto -lpthread

elgamal_shamir.o: elgamal_shamir.cc elgamal_shamir.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o elgamal_shamir.o elgamal_shamir.cc -lssl -lcrypto -lpthread

log.o: log.cc log.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o log.o log.cc -lssl -lcrypto -lpthread

baseline.o: baseline.cc baseline.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o baseline.o baseline.cc -lssl -lcrypto -lpthread

multisig.o: multisig.cc multisig.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o multisig.o multisig.cc -lssl -lcrypto -lpthread

merkle_tree.o: merkle_tree.cc merkle_tree.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o merkle_tree.o merkle_tree.cc -lssl -lcrypto -lpthread

TreeTest: TreeTest.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o elgamal.o elgamal_shamir.o log.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

TreeBench: TreeBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o elgamal.o elgamal_shamir.o log.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

PuncEncBench: PuncEncBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o elgamal.o elgamal_shamir.o log.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

MicroBench: MicroBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o elgamal.o elgamal_shamir.o log.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

RecoveryTest: RecoveryTest.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o usb.o elgamal.o elgamal_shamir.o log.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

UsbTest: UsbTest.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -I/usr/local/include -I/usr/local/Cellar/libusb/1.0.23/include/ -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lusb-1.0 -lpthread

RecoveryBench: RecoveryBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o usb.o elgamal.o elgamal_shamir.o log.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

SaveBench: SaveBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o usb.o elgamal.o elgamal_shamir.o log.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

ElGamalTest: ElGamalTest.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o elgamal.o elgamal_shamir.o log.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

LogTest: LogTest.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o elgamal.o elgamal_shamir.o log.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

BaselineBench: BaselineBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o elgamal.o elgamal_shamir.o log.o baseline.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

MultisigTest: MultisigTest.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o elgamal.o elgamal_shamir.o log.o baseline.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

LogEpochBench: LogEpochBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o elgamal.o elgamal_shamir.o log.o baseline.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

ReencryptBench: ReencryptBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o elgamal.o elgamal_shamir.o log.o baseline.o multisig.o merkle_tree.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread

CryptoTest: CryptoTest.cc params.o ibe.o shamir.o usb.o elgamal.o elgamal_shamir.o multisig.o merkle_tree.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -Wall -o $@ $^ jedi-pairing/pairing.a $(LDLIBS) -lssl -lcrypto -lpthread
