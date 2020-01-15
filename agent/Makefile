# Copyright 2014 Google Inc. All rights reserved.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

all: list Test CryptoTest TreeTest TreeBench RecoveryTest RecoveryBench PuncEncBench MicroBench TreeBuildBench UsbTest PingBench

#CC ?= gcc
#CXX ?= g++
CC ?= clang
CXX ?= clang++
PKG_CONFIG ?= pkg-config

UNAME := $(shell uname)

ifeq ($(UNAME), Linux)

HIDAPI_PKG:=hidapi-hidraw
HIDAPI_LDLIBS:=$(shell $(PKG_CONFIG) --libs $(HIDAPI_PKG))
ifeq ($(HIDAPI_LDLIBS),)
# Use local source code
HIDAPI:=hid.o
HIDAPI_CPPFLAGS:=-Ihidapi/hidapi
hid.o: hidapi/linux/hid.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o hid.o hidapi/linux/hid.c

else
# Use hidapi library
HIDAPI:=
HIDAPI_CPPFLAGS:=$(shell $(PKG_CONFIG) --cflags-only-I $(HIDAPI_PKG))
endif # hidapi library

CPPFLAGS+=$(HIDAPI_CPPFLAGS) -D__OS_LINUX
LDLIBS+=-lrt -ludev $(HIDAPI_LDLIBS)
endif  # Linux

ifeq ($(UNAME), Darwin)

CFLAGS+=-Ihidapi/hidapi -D__OS_MAC -Ijedi-pairing/include
CPPFLAGS+=-Ihidapi/hidapi -D__OS_MAC -Ijedi-pairing/include
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
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o params.o params.c -lssl -lcrypto

ibe.o: ibe.c ibe.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o ibe.o ibe.c -lssl -lcrypto

shamir.o: shamir.c shamir.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o shamir.o shamir.c -lssl -lcrypto

hsm.o: hsm.cc hsm.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o hsm.o hsm.cc -lssl -lcrypto

punc_enc.o: punc_enc.c punc_enc.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o punc_enc.o punc_enc.c -lssl -lcrypto

datacenter.o: datacenter.cc datacenter.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o datacenter.o datacenter.cc -lssl -lcrypto

usb.o: usb.cc usb.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o usb.o usb.cc -lssl -lcrypto


# simple hidapi tool to list devices to see paths.
list: list.c $(HIDAPI)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -o $@ $^ $(LDLIBS)

TreeTest: TreeTest.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

TreeBench: TreeBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

TreeBuildBench: TreeBuildBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

PuncEncBench: PuncEncBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

MicroBench: MicroBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

RecoveryTest: RecoveryTest.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o usb.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

UsbTest: UsbTest.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) -I/usr/local/include -I/usr/local/Cellar/libusb/1.0.23/include/ jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto -lusb-1.0

RecoveryBench: RecoveryBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o usb.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

PingBench: PingBench.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o usb.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

Test: Test.cc hsm.o datacenter.o u2f_util.o params.o punc_enc.o ibe.o shamir.o punc_enc.o usb.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

CryptoTest: CryptoTest.cc params.o ibe.o shamir.o usb.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto
