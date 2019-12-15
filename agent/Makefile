# Copyright 2014 Google Inc. All rights reserved.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

all: list Test CryptoTest TreeTest RecoveryTest

CC ?= gcc
CXX ?= g++
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

CPPFLAGS+=-Ihidapi/hidapi -D__OS_MAC -Ijedi-pairing/include
LDLIBS+=-framework IOKit -framework CoreFoundation -Ljedi-pairing/pairing.a
HIDAPI=hid.o
hid.o: hidapi/mac/hid.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o hid.o hidapi/mac/hid.c

endif  # Darwin

# utility tools.
u2f_util.o: u2f_util.cc u2f_util.h u2f.h u2f_hid.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) -Wall -o u2f_util.o u2f_util.cc

params.o: params.c params.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o params.o params.c -lssl -lcrypto

ibe.o: ibe.c ibe.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o ibe.o ibe.c -lssl -lcrypto

shamir.o: shamir.c shamir.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o shamir.o shamir.c -lssl -lcrypto

hsm.o: hsm.cc hsm.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o hsm.o hsm.cc -lssl -lcrypto

datacenter.o: datacenter.cc datacenter.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o datacenter.o datacenter.cc -lssl -lcrypto

# simple hidapi tool to list devices to see paths.
list: list.c $(HIDAPI)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o $@ $^ $(LDLIBS)

TreeTest: TreeTest.cc hsm.o datacenter.o u2f_util.o params.o ibe.o shamir.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

RecoveryTest: RecoveryTest.cc hsm.o datacenter.o u2f_util.o params.o ibe.o shamir.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

Test: Test.cc hsm.o datacenter.o u2f_util.o params.o ibe.o shamir.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

CryptoTest: CryptoTest.cc params.o ibe.o shamir.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto
