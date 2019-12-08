# Copyright 2014 Google Inc. All rights reserved.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

all: list Test IBETest

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

sig_parse.o: sig_parse.c sig_parse.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o sig_parse.o sig_parse.c -lssl -lcrypto

params.o: params.c params.h
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o params.o params.c -lssl -lcrypto

asn1.o: asn1.c asn1.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o asn1.o asn1.c -lssl -lcrypto

base64.o: base64.c base64.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o base64.o base64.c -lssl -lcrypto

ibe.o: ibe.c ibe.h
	$(CXX) -c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o ibe.o ibe.c -lssl -lcrypto


# simple hidapi tool to list devices to see paths.
list: list.c $(HIDAPI)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -Wall -o $@ $^ $(LDLIBS)

# Test counter
Test: Test.cc agent.o u2f_util.o sig_parse.o params.o asn1.o ibe.o $(HIDAPI)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto

IBETest: IBETest.cc params.o ibe.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) jedi-pairing/pairing.a -Wall -o $@ $^ $(LDLIBS) -lssl -lcrypto
