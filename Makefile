# SPDX-License-Identifier: GPL-2.0+
# Top level Makefile for iferrmond

ifeq ("$(origin V)", "command line")
VERBOSE = $(V)
endif
ifndef VERBOSE
VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
endif

PREFIX?=/usr
LIBDIR?=$(PREFIX)/lib
KERNEL_INCLUDE?=/usr/include

SHARED_LIBS = y

DEFINES= -DRESOLVE_HOSTNAMES -DLIBDIR=\"$(LIBDIR)\"
ifneq ($(SHARED_LIBS),y)
DEFINES+= -DNO_SHARED_LIBS
endif

#options for mpls
ADDLIB+=mpls_ntop.o mpls_pton.o

CC := gcc
HOSTCC ?= $(CC)
DEFINES += -D_GNU_SOURCE
# Turn on transparent support for LFS
DEFINES += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CCOPTS = -O2 -pipe
WFLAGS := -Wall -Wstrict-prototypes  -Wmissing-prototypes
WFLAGS += -Wmissing-declarations -Wold-style-definition -Wformat=2

# Use (un-comment) only for Debugging purposes, not Production!
CCOPTS = -g -v -pipe -Xlinker -Map=iferrmond.map

CFLAGS := $(WFLAGS) $(CCOPTS) -I../include -I../include/uapi $(DEFINES) $(CFLAGS)
YACCFLAGS = -d -t -v

SUBDIRS=lib daemon 

LIBNETLINK=../lib/libutil.a ../lib/libnetlink.a
LDLIBS += $(LIBNETLINK)

all: config.mk
	@set -e; \
	for i in $(SUBDIRS); \
	do echo; echo $$i; $(MAKE) -C $$i; done

.PHONY: clean clobber distclean check cscope version

help:
	@echo "Make Targets:"
	@echo " all                 - build binaries"
	@echo " clean               - remove products of build"
	@echo " install             - install binaries on local machine"
	@echo " cscope              - build cscope database"
	@echo ""
	@echo "Make Arguments:"
	@echo " V=[0|1]             - set build verbosity level"

config.mk:
	sh configure $(KERNEL_INCLUDE)

install: all
	@for i in daemon;  do $(MAKE) -C $$i install; done

start: 
	@for i in daemon;  do $(MAKE) -C $$i start; done

uninstall: 
	@for i in daemon;  do $(MAKE) -C $$i uninstall; done

clean:
	@for i in $(SUBDIRS) ; \
	do $(MAKE) -C $$i clean; done

cscope:
	cscope -b -R -Iinclude -slib -sdaemon

.EXPORT_ALL_VARIABLES:
