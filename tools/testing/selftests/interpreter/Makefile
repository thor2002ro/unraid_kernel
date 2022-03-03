# SPDX-License-Identifier: GPL-2.0

CFLAGS += -Wall -O2 -I$(khdr_dir) $(KHDR_INCLUDES)
LDLIBS += -lcap

src_test := $(wildcard *_test.c)
TEST_GEN_PROGS := $(src_test:.c=)

KSFT_KHDR_INSTALL := 1
include ../lib.mk

khdr_dir = $(top_srcdir)/usr/include

$(khdr_dir)/asm-generic/unistd.h: khdr
	@:

$(khdr_dir)/linux/trusted-for.h: khdr
	@:

$(OUTPUT)/%_test: %_test.c $(khdr_dir)/asm-generic/unistd.h $(khdr_dir)/linux/trusted-for.h ../kselftest_harness.h
	$(LINK.c) $< $(LDLIBS) -o $@
