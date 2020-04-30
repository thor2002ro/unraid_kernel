#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

# Check whether the compiler tail-call optimizes across an asm() statement.
# Fail the build if it does.

echo "int foo(int a); int bar(int a) { int r = foo(a); asm(\"\"); return r; }" |\
	     $* -O2 -x c -c -S - -o - 2>/dev/null |\
	     grep -E "^[[:blank:]]+jmp[[:blank:]]+.*"
