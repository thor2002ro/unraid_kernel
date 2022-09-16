// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */
#include <linux/kernel.h>
#include <linux/types.h>

#include "../../../../lib/vdso/getrandom.c"

ssize_t __vdso_getrandom(void *buffer, size_t len, unsigned int flags, void *state)
{
	return __cvdso_getrandom(buffer, len, flags, state);
}

ssize_t getrandom(void *, size_t, unsigned int, void *)
	__attribute__((weak, alias("__vdso_getrandom")));
