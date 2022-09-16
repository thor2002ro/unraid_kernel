/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _VDSO_LIB_GETRANDOM_H
#define _VDSO_LIB_GETRANDOM_H

#include <crypto/chacha.h>

struct vgetrandom_state {
	u64 last_reseed;
	unsigned long generation;
	union {
		struct {
			u8 key[CHACHA_KEY_SIZE];
			u8 batch[CHACHA_BLOCK_SIZE * 3 / 2];
		};
		u8 key_batch[CHACHA_BLOCK_SIZE * 2];
	};
	u8 pos;
	bool not_forked;
};

#endif /* _VDSO_LIB_GETRANDOM_H */
