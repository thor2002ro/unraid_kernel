// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/fs.h>
#include <vdso/datapage.h>
#include <asm/vdso/getrandom.h>
#include <asm/vdso/vsyscall.h>
#include "getrandom.h"

#undef memcpy
#define memcpy(d,s,l) __builtin_memcpy(d,s,l)
#undef memset
#define memset(d,c,l) __builtin_memset(d,c,l)

#define CHACHA_FOR_VDSO_INCLUDE
#include "../crypto/chacha.c"

static void memcpy_and_zero(void *dst, void *src, size_t len)
{
#define CASCADE(type) \
	while (len >= sizeof(type)) { \
		*(type *)dst = *(type *)src; \
		*(type *)src = 0; \
		dst += sizeof(type); \
		src += sizeof(type); \
		len -= sizeof(type); \
	}
#ifdef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#if BITS_PER_LONG == 64
	CASCADE(u64);
#endif
	CASCADE(u32);
	CASCADE(u16);
#endif
	CASCADE(u8);
#undef CASCADE
}

static __always_inline ssize_t
__cvdso_getrandom(void *buffer, size_t len, unsigned int flags, void *opaque_state)
{
	struct vgetrandom_state *state = opaque_state;
	const struct vdso_rng_data *rng_info = __arch_get_vdso_rng_data();
	const struct vdso_data *timebase = &__arch_get_vdso_data()[CS_HRES_COARSE];
	const struct vdso_timestamp *course_mono = &timebase->basetime[CLOCK_MONOTONIC_COARSE];
	u32 chacha_state[CHACHA_STATE_WORDS];
	ssize_t ret = min_t(size_t, MAX_RW_COUNT, len);
	size_t batch_len;

	if (unlikely(!rng_info->is_ready))
		return getrandom_syscall(buffer, len, flags);

	if (unlikely(!len))
		return 0;

	if (unlikely(!READ_ONCE(state->not_forked)))
		state->not_forked = true;

retry_generation:
	if (unlikely(state->generation != READ_ONCE(rng_info->generation) ||
		     /* 15 sec is crude approximation of crng_has_old_seed(). In the future,
		      * export this in rng_info->expiration, or similar. Needs improvement. */
		     READ_ONCE(course_mono->sec) - state->last_reseed > 15)) {
		if (getrandom_syscall(state->key, sizeof(state->key), 0) != sizeof(state->key))
			return getrandom_syscall(buffer, len, flags);
		/* We shouldn't be reading rng_info->generation afterwards, as technically it could
		 * be bumped in between these two lines. Instead this should be set to the value
		 * read in the `if ()` above. But in fact, the lazy semantics of generation bumping
		 * always make this happen. So live with this for now. Needs improvement. */
		state->generation = READ_ONCE(rng_info->generation);
		state->last_reseed = READ_ONCE(course_mono->sec);
		state->pos = sizeof(state->batch);
	}

	len = ret;
more_batch:
	batch_len = min_t(size_t, sizeof(state->batch) - state->pos, len);
	if (batch_len) {
		memcpy_and_zero(buffer, state->batch + state->pos, batch_len);
		state->pos += batch_len;
		buffer += batch_len;
		len -= batch_len;
	}
	if (!len) {
		if (unlikely(state->generation != READ_ONCE(rng_info->generation)))
			goto retry_generation;
		if (unlikely(!READ_ONCE(state->not_forked))) {
			state->not_forked = true;
			goto retry_generation;
		}
		return ret;
	}

	chacha_init_consts(chacha_state);
	memcpy(&chacha_state[4], state->key, CHACHA_KEY_SIZE);
	memset(&chacha_state[12], 0, sizeof(u32) * 4);

	while (len >= CHACHA_BLOCK_SIZE) {
		chacha20_block(chacha_state, buffer);
		if (unlikely(chacha_state[12] == 0))
			++chacha_state[13];
		buffer += CHACHA_BLOCK_SIZE;
		len -= CHACHA_BLOCK_SIZE;
	}

	chacha20_block(chacha_state, state->key_batch);
	if (unlikely(chacha_state[12] == 0))
		++chacha_state[13];
	chacha20_block(chacha_state, state->key_batch + CHACHA_BLOCK_SIZE);
	state->pos = 0;
	memzero_explicit(chacha_state, sizeof(chacha_state));
	goto more_batch;
}
