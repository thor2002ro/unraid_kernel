#ifndef LINUX_ATOMIC_REF_H
#define LINUX_ATOMIC_REF_H

/*
 * Shamelessly stolen from the mm implementation of page reference checking,
 * see commit f958d7b528b1 for details.
 */
#define atomic_ref_zero_or_close_to_overflow(ref)	\
	((unsigned int) atomic_read(ref) + 127u <= 127u)

static inline bool atomic_ref_inc_not_zero(atomic_t *ref)
{
	return atomic_inc_not_zero(ref);
}

static inline bool atomic_ref_put_and_test(atomic_t *ref)
{
	WARN_ON_ONCE(atomic_ref_zero_or_close_to_overflow(ref));
	return atomic_dec_and_test(ref);
}

static inline void atomic_ref_put(atomic_t *ref)
{
	WARN_ON_ONCE(atomic_ref_put_and_test(ref));
}

static inline void atomic_ref_get(atomic_t *ref)
{
	WARN_ON_ONCE(atomic_ref_zero_or_close_to_overflow(ref));
	atomic_inc(ref);
}

#endif
