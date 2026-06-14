/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005-2026 Junjiro R. Okajima
 */

/*
 * simple read-write semaphore wrappers
 */

#ifndef __AUFS_RWSEM_H__
#define __AUFS_RWSEM_H__

#ifdef __KERNEL__

#include "debug.h"

/* in the future, the name 'au_rwsem' will be totally gone */
#define au_rwsem	rw_semaphore

/* to debug easier, do not make them inlined functions */
#ifndef CONFIG_PREEMPT_RT
#define AuRwMustNoWaiters(rw)	AuDebugOn(rwsem_is_contended(rw))
#else
AuStubVoid(AuRwMustNoWaiters, struct rw_semaphore *rw)
#endif

#ifdef CONFIG_LOCKDEP
/* rwsem_is_locked() is unusable */
#define AuRwMustReadLock(rw)	AuDebugOn(IS_ENABLED(CONFIG_LOCKDEP)	\
					  && !lockdep_recursing(current) \
					  && debug_locks		\
					  && !lockdep_is_held_type(rw, 1))
#define AuRwMustWriteLock(rw)	AuDebugOn(IS_ENABLED(CONFIG_LOCKDEP)	\
					  && !lockdep_recursing(current) \
					  && debug_locks		\
					  && !lockdep_is_held_type(rw, 0))
#define AuRwMustAnyLock(rw)	AuDebugOn(IS_ENABLED(CONFIG_LOCKDEP)	\
					  && !lockdep_recursing(current) \
					  && debug_locks		\
					  && !lockdep_is_held(rw))
#define AuRwDestroy(rw)		AuDebugOn(IS_ENABLED(CONFIG_LOCKDEP)	\
					  && !lockdep_recursing(current) \
					  && debug_locks		\
					  && lockdep_is_held(rw))
#else
AuStubVoid(AuRwMustReadLock, struct rw_semaphore *rw)
AuStubVoid(AuRwMustWriteLock, struct rw_semaphore *rw)
AuStubVoid(AuRwMustAnyLock, struct rw_semaphore *rw)
AuStubVoid(AuRwDestroy, struct rw_semaphore *rw)
#endif

#define au_rw_init(rw)	init_rwsem(rw)

#define au_rw_init_wlock(rw) do {		\
		au_rw_init(rw);			\
		down_write(rw);			\
	} while (0)

#define au_rw_init_wlock_nested(rw, lsc) do {	\
		au_rw_init(rw);			\
		down_write_nested(rw, lsc);	\
	} while (0)

#define au_rw_read_lock(rw)		down_read(rw)
#define au_rw_read_lock_nested(rw, lsc)	down_read_nested(rw, lsc)
#define au_rw_read_unlock(rw)		up_read(rw)
#define au_rw_dgrade_lock(rw)		downgrade_write(rw)
#define au_rw_write_lock(rw)		down_write(rw)
#define au_rw_write_lock_nested(rw, lsc) down_write_nested(rw, lsc)
#define au_rw_write_unlock(rw)		up_write(rw)
/* why is not _nested version defined? */
#define au_rw_read_trylock(rw)		down_read_trylock(rw)
#define au_rw_write_trylock(rw)		down_write_trylock(rw)

#endif /* __KERNEL__ */
#endif /* __AUFS_RWSEM_H__ */
