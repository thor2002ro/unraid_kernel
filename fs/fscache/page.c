// SPDX-License-Identifier: GPL-2.0-or-later
/* Cache page management and data I/O routines
 *
 * Copyright (C) 2004-2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL PAGE
#include <linux/module.h>
#include <linux/fscache-cache.h>
#include <linux/buffer_head.h>
#include <linux/pagevec.h>
#include <linux/slab.h>
#include "internal.h"

/*
 * actually apply the changed attributes to a cache object
 */
static void fscache_attr_changed_op(struct fscache_operation *op)
{
	struct fscache_object *object = op->object;
	int ret;

	_enter("{OBJ%x OP%x}", object->debug_id, op->debug_id);

	fscache_stat(&fscache_n_attr_changed_calls);

	if (fscache_object_is_active(object)) {
		fscache_stat(&fscache_n_cop_attr_changed);
		ret = object->cache->ops->attr_changed(object);
		fscache_stat_d(&fscache_n_cop_attr_changed);
		if (ret < 0)
			fscache_abort_object(object);
		fscache_op_complete(op, ret < 0);
	} else {
		fscache_op_complete(op, true);
	}

	_leave("");
}

/*
 * notification that the attributes on an object have changed
 */
int __fscache_attr_changed(struct fscache_cookie *cookie)
{
	struct fscache_operation *op;
	struct fscache_object *object;
	bool wake_cookie = false;

	_enter("%p", cookie);

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);

	fscache_stat(&fscache_n_attr_changed);

	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (!op) {
		fscache_stat(&fscache_n_attr_changed_nomem);
		_leave(" = -ENOMEM");
		return -ENOMEM;
	}

	fscache_operation_init(cookie, op, fscache_attr_changed_op, NULL, NULL);
	trace_fscache_page_op(cookie, NULL, op, fscache_page_op_attr_changed);
	op->flags = FSCACHE_OP_ASYNC |
		(1 << FSCACHE_OP_EXCLUSIVE) |
		(1 << FSCACHE_OP_UNUSE_COOKIE);

	spin_lock(&cookie->lock);

	if (!fscache_cookie_enabled(cookie) ||
	    hlist_empty(&cookie->backing_objects))
		goto nobufs;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	__fscache_use_cookie(cookie);
	if (fscache_submit_exclusive_op(object, op) < 0)
		goto nobufs_dec;
	spin_unlock(&cookie->lock);
	fscache_stat(&fscache_n_attr_changed_ok);
	fscache_put_operation(op);
	_leave(" = 0");
	return 0;

nobufs_dec:
	wake_cookie = __fscache_unuse_cookie(cookie);
nobufs:
	spin_unlock(&cookie->lock);
	fscache_put_operation(op);
	if (wake_cookie)
		__fscache_wake_unused_cookie(cookie);
	fscache_stat(&fscache_n_attr_changed_nobufs);
	_leave(" = %d", -ENOBUFS);
	return -ENOBUFS;
}
EXPORT_SYMBOL(__fscache_attr_changed);

/*
 * wait for a deferred lookup to complete
 */
int fscache_wait_for_deferred_lookup(struct fscache_cookie *cookie)
{
	_enter("");

	if (!test_bit(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags)) {
		_leave(" = 0 [imm]");
		return 0;
	}

	fscache_stat(&fscache_n_retrievals_wait);

	if (wait_on_bit(&cookie->flags, FSCACHE_COOKIE_LOOKING_UP,
			TASK_INTERRUPTIBLE) != 0) {
		fscache_stat(&fscache_n_retrievals_intr);
		_leave(" = -ERESTARTSYS");
		return -ERESTARTSYS;
	}

	ASSERT(!test_bit(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags));

	smp_rmb();
	_leave(" = 0 [dly]");
	return 0;
}

/*
 * wait for an object to become active (or dead)
 */
int fscache_wait_for_operation_activation(struct fscache_object *object,
					  struct fscache_operation *op,
					  atomic_t *stat_op_waits,
					  atomic_t *stat_object_dead)
{
	int ret;

	if (!test_bit(FSCACHE_OP_WAITING, &op->flags))
		goto check_if_dead;

	_debug(">>> WT");
	if (stat_op_waits)
		fscache_stat(stat_op_waits);
	if (wait_on_bit(&op->flags, FSCACHE_OP_WAITING,
			TASK_INTERRUPTIBLE) != 0) {
		trace_fscache_op(object->cookie, op, fscache_op_signal);
		ret = fscache_cancel_op(op, false);
		if (ret == 0)
			return -ERESTARTSYS;

		/* it's been removed from the pending queue by another party,
		 * so we should get to run shortly */
		wait_on_bit(&op->flags, FSCACHE_OP_WAITING,
			    TASK_UNINTERRUPTIBLE);
	}
	_debug("<<< GO");

check_if_dead:
	if (op->state == FSCACHE_OP_ST_CANCELLED) {
		if (stat_object_dead)
			fscache_stat(stat_object_dead);
		_leave(" = -ENOBUFS [cancelled]");
		return -ENOBUFS;
	}
	if (unlikely(fscache_object_is_dying(object) ||
		     fscache_cache_is_broken(object))) {
		enum fscache_operation_state state = op->state;
		trace_fscache_op(object->cookie, op, fscache_op_signal);
		fscache_cancel_op(op, true);
		if (stat_object_dead)
			fscache_stat(stat_object_dead);
		_leave(" = -ENOBUFS [obj dead %d]", state);
		return -ENOBUFS;
	}
	return 0;
}
