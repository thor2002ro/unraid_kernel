// SPDX-License-Identifier: GPL-2.0-or-later
/* Cache data I/O routines
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define FSCACHE_DEBUG_LEVEL PAGE
#include <linux/module.h>
#define FSCACHE_USE_NEW_IO_API
#define FSCACHE_USE_FALLBACK_IO_API
#include <linux/fscache-cache.h>
#include <linux/uio.h>
#include <linux/bvec.h>
#include <linux/slab.h>
#include <linux/netfs.h>
#include "internal.h"

/*
 * Start a cache operation.
 * - we return:
 *   -ENOMEM	- out of memory, some pages may be being read
 *   -ERESTARTSYS - interrupted, some pages may be being read
 *   -ENOBUFS	- no backing object or space available in which to cache any
 *                pages not being read
 *   -ENODATA	- no data available in the backing object for some or all of
 *                the pages
 *   0		- dispatched a read on all pages
 */
int __fscache_begin_operation(struct netfs_cache_resources *cres,
			      struct fscache_cookie *cookie,
			      bool for_write)
{
	struct fscache_operation *op;
	struct fscache_object *object;
	bool wake_cookie = false;
	int ret;

	_enter("c=%08x", cres->debug_id);

	if (for_write)
		fscache_stat(&fscache_n_stores);
	else
		fscache_stat(&fscache_n_retrievals);

	if (hlist_empty(&cookie->backing_objects))
		goto nobufs;

	if (test_bit(FSCACHE_COOKIE_INVALIDATING, &cookie->flags)) {
		_leave(" = -ENOBUFS [invalidating]");
		return -ENOBUFS;
	}

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);

	if (fscache_wait_for_deferred_lookup(cookie) < 0)
		return -ERESTARTSYS;

	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (!op)
		return -ENOMEM;

	fscache_operation_init(cookie, op, NULL, NULL, NULL);
	op->flags = FSCACHE_OP_MYTHREAD |
		(1UL << FSCACHE_OP_WAITING) |
		(1UL << FSCACHE_OP_UNUSE_COOKIE);

	trace_fscache_page_op(cookie, NULL, op, fscache_page_op_retr_multi);

	spin_lock(&cookie->lock);

	if (!fscache_cookie_enabled(cookie) ||
	    hlist_empty(&cookie->backing_objects))
		goto nobufs_unlock;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	__fscache_use_cookie(cookie);
	atomic_inc(&object->n_reads);
	__set_bit(FSCACHE_OP_DEC_READ_CNT, &op->flags);

	if (fscache_submit_op(object, op) < 0)
		goto nobufs_unlock_dec;
	spin_unlock(&cookie->lock);

	/* we wait for the operation to become active, and then process it
	 * *here*, in this thread, and not in the thread pool */
	if (for_write) {
		fscache_stat(&fscache_n_store_ops);

		ret = fscache_wait_for_operation_activation(
			object, op,
			__fscache_stat(&fscache_n_store_op_waits),
			__fscache_stat(&fscache_n_stores_object_dead));
	} else {
		fscache_stat(&fscache_n_retrieval_ops);

		ret = fscache_wait_for_operation_activation(
			object, op,
			__fscache_stat(&fscache_n_retrieval_op_waits),
			__fscache_stat(&fscache_n_retrievals_object_dead));
	}
	if (ret < 0)
		goto error;

	/* ask the cache to honour the operation */
	ret = object->cache->ops->begin_operation(cres, op);

error:
	if (for_write) {
		if (ret == -ENOMEM)
			fscache_stat(&fscache_n_stores_oom);
		else if (ret == -ERESTARTSYS)
			fscache_stat(&fscache_n_stores_intr);
		else if (ret < 0)
			fscache_stat(&fscache_n_stores_nobufs);
		else
			fscache_stat(&fscache_n_stores_ok);
	} else {
		if (ret == -ENOMEM)
			fscache_stat(&fscache_n_retrievals_nomem);
		else if (ret == -ERESTARTSYS)
			fscache_stat(&fscache_n_retrievals_intr);
		else if (ret == -ENODATA)
			fscache_stat(&fscache_n_retrievals_nodata);
		else if (ret < 0)
			fscache_stat(&fscache_n_retrievals_nobufs);
		else
			fscache_stat(&fscache_n_retrievals_ok);
	}

	fscache_put_operation(op);
	_leave(" = %d", ret);
	return ret;

nobufs_unlock_dec:
	atomic_dec(&object->n_reads);
	wake_cookie = __fscache_unuse_cookie(cookie);
nobufs_unlock:
	spin_unlock(&cookie->lock);
	fscache_put_operation(op);
	if (wake_cookie)
		__fscache_wake_unused_cookie(cookie);
nobufs:
	if (for_write)
		fscache_stat(&fscache_n_stores_nobufs);
	else
		fscache_stat(&fscache_n_retrievals_nobufs);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}
EXPORT_SYMBOL(__fscache_begin_operation);

/*
 * Clean up an operation.
 */
static void fscache_end_operation(struct netfs_cache_resources *cres)
{
	cres->ops->end_operation(cres);
}

/*
 * Fallback page reading interface.
 */
int __fscache_fallback_read_page(struct fscache_cookie *cookie, struct page *page)
{
	struct netfs_cache_resources cres;
	struct iov_iter iter;
	struct bio_vec bvec[1];
	int ret;

	_enter("%lx", page->index);

	memset(&cres, 0, sizeof(cres));
	bvec[0].bv_page		= page;
	bvec[0].bv_offset	= 0;
	bvec[0].bv_len		= PAGE_SIZE;
	iov_iter_bvec(&iter, READ, bvec, ARRAY_SIZE(bvec), PAGE_SIZE);

	ret = fscache_begin_read_operation(&cres, cookie);
	if (ret < 0)
		return ret;

	ret = fscache_read(&cres, page_offset(page), &iter, NETFS_READ_HOLE_FAIL,
			   NULL, NULL);
	fscache_end_operation(&cres);
	_leave(" = %d", ret);
	return ret;
}
EXPORT_SYMBOL(__fscache_fallback_read_page);

/*
 * Fallback page writing interface.
 */
int __fscache_fallback_write_page(struct fscache_cookie *cookie, struct page *page)
{
	struct netfs_cache_resources cres;
	struct iov_iter iter;
	struct bio_vec bvec[1];
	int ret;

	_enter("%lx", page->index);

	memset(&cres, 0, sizeof(cres));
	bvec[0].bv_page		= page;
	bvec[0].bv_offset	= 0;
	bvec[0].bv_len		= PAGE_SIZE;
	iov_iter_bvec(&iter, WRITE, bvec, ARRAY_SIZE(bvec), PAGE_SIZE);

	ret = __fscache_begin_operation(&cres, cookie, true);
	if (ret < 0)
		return ret;

	ret = cres.ops->prepare_fallback_write(&cres, page_index(page));
	if (ret < 0)
		goto out;

	ret = fscache_write(&cres, page_offset(page), &iter, NULL, NULL);
out:
	fscache_end_operation(&cres);
	_leave(" = %d", ret);
	return ret;
}
EXPORT_SYMBOL(__fscache_fallback_write_page);
