// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2010 Red Hat, Inc. All Rights Reserved.
 */

#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_shared.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_extent_busy.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"
#include "xfs_log.h"
#include "xfs_log_priv.h"
#include "xfs_trace.h"

struct workqueue_struct *xfs_discard_wq;

/*
 * Allocate a new ticket. Failing to get a new ticket makes it really hard to
 * recover, so we don't allow failure here. Also, we allocate in a context that
 * we don't want to be issuing transactions from, so we need to tell the
 * allocation code this as well.
 *
 * We don't reserve any space for the ticket - we are going to steal whatever
 * space we require from transactions as they commit. To ensure we reserve all
 * the space required, we need to set the current reservation of the ticket to
 * zero so that we know to steal the initial transaction overhead from the
 * first transaction commit.
 */
static struct xlog_ticket *
xlog_cil_ticket_alloc(
	struct xlog	*log)
{
	struct xlog_ticket *tic;

	tic = xlog_ticket_alloc(log, 0, 1, 0);

	/*
	 * set the current reservation to zero so we know to steal the basic
	 * transaction overhead reservation from the first transaction commit.
	 */
	tic->t_curr_res = 0;
	tic->t_iclog_hdrs = 0;
	return tic;
}

static inline void
xlog_cil_set_iclog_hdr_count(struct xfs_cil *cil)
{
	struct xlog	*log = cil->xc_log;

	atomic_set(&cil->xc_iclog_hdrs,
		   (XLOG_CIL_BLOCKING_SPACE_LIMIT(log) /
			(log->l_iclog_size - log->l_iclog_hsize)));
}

/*
 * Unavoidable forward declaration - xlog_cil_push_work() calls
 * xlog_cil_ctx_alloc() itself.
 */
static void xlog_cil_push_work(struct work_struct *work);

static struct xfs_cil_ctx *
xlog_cil_ctx_alloc(void)
{
	struct xfs_cil_ctx	*ctx;

	ctx = kmem_zalloc(sizeof(*ctx), KM_NOFS);
	INIT_LIST_HEAD(&ctx->committing);
	INIT_LIST_HEAD(&ctx->busy_extents);
	INIT_LIST_HEAD(&ctx->log_items);
	INIT_LIST_HEAD(&ctx->lv_chain);
	INIT_WORK(&ctx->push_work, xlog_cil_push_work);
	return ctx;
}

/*
 * Aggregate the CIL per cpu structures into global counts, lists, etc and
 * clear the percpu state ready for the next context to use.
 */
static void
xlog_cil_pcp_aggregate(
	struct xfs_cil		*cil,
	struct xfs_cil_ctx	*ctx)
{
	struct xlog_cil_pcp	*cilpcp;
	int			cpu;

	for_each_online_cpu(cpu) {
		cilpcp = per_cpu_ptr(cil->xc_pcp, cpu);

		ctx->ticket->t_curr_res += cilpcp->space_reserved;
		ctx->ticket->t_unit_res += cilpcp->space_reserved;
		cilpcp->space_reserved = 0;

		if (!list_empty(&cilpcp->busy_extents)) {
			list_splice_init(&cilpcp->busy_extents,
					&ctx->busy_extents);
		}
		if (!list_empty(&cilpcp->log_items))
			list_splice_init(&cilpcp->log_items, &ctx->log_items);

		/*
		 * We're in the middle of switching cil contexts.  Reset the
		 * counter we use to detect when the current context is nearing
		 * full.
		 */
		cilpcp->space_used = 0;
	}
}

static void
xlog_cil_ctx_switch(
	struct xfs_cil		*cil,
	struct xfs_cil_ctx	*ctx)
{
	xlog_cil_set_iclog_hdr_count(cil);
	set_bit(XLOG_CIL_EMPTY, &cil->xc_flags);
	ctx->sequence = ++cil->xc_current_sequence;
	ctx->cil = cil;
	cil->xc_ctx = ctx;
}

/*
 * After the first stage of log recovery is done, we know where the head and
 * tail of the log are. We need this log initialisation done before we can
 * initialise the first CIL checkpoint context.
 *
 * Here we allocate a log ticket to track space usage during a CIL push.  This
 * ticket is passed to xlog_write() directly so that we don't slowly leak log
 * space by failing to account for space used by log headers and additional
 * region headers for split regions.
 */
void
xlog_cil_init_post_recovery(
	struct xlog	*log)
{
	log->l_cilp->xc_ctx->ticket = xlog_cil_ticket_alloc(log);
	log->l_cilp->xc_ctx->sequence = 1;
	xlog_cil_set_iclog_hdr_count(log->l_cilp);
}

static inline int
xlog_cil_iovec_space(
	uint	niovecs)
{
	return round_up((sizeof(struct xfs_log_vec) +
					niovecs * sizeof(struct xfs_log_iovec)),
			sizeof(uint64_t));
}

/*
 * Allocate or pin log vector buffers for CIL insertion.
 *
 * The CIL currently uses disposable buffers for copying a snapshot of the
 * modified items into the log during a push. The biggest problem with this is
 * the requirement to allocate the disposable buffer during the commit if:
 *	a) does not exist; or
 *	b) it is too small
 *
 * If we do this allocation within xlog_cil_insert_format_items(), it is done
 * under the xc_ctx_lock, which means that a CIL push cannot occur during
 * the memory allocation. This means that we have a potential deadlock situation
 * under low memory conditions when we have lots of dirty metadata pinned in
 * the CIL and we need a CIL commit to occur to free memory.
 *
 * To avoid this, we need to move the memory allocation outside the
 * xc_ctx_lock, but because the log vector buffers are disposable, that opens
 * up a TOCTOU race condition w.r.t. the CIL committing and removing the log
 * vector buffers between the check and the formatting of the item into the
 * log vector buffer within the xc_ctx_lock.
 *
 * Because the log vector buffer needs to be unchanged during the CIL push
 * process, we cannot share the buffer between the transaction commit (which
 * modifies the buffer) and the CIL push context that is writing the changes
 * into the log. This means skipping preallocation of buffer space is
 * unreliable, but we most definitely do not want to be allocating and freeing
 * buffers unnecessarily during commits when overwrites can be done safely.
 *
 * The simplest solution to this problem is to allocate a shadow buffer when a
 * log item is committed for the second time, and then to only use this buffer
 * if necessary. The buffer can remain attached to the log item until such time
 * it is needed, and this is the buffer that is reallocated to match the size of
 * the incoming modification. Then during the formatting of the item we can swap
 * the active buffer with the new one if we can't reuse the existing buffer. We
 * don't free the old buffer as it may be reused on the next modification if
 * it's size is right, otherwise we'll free and reallocate it at that point.
 *
 * This function builds a vector for the changes in each log item in the
 * transaction. It then works out the length of the buffer needed for each log
 * item, allocates them and attaches the vector to the log item in preparation
 * for the formatting step which occurs under the xc_ctx_lock.
 *
 * While this means the memory footprint goes up, it avoids the repeated
 * alloc/free pattern that repeated modifications of an item would otherwise
 * cause, and hence minimises the CPU overhead of such behaviour.
 */
static void
xlog_cil_alloc_shadow_bufs(
	struct xlog		*log,
	struct xfs_trans	*tp)
{
	struct xfs_log_item	*lip;

	list_for_each_entry(lip, &tp->t_items, li_trans) {
		struct xfs_log_vec *lv;
		int	niovecs = 0;
		int	nbytes = 0;
		int	buf_size;
		bool	ordered = false;

		/* Skip items which aren't dirty in this transaction. */
		if (!test_bit(XFS_LI_DIRTY, &lip->li_flags))
			continue;

		/* get number of vecs and size of data to be stored */
		lip->li_ops->iop_size(lip, &niovecs, &nbytes);

		/*
		 * Ordered items need to be tracked but we do not wish to write
		 * them. We need a logvec to track the object, but we do not
		 * need an iovec or buffer to be allocated for copying data.
		 */
		if (niovecs == XFS_LOG_VEC_ORDERED) {
			ordered = true;
			niovecs = 0;
			nbytes = 0;
		}

		/*
		 * We 64-bit align the length of each iovec so that the start of
		 * the next one is naturally aligned.  We'll need to account for
		 * that slack space here.
		 *
		 * We also add the xlog_op_header to each region when
		 * formatting, but that's not accounted to the size of the item
		 * at this point. Hence we'll need an addition number of bytes
		 * for each vector to hold an opheader.
		 *
		 * Then round nbytes up to 64-bit alignment so that the initial
		 * buffer alignment is easy to calculate and verify.
		 */
		nbytes += niovecs *
			(sizeof(uint64_t) + sizeof(struct xlog_op_header));
		nbytes = round_up(nbytes, sizeof(uint64_t));

		/*
		 * The data buffer needs to start 64-bit aligned, so round up
		 * that space to ensure we can align it appropriately and not
		 * overrun the buffer.
		 */
		buf_size = nbytes + xlog_cil_iovec_space(niovecs);

		/*
		 * if we have no shadow buffer, or it is too small, we need to
		 * reallocate it.
		 */
		if (!lip->li_lv_shadow ||
		    buf_size > lip->li_lv_shadow->lv_size) {

			/*
			 * We free and allocate here as a realloc would copy
			 * unnecessary data. We don't use kmem_zalloc() for the
			 * same reason - we don't need to zero the data area in
			 * the buffer, only the log vector header and the iovec
			 * storage.
			 */
			kmem_free(lip->li_lv_shadow);

			lv = kmem_alloc_large(buf_size, KM_NOFS);
			memset(lv, 0, xlog_cil_iovec_space(niovecs));

			INIT_LIST_HEAD(&lv->lv_list);
			lv->lv_item = lip;
			lv->lv_size = buf_size;
			if (ordered)
				lv->lv_buf_len = XFS_LOG_VEC_ORDERED;
			else
				lv->lv_iovecp = (struct xfs_log_iovec *)&lv[1];
			lip->li_lv_shadow = lv;
		} else {
			/* same or smaller, optimise common overwrite case */
			lv = lip->li_lv_shadow;
			if (ordered)
				lv->lv_buf_len = XFS_LOG_VEC_ORDERED;
			else
				lv->lv_buf_len = 0;
			lv->lv_bytes = 0;
		}

		/* Ensure the lv is set up according to ->iop_size */
		lv->lv_niovecs = niovecs;

		/* The allocated data region lies beyond the iovec region */
		lv->lv_buf = (char *)lv + xlog_cil_iovec_space(niovecs);
	}

}

/*
 * Prepare the log item for insertion into the CIL. Calculate the difference in
 * log space it will consume, and if it is a new item pin it as well.
 */
STATIC void
xfs_cil_prepare_item(
	struct xlog		*log,
	struct xfs_log_vec	*lv,
	struct xfs_log_vec	*old_lv,
	int			*diff_len)
{
	/* Account for the new LV being passed in */
	if (lv->lv_buf_len != XFS_LOG_VEC_ORDERED)
		*diff_len += lv->lv_bytes;

	/*
	 * If there is no old LV, this is the first time we've seen the item in
	 * this CIL context and so we need to pin it. If we are replacing the
	 * old_lv, then remove the space it accounts for and make it the shadow
	 * buffer for later freeing. In both cases we are now switching to the
	 * shadow buffer, so update the pointer to it appropriately.
	 */
	if (!old_lv) {
		if (lv->lv_item->li_ops->iop_pin)
			lv->lv_item->li_ops->iop_pin(lv->lv_item);
		lv->lv_item->li_lv_shadow = NULL;
	} else if (old_lv != lv) {
		ASSERT(lv->lv_buf_len != XFS_LOG_VEC_ORDERED);

		*diff_len -= old_lv->lv_bytes;
		lv->lv_item->li_lv_shadow = old_lv;
	}

	/* attach new log vector to log item */
	lv->lv_item->li_lv = lv;

	/*
	 * If this is the first time the item is being committed to the
	 * CIL, store the sequence number on the log item so we can
	 * tell in future commits whether this is the first checkpoint
	 * the item is being committed into.
	 */
	if (!lv->lv_item->li_seq)
		lv->lv_item->li_seq = log->l_cilp->xc_ctx->sequence;
}

/*
 * Format log item into a flat buffers
 *
 * For delayed logging, we need to hold a formatted buffer containing all the
 * changes on the log item. This enables us to relog the item in memory and
 * write it out asynchronously without needing to relock the object that was
 * modified at the time it gets written into the iclog.
 *
 * This function takes the prepared log vectors attached to each log item, and
 * formats the changes into the log vector buffer. The buffer it uses is
 * dependent on the current state of the vector in the CIL - the shadow lv is
 * guaranteed to be large enough for the current modification, but we will only
 * use that if we can't reuse the existing lv. If we can't reuse the existing
 * lv, then simple swap it out for the shadow lv. We don't free it - that is
 * done lazily either by th enext modification or the freeing of the log item.
 *
 * We don't set up region headers during this process; we simply copy the
 * regions into the flat buffer. We can do this because we still have to do a
 * formatting step to write the regions into the iclog buffer.  Writing the
 * ophdrs during the iclog write means that we can support splitting large
 * regions across iclog boundares without needing a change in the format of the
 * item/region encapsulation.
 *
 * Hence what we need to do now is change the rewrite the vector array to point
 * to the copied region inside the buffer we just allocated. This allows us to
 * format the regions into the iclog as though they are being formatted
 * directly out of the objects themselves.
 */
static void
xlog_cil_insert_format_items(
	struct xlog		*log,
	struct xfs_trans	*tp,
	int			*diff_len)
{
	struct xfs_log_item	*lip;

	/* Bail out if we didn't find a log item.  */
	if (list_empty(&tp->t_items)) {
		ASSERT(0);
		return;
	}

	list_for_each_entry(lip, &tp->t_items, li_trans) {
		struct xfs_log_vec *lv;
		struct xfs_log_vec *old_lv = NULL;
		struct xfs_log_vec *shadow;
		bool	ordered = false;

		/* Skip items which aren't dirty in this transaction. */
		if (!test_bit(XFS_LI_DIRTY, &lip->li_flags))
			continue;

		/*
		 * The formatting size information is already attached to
		 * the shadow lv on the log item.
		 */
		shadow = lip->li_lv_shadow;
		if (shadow->lv_buf_len == XFS_LOG_VEC_ORDERED)
			ordered = true;

		/* Skip items that do not have any vectors for writing */
		if (!shadow->lv_niovecs && !ordered)
			continue;

		/* compare to existing item size */
		old_lv = lip->li_lv;
		if (lip->li_lv && shadow->lv_size <= lip->li_lv->lv_size) {
			/* same or smaller, optimise common overwrite case */
			lv = lip->li_lv;

			if (ordered)
				goto insert;

			/*
			 * set the item up as though it is a new insertion so
			 * that the space reservation accounting is correct.
			 */
			*diff_len -= lv->lv_bytes;

			/* Ensure the lv is set up according to ->iop_size */
			lv->lv_niovecs = shadow->lv_niovecs;

			/* reset the lv buffer information for new formatting */
			lv->lv_buf_len = 0;
			lv->lv_bytes = 0;
			lv->lv_buf = (char *)lv +
					xlog_cil_iovec_space(lv->lv_niovecs);
		} else {
			/* switch to shadow buffer! */
			lv = shadow;
			lv->lv_item = lip;
			if (ordered) {
				/* track as an ordered logvec */
				ASSERT(lip->li_lv == NULL);
				goto insert;
			}
		}

		ASSERT(IS_ALIGNED((unsigned long)lv->lv_buf, sizeof(uint64_t)));
		lip->li_ops->iop_format(lip, lv);
insert:
		xfs_cil_prepare_item(log, lv, old_lv, diff_len);
	}
}

/*
 * Insert the log items into the CIL and calculate the difference in space
 * consumed by the item. Add the space to the checkpoint ticket and calculate
 * if the change requires additional log metadata. If it does, take that space
 * as well. Remove the amount of space we added to the checkpoint ticket from
 * the current transaction ticket so that the accounting works out correctly.
 */
static void
xlog_cil_insert_items(
	struct xlog		*log,
	struct xfs_trans	*tp)
{
	struct xfs_cil		*cil = log->l_cilp;
	struct xfs_cil_ctx	*ctx = cil->xc_ctx;
	struct xfs_log_item	*lip;
	int			len = 0;
	int			iovhdr_res = 0, split_res = 0, ctx_res = 0;
	int			space_used;
	int			order;
	struct xlog_cil_pcp	*cilpcp;

	ASSERT(tp);

	/*
	 * We can do this safely because the context can't checkpoint until we
	 * are done so it doesn't matter exactly how we update the CIL.
	 */
	xlog_cil_insert_format_items(log, tp, &len);

	/*
	 * We need to take the CIL checkpoint unit reservation on the first
	 * commit into the CIL. Test the XLOG_CIL_EMPTY bit first so we don't
	 * unnecessarily do an atomic op in the fast path here. We can clear the
	 * XLOG_CIL_EMPTY bit as we are under the xc_ctx_lock here and that
	 * needs to be held exclusively to reset the XLOG_CIL_EMPTY bit.
	 */
	if (test_bit(XLOG_CIL_EMPTY, &cil->xc_flags) &&
	    test_and_clear_bit(XLOG_CIL_EMPTY, &cil->xc_flags))
		ctx_res = ctx->ticket->t_unit_res;

	/*
	 * Check if we need to steal iclog headers. atomic_read() is not a
	 * locked atomic operation, so we can check the value before we do any
	 * real atomic ops in the fast path. If we've already taken the CIL unit
	 * reservation from this commit, we've already got one iclog header
	 * space reserved so we have to account for that otherwise we risk
	 * overrunning the reservation on this ticket.
	 *
	 * If the CIL is already at the hard limit, we might need more header
	 * space that originally reserved. So steal more header space from every
	 * commit that occurs once we are over the hard limit to ensure the CIL
	 * push won't run out of reservation space.
	 *
	 * This can steal more than we need, but that's OK.
	 */
	space_used = atomic_read(&ctx->space_used);
	if (atomic_read(&cil->xc_iclog_hdrs) > 0 ||
	    space_used + len >= XLOG_CIL_BLOCKING_SPACE_LIMIT(log)) {
		int	split_res = log->l_iclog_hsize +
					sizeof(struct xlog_op_header);
		if (ctx_res)
			ctx_res += split_res * (tp->t_ticket->t_iclog_hdrs - 1);
		else
			ctx_res = split_res * tp->t_ticket->t_iclog_hdrs;
		atomic_sub(tp->t_ticket->t_iclog_hdrs, &cil->xc_iclog_hdrs);
	}

	/*
	 * Update the CIL percpu pointer. This updates the global counter when
	 * over the percpu batch size or when the CIL is over the space limit.
	 * This means low lock overhead for normal updates, and when over the
	 * limit the space used is immediately accounted. This makes enforcing
	 * the hard limit much more accurate. The per cpu fold threshold is
	 * based on how close we are to the hard limit.
	 */
	cilpcp = get_cpu_ptr(cil->xc_pcp);
	cilpcp->space_reserved += ctx_res;
	cilpcp->space_used += len;
	if (space_used >= XLOG_CIL_SPACE_LIMIT(log) ||
	    cilpcp->space_used >
			((XLOG_CIL_BLOCKING_SPACE_LIMIT(log) - space_used) /
					num_online_cpus())) {
		atomic_add(cilpcp->space_used, &ctx->space_used);
		cilpcp->space_used = 0;
	}
	/* attach the transaction to the CIL if it has any busy extents */
	if (!list_empty(&tp->t_busy))
		list_splice_init(&tp->t_busy, &cilpcp->busy_extents);
	/*
	 * Now update the order of everything modified in the transaction
	 * and insert items into the CIL if they aren't already there.
	 * We do this here so we only need to take the CIL lock once during
	 * the transaction commit.
	 */
	order = atomic_inc_return(&ctx->order_id);
	list_for_each_entry(lip, &tp->t_items, li_trans) {

		/* Skip items which aren't dirty in this transaction. */
		if (!test_bit(XFS_LI_DIRTY, &lip->li_flags))
			continue;

		lip->li_order_id = order;
		if (!list_empty(&lip->li_cil))
			continue;
		list_add_tail(&lip->li_cil, &cilpcp->log_items);
	}
	put_cpu_ptr(cilpcp);

	/*
	 * If we've overrun the reservation, dump the tx details before we move
	 * the log items. Shutdown is imminent...
	 */
	tp->t_ticket->t_curr_res -= ctx_res + len;
	if (WARN_ON(tp->t_ticket->t_curr_res < 0)) {
		xfs_warn(log->l_mp, "Transaction log reservation overrun:");
		xfs_warn(log->l_mp,
			 "  log items: %d bytes (iov hdrs: %d bytes)",
			 len, iovhdr_res);
		xfs_warn(log->l_mp, "  split region headers: %d bytes",
			 split_res);
		xfs_warn(log->l_mp, "  ctx ticket: %d bytes", ctx_res);
		xlog_print_trans(tp);
	}

	if (tp->t_ticket->t_curr_res < 0)
		xfs_force_shutdown(log->l_mp, SHUTDOWN_LOG_IO_ERROR);
}

static void
xlog_cil_free_logvec(
	struct list_head	*lv_chain)
{
	struct xfs_log_vec	*lv;

	while (!list_empty(lv_chain)) {
		lv = list_first_entry(lv_chain, struct xfs_log_vec, lv_list);
		list_del_init(&lv->lv_list);
		kmem_free(lv);
	}
}

static void
xlog_discard_endio_work(
	struct work_struct	*work)
{
	struct xfs_cil_ctx	*ctx =
		container_of(work, struct xfs_cil_ctx, discard_endio_work);
	struct xfs_mount	*mp = ctx->cil->xc_log->l_mp;

	xfs_extent_busy_clear(mp, &ctx->busy_extents, false);
	kmem_free(ctx);
}

/*
 * Queue up the actual completion to a thread to avoid IRQ-safe locking for
 * pagb_lock.  Note that we need a unbounded workqueue, otherwise we might
 * get the execution delayed up to 30 seconds for weird reasons.
 */
static void
xlog_discard_endio(
	struct bio		*bio)
{
	struct xfs_cil_ctx	*ctx = bio->bi_private;

	INIT_WORK(&ctx->discard_endio_work, xlog_discard_endio_work);
	queue_work(xfs_discard_wq, &ctx->discard_endio_work);
	bio_put(bio);
}

static void
xlog_discard_busy_extents(
	struct xfs_mount	*mp,
	struct xfs_cil_ctx	*ctx)
{
	struct list_head	*list = &ctx->busy_extents;
	struct xfs_extent_busy	*busyp;
	struct bio		*bio = NULL;
	struct blk_plug		plug;
	int			error = 0;

	ASSERT(mp->m_flags & XFS_MOUNT_DISCARD);

	blk_start_plug(&plug);
	list_for_each_entry(busyp, list, list) {
		trace_xfs_discard_extent(mp, busyp->agno, busyp->bno,
					 busyp->length);

		error = __blkdev_issue_discard(mp->m_ddev_targp->bt_bdev,
				XFS_AGB_TO_DADDR(mp, busyp->agno, busyp->bno),
				XFS_FSB_TO_BB(mp, busyp->length),
				GFP_NOFS, 0, &bio);
		if (error && error != -EOPNOTSUPP) {
			xfs_info(mp,
	 "discard failed for extent [0x%llx,%u], error %d",
				 (unsigned long long)busyp->bno,
				 busyp->length,
				 error);
			break;
		}
	}

	if (bio) {
		bio->bi_private = ctx;
		bio->bi_end_io = xlog_discard_endio;
		submit_bio(bio);
	} else {
		xlog_discard_endio_work(&ctx->discard_endio_work);
	}
	blk_finish_plug(&plug);
}

/*
 * Mark all items committed and clear busy extents. We free the log vector
 * chains in a separate pass so that we unpin the log items as quickly as
 * possible.
 */
static void
xlog_cil_committed(
	struct xfs_cil_ctx	*ctx)
{
	struct xfs_mount	*mp = ctx->cil->xc_log->l_mp;
	bool			abort = XLOG_FORCED_SHUTDOWN(ctx->cil->xc_log);

	/*
	 * If the I/O failed, we're aborting the commit and already shutdown.
	 * Wake any commit waiters before aborting the log items so we don't
	 * block async log pushers on callbacks. Async log pushers explicitly do
	 * not wait on log force completion because they may be holding locks
	 * required to unpin items.
	 */
	if (abort) {
		spin_lock(&ctx->cil->xc_push_lock);
		wake_up_all(&ctx->cil->xc_commit_wait);
		spin_unlock(&ctx->cil->xc_push_lock);
	}

	xfs_trans_committed_bulk(ctx->cil->xc_log->l_ailp, &ctx->lv_chain,
					ctx->start_lsn, abort);

	xfs_extent_busy_sort(&ctx->busy_extents);
	xfs_extent_busy_clear(mp, &ctx->busy_extents,
			     (mp->m_flags & XFS_MOUNT_DISCARD) && !abort);

	spin_lock(&ctx->cil->xc_push_lock);
	list_del(&ctx->committing);
	spin_unlock(&ctx->cil->xc_push_lock);

	xlog_cil_free_logvec(&ctx->lv_chain);

	if (!list_empty(&ctx->busy_extents))
		xlog_discard_busy_extents(mp, ctx);
	else
		kmem_free(ctx);
}

void
xlog_cil_process_committed(
	struct list_head	*list)
{
	struct xfs_cil_ctx	*ctx;

	while ((ctx = list_first_entry_or_null(list,
			struct xfs_cil_ctx, iclog_entry))) {
		list_del(&ctx->iclog_entry);
		xlog_cil_committed(ctx);
	}
}

struct xlog_cil_trans_hdr {
	struct xlog_op_header	oph[2];
	struct xfs_trans_header	thdr;
	struct xfs_log_iovec	lhdr[2];
};

/*
 * Build a checkpoint transaction header to begin the journal transaction.  We
 * need to account for the space used by the transaction header here as it is
 * not accounted for in xlog_write().
 *
 * This is the only place we write a transaction header, so we also build the
 * log opheaders that indicate the start of a log transaction and wrap the
 * transaction header. We keep the start record in it's own log vector rather
 * than compacting them into a single region as this ends up making the logic
 * in xlog_write() for handling empty opheaders for start, commit and unmount
 * records much simpler.
 */
static void
xlog_cil_build_trans_hdr(
	struct xfs_cil_ctx	*ctx,
	struct xlog_cil_trans_hdr *hdr,
	struct xfs_log_vec	*lvhdr,
	int			num_iovecs)
{
	struct xlog_ticket	*tic = ctx->ticket;
	uint32_t		tid = cpu_to_be32(tic->t_tid);

	memset(hdr, 0, sizeof(*hdr));

	/* Log start record */
	hdr->oph[0].oh_tid = tid;
	hdr->oph[0].oh_clientid = XFS_TRANSACTION;
	hdr->oph[0].oh_flags = XLOG_START_TRANS;

	/* log iovec region pointer */
	hdr->lhdr[0].i_addr = &hdr->oph[0];
	hdr->lhdr[0].i_len = sizeof(struct xlog_op_header);
	hdr->lhdr[0].i_type = XLOG_REG_TYPE_LRHEADER;

	/* log opheader */
	hdr->oph[1].oh_tid = tid;
	hdr->oph[1].oh_clientid = XFS_TRANSACTION;

	/* transaction header */
	hdr->thdr.th_magic = XFS_TRANS_HEADER_MAGIC;
	hdr->thdr.th_type = XFS_TRANS_CHECKPOINT;
	hdr->thdr.th_tid = tid;
	hdr->thdr.th_num_items = num_iovecs;

	/* log iovec region pointer */
	hdr->lhdr[1].i_addr = &hdr->oph[1];
	hdr->lhdr[1].i_len = sizeof(struct xlog_op_header) +
				sizeof(struct xfs_trans_header);
	hdr->lhdr[1].i_type = XLOG_REG_TYPE_TRANSHDR;

	lvhdr->lv_niovecs = 2;
	lvhdr->lv_iovecp = &hdr->lhdr[0];
	lvhdr->lv_bytes = hdr->lhdr[0].i_len + hdr->lhdr[1].i_len;

	tic->t_curr_res -= lvhdr->lv_bytes;
}

/*
 * CIL item reordering compare function. We want to order in ascending ID order,
 * but we want to leave items with the same ID in the order they were added to
 * the list. This is important for operations like reflink where we log 4 order
 * dependent intents in a single transaction when we overwrite an existing
 * shared extent with a new shared extent. i.e. BUI(unmap), CUI(drop),
 * CUI (inc), BUI(remap)...
 */
static int
xlog_cil_order_cmp(
	void			*priv,
	const struct list_head	*a,
	const struct list_head	*b)
{
	struct xfs_log_vec	*l1 = container_of(a, struct xfs_log_vec, lv_list);
	struct xfs_log_vec	*l2 = container_of(b, struct xfs_log_vec, lv_list);

	return l1->lv_order_id > l2->lv_order_id;
}

/*
 * Push the Committed Item List to the log.
 *
 * If the current sequence is the same as xc_push_seq we need to do a flush. If
 * xc_push_seq is less than the current sequence, then it has already been
 * flushed and we don't need to do anything - the caller will wait for it to
 * complete if necessary.
 *
 * xc_push_seq is checked unlocked against the sequence number for a match.
 * Hence we can allow log forces to run racily and not issue pushes for the
 * same sequence twice.  If we get a race between multiple pushes for the same
 * sequence they will block on the first one and then abort, hence avoiding
 * needless pushes.
 */
static void
xlog_cil_push_work(
	struct work_struct	*work)
{
	struct xfs_cil_ctx	*ctx =
		container_of(work, struct xfs_cil_ctx, push_work);
	struct xfs_cil		*cil = ctx->cil;
	struct xlog		*log = cil->xc_log;
	struct xfs_log_vec	*lv;
	struct xfs_cil_ctx	*new_ctx;
	struct xlog_in_core	*commit_iclog;
	int			num_iovecs = 0;
	int			num_bytes = 0;
	int			error = 0;
	struct xlog_cil_trans_hdr thdr;
	struct xfs_log_vec	lvhdr = {};
	xfs_lsn_t		commit_lsn;
	xfs_lsn_t		push_seq;
	struct bio		bio;
	DECLARE_COMPLETION_ONSTACK(bdev_flush);
	bool			push_commit_stable;
	struct xlog_ticket	*ticket;

	new_ctx = xlog_cil_ctx_alloc();
	new_ctx->ticket = xlog_cil_ticket_alloc(log);

	down_write(&cil->xc_ctx_lock);

	spin_lock(&cil->xc_push_lock);
	push_seq = cil->xc_push_seq;
	ASSERT(push_seq <= ctx->sequence);
	push_commit_stable = cil->xc_push_commit_stable;
	cil->xc_push_commit_stable = false;

	/*
	 * As we are about to switch to a new, empty CIL context, we no longer
	 * need to throttle tasks on CIL space overruns. Wake any waiters that
	 * the hard push throttle may have caught so they can start committing
	 * to the new context. The ctx->xc_push_lock provides the serialisation
	 * necessary for safely using the lockless waitqueue_active() check in
	 * this context.
	 */
	if (waitqueue_active(&cil->xc_push_wait))
		wake_up_all(&cil->xc_push_wait);

	/*
	 * Check if we've anything to push. If there is nothing, then we don't
	 * move on to a new sequence number and so we have to be able to push
	 * this sequence again later.
	 */
	if (test_bit(XLOG_CIL_EMPTY, &cil->xc_flags)) {
		cil->xc_push_seq = 0;
		spin_unlock(&cil->xc_push_lock);
		goto out_skip;
	}


	/* check for a previously pushed sequence */
	if (push_seq < ctx->sequence) {
		spin_unlock(&cil->xc_push_lock);
		goto out_skip;
	}

	/*
	 * We are now going to push this context, so add it to the committing
	 * list before we do anything else. This ensures that anyone waiting on
	 * this push can easily detect the difference between a "push in
	 * progress" and "CIL is empty, nothing to do".
	 *
	 * IOWs, a wait loop can now check for:
	 *	the current sequence not being found on the committing list;
	 *	an empty CIL; and
	 *	an unchanged sequence number
	 * to detect a push that had nothing to do and therefore does not need
	 * waiting on. If the CIL is not empty, we get put on the committing
	 * list before emptying the CIL and bumping the sequence number. Hence
	 * an empty CIL and an unchanged sequence number means we jumped out
	 * above after doing nothing.
	 *
	 * Hence the waiter will either find the commit sequence on the
	 * committing list or the sequence number will be unchanged and the CIL
	 * still dirty. In that latter case, the push has not yet started, and
	 * so the waiter will have to continue trying to check the CIL
	 * committing list until it is found. In extreme cases of delay, the
	 * sequence may fully commit between the attempts the wait makes to wait
	 * on the commit sequence.
	 */
	list_add(&ctx->committing, &cil->xc_committing);
	spin_unlock(&cil->xc_push_lock);

	/*
	 * The CIL is stable at this point - nothing new will be added to it
	 * because we hold the flush lock exclusively. Hence we can now issue
	 * a cache flush to ensure all the completed metadata in the journal we
	 * are about to overwrite is on stable storage.
	 */
	xfs_flush_bdev_async(&bio, log->l_mp->m_ddev_targp->bt_bdev,
				&bdev_flush);

	xlog_cil_pcp_aggregate(cil, ctx);

	while (!list_empty(&ctx->log_items)) {
		struct xfs_log_item	*item;

		item = list_first_entry(&ctx->log_items,
					struct xfs_log_item, li_cil);
		lv = item->li_lv;
		lv->lv_order_id = item->li_order_id;
		num_iovecs += lv->lv_niovecs;
		/* we don't write ordered log vectors */
		if (lv->lv_buf_len != XFS_LOG_VEC_ORDERED)
			num_bytes += lv->lv_bytes;

		list_add_tail(&lv->lv_list, &ctx->lv_chain);
		list_del_init(&item->li_cil);
		item->li_order_id = 0;
		item->li_lv = NULL;
	}

	/*
	 * Switch the contexts so we can drop the context lock and move out
	 * of a shared context. We can't just go straight to the commit record,
	 * though - we need to synchronise with previous and future commits so
	 * that the commit records are correctly ordered in the log to ensure
	 * that we process items during log IO completion in the correct order.
	 *
	 * For example, if we get an EFI in one checkpoint and the EFD in the
	 * next (e.g. due to log forces), we do not want the checkpoint with
	 * the EFD to be committed before the checkpoint with the EFI.  Hence
	 * we must strictly order the commit records of the checkpoints so
	 * that: a) the checkpoint callbacks are attached to the iclogs in the
	 * correct order; and b) the checkpoints are replayed in correct order
	 * in log recovery.
	 *
	 * Hence we need to add this context to the committing context list so
	 * that higher sequences will wait for us to write out a commit record
	 * before they do.
	 *
	 * xfs_log_force_seq requires us to mirror the new sequence into the cil
	 * structure atomically with the addition of this sequence to the
	 * committing list. This also ensures that we can do unlocked checks
	 * against the current sequence in log forces without risking
	 * deferencing a freed context pointer.
	 */
	spin_lock(&cil->xc_push_lock);
	xlog_cil_ctx_switch(cil, new_ctx);
	spin_unlock(&cil->xc_push_lock);
	up_write(&cil->xc_ctx_lock);

	/*
	 * Sort the log vector chain before we add the transaction headers.
	 * This ensures we always have the transaction headers at the start
	 * of the chain.
	 */
	list_sort(NULL, &ctx->lv_chain, xlog_cil_order_cmp);

	/*
	 * Build a checkpoint transaction header and write it to the log to
	 * begin the transaction. We need to account for the space used by the
	 * transaction header here as it is not accounted for in xlog_write().
	 * Add the lvhdr to the head of the lv chain we pass to xlog_write() so
	 * it gets written into the iclog first.
	 */
	xlog_cil_build_trans_hdr(ctx, &thdr, &lvhdr, num_iovecs);
	num_bytes += lvhdr.lv_bytes;
	list_add(&lvhdr.lv_list, &ctx->lv_chain);

	/*
	 * Before we format and submit the first iclog, we have to ensure that
	 * the metadata writeback ordering cache flush is complete.
	 */
	wait_for_completion(&bdev_flush);

	/*
	 * The LSN we need to pass to the log items on transaction commit is the
	 * LSN reported by the first log vector write, not the commit lsn. If we
	 * use the commit record lsn then we can move the tail beyond the grant
	 * write head.
	 */
	error = xlog_write(log, &ctx->lv_chain, ctx->ticket, &ctx->start_lsn,
				NULL, num_bytes);

	/*
	 * Take the lvhdr back off the lv_chain as it should not be passed
	 * to log IO completion.
	 */
	list_del(&lvhdr.lv_list);
	if (error)
		goto out_abort_free_ticket;

	/*
	 * now that we've written the checkpoint into the log, strictly
	 * order the commit records so replay will get them in the right order.
	 */
restart:
	spin_lock(&cil->xc_push_lock);
	list_for_each_entry(new_ctx, &cil->xc_committing, committing) {
		/*
		 * Avoid getting stuck in this loop because we were woken by the
		 * shutdown, but then went back to sleep once already in the
		 * shutdown state.
		 */
		if (XLOG_FORCED_SHUTDOWN(log)) {
			spin_unlock(&cil->xc_push_lock);
			goto out_abort_free_ticket;
		}

		/*
		 * Higher sequences will wait for this one so skip them.
		 * Don't wait for our own sequence, either.
		 */
		if (new_ctx->sequence >= ctx->sequence)
			continue;
		if (!new_ctx->commit_lsn) {
			/*
			 * It is still being pushed! Wait for the push to
			 * complete, then start again from the beginning.
			 */
			xlog_wait(&cil->xc_commit_wait, &cil->xc_push_lock);
			goto restart;
		}
	}
	spin_unlock(&cil->xc_push_lock);

	error = xlog_commit_record(log, ctx->ticket, &commit_iclog, &commit_lsn);
	if (error)
		goto out_abort_free_ticket;

	spin_lock(&commit_iclog->ic_callback_lock);
	if (commit_iclog->ic_state == XLOG_STATE_IOERROR) {
		spin_unlock(&commit_iclog->ic_callback_lock);
		goto out_abort_free_ticket;
	}
	ASSERT_ALWAYS(commit_iclog->ic_state == XLOG_STATE_ACTIVE ||
		      commit_iclog->ic_state == XLOG_STATE_WANT_SYNC);
	list_add_tail(&ctx->iclog_entry, &commit_iclog->ic_callbacks);
	spin_unlock(&commit_iclog->ic_callback_lock);

	/*
	 * now the checkpoint commit is complete and we've attached the
	 * callbacks to the iclog we can assign the commit LSN to the context
	 * and wake up anyone who is waiting for the commit to complete.
	 */
	spin_lock(&cil->xc_push_lock);
	ctx->commit_lsn = commit_lsn;
	wake_up_all(&cil->xc_commit_wait);
	spin_unlock(&cil->xc_push_lock);

	/*
	 * Pull the ticket off the ctx so we can ungrant it after releasing the
	 * commit_iclog. The ctx may be freed by the time we return from
	 * releasing the commit_iclog (i.e. checkpoint has been completed and
	 * callback run) so we can't reference the ctx after the call to
	 * xlog_state_release_iclog().
	 */
	ticket = ctx->ticket;

	/*
	 * If the checkpoint spans multiple iclogs, wait for all previous
	 * iclogs to complete before we submit the commit_iclog. In this case,
	 * the commit_iclog write needs to issue a pre-flush so that the
	 * ordering is correctly preserved down to stable storage.
	 */
	spin_lock(&log->l_icloglock);
	if (ctx->start_lsn != commit_lsn) {
		xlog_wait_on_iclog(commit_iclog->ic_prev);
		spin_lock(&log->l_icloglock);
		commit_iclog->ic_flags |= XLOG_ICL_NEED_FLUSH;
	}

	/*
	 * The commit iclog must be written to stable storage to guarantee
	 * journal IO vs metadata writeback IO is correctly ordered on stable
	 * storage.
	 *
	 * If the push caller needs the commit to be immediately stable and the
	 * commit_iclog is not yet marked as XLOG_STATE_WANT_SYNC to indicate it
	 * will be written when released, switch it's state to WANT_SYNC right
	 * now.
	 */
	commit_iclog->ic_flags |= XLOG_ICL_NEED_FUA;
	if (push_commit_stable && commit_iclog->ic_state == XLOG_STATE_ACTIVE)
		xlog_state_switch_iclogs(log, commit_iclog, 0);
	xlog_state_release_iclog(log, commit_iclog, ticket);
	spin_unlock(&log->l_icloglock);

	xfs_log_ticket_ungrant(log, ticket);
	return;

out_skip:
	up_write(&cil->xc_ctx_lock);
	xfs_log_ticket_put(new_ctx->ticket);
	kmem_free(new_ctx);
	return;

out_abort_free_ticket:
	xfs_log_ticket_ungrant(log, ctx->ticket);
	ASSERT(XLOG_FORCED_SHUTDOWN(log));
	xlog_cil_committed(ctx);
}

/*
 * We need to push CIL every so often so we don't cache more than we can fit in
 * the log. The limit really is that a checkpoint can't be more than half the
 * log (the current checkpoint is not allowed to overwrite the previous
 * checkpoint), but commit latency and memory usage limit this to a smaller
 * size.
 */
static void
xlog_cil_push_background(
	struct xlog	*log) __releases(cil->xc_ctx_lock)
{
	struct xfs_cil	*cil = log->l_cilp;
	int		space_used = atomic_read(&cil->xc_ctx->space_used);

	/*
	 * The cil won't be empty because we are called while holding the
	 * context lock so whatever we added to the CIL will still be there.
	 */
	ASSERT(!test_bit(XLOG_CIL_EMPTY, &cil->xc_flags));

	/*
	 * We are done if:
	 * - we haven't used up all the space available yet; or
	 * - we've already queued up a push; and
	 * - we're not over the hard limit; and
	 * - nothing has been over the hard limit.
	 *
	 * If so, we don't need to take the push lock as there's nothing to do.
	 */
	if (space_used < XLOG_CIL_SPACE_LIMIT(log) ||
	    (cil->xc_push_seq == cil->xc_current_sequence &&
	     space_used < XLOG_CIL_BLOCKING_SPACE_LIMIT(log) &&
	     !waitqueue_active(&cil->xc_push_wait))) {
		up_read(&cil->xc_ctx_lock);
		return;
	}

	spin_lock(&cil->xc_push_lock);
	if (cil->xc_push_seq < cil->xc_current_sequence) {
		cil->xc_push_seq = cil->xc_current_sequence;
		queue_work(log->l_mp->m_cil_workqueue, &cil->xc_ctx->push_work);
	}

	/*
	 * Drop the context lock now, we can't hold that if we need to sleep
	 * because we are over the blocking threshold. The push_lock is still
	 * held, so blocking threshold sleep/wakeup is still correctly
	 * serialised here.
	 */
	up_read(&cil->xc_ctx_lock);

	/*
	 * If we are well over the space limit, throttle the work that is being
	 * done until the push work on this context has begun. Enforce the hard
	 * throttle on all transaction commits once it has been activated, even
	 * if the committing transactions have resulted in the space usage
	 * dipping back down under the hard limit.
	 *
	 * The ctx->xc_push_lock provides the serialisation necessary for safely
	 * using the lockless waitqueue_active() check in this context.
	 */
	if (space_used >= XLOG_CIL_BLOCKING_SPACE_LIMIT(log) ||
	    waitqueue_active(&cil->xc_push_wait)) {
		trace_xfs_log_cil_wait(log, cil->xc_ctx->ticket);
		ASSERT(space_used < log->l_logsize);
		xlog_wait(&cil->xc_push_wait, &cil->xc_push_lock);
		return;
	}

	spin_unlock(&cil->xc_push_lock);

}

/*
 * xlog_cil_push_now() is used to trigger an immediate CIL push to the sequence
 * number that is passed. When it returns, the work will be queued for
 * @push_seq, but it won't be completed.
 *
 * If the caller is performing a synchronous force, we will flush the workqueue
 * to get previously queued work moving to minimise the wait time they will
 * undergo waiting for all outstanding pushes to complete. The caller is
 * expected to do the required waiting for push_seq to complete.
 *
 * If the caller is performing an async push, we need to ensure that the
 * checkpoint is fully flushed out of the iclogs when we finish the push. If we
 * don't do this, then the commit record may remain sitting in memory in an
 * ACTIVE iclog. This then requires another full log force to push to disk,
 * which defeats the purpose of having an async, non-blocking CIL force
 * mechanism. Hence in this case we need to pass a flag to the push work to
 * indicate it needs to flush the commit record itself.
 */
static void
xlog_cil_push_now(
	struct xlog	*log,
	xfs_lsn_t	push_seq,
	bool		async)
{
	struct xfs_cil	*cil = log->l_cilp;

	if (!cil)
		return;

	ASSERT(push_seq && push_seq <= cil->xc_current_sequence);

	/* start on any pending background push to minimise wait time on it */
	if (!async)
		flush_workqueue(log->l_mp->m_cil_workqueue);

	/*
	 * If the CIL is empty or we've already pushed the sequence then
	 * there's no work we need to do.
	 */
	spin_lock(&cil->xc_push_lock);
	if (test_bit(XLOG_CIL_EMPTY, &cil->xc_flags) ||
	    push_seq <= cil->xc_push_seq) {
		spin_unlock(&cil->xc_push_lock);
		return;
	}

	cil->xc_push_seq = push_seq;
	cil->xc_push_commit_stable = async;
	queue_work(log->l_mp->m_cil_workqueue, &cil->xc_ctx->push_work);
	spin_unlock(&cil->xc_push_lock);
}

bool
xlog_cil_empty(
	struct xlog	*log)
{
	struct xfs_cil	*cil = log->l_cilp;
	bool		empty = false;

	spin_lock(&cil->xc_push_lock);
	if (test_bit(XLOG_CIL_EMPTY, &cil->xc_flags))
		empty = true;
	spin_unlock(&cil->xc_push_lock);
	return empty;
}

/*
 * Commit a transaction with the given vector to the Committed Item List.
 *
 * To do this, we need to format the item, pin it in memory if required and
 * account for the space used by the transaction. Once we have done that we
 * need to release the unused reservation for the transaction, attach the
 * transaction to the checkpoint context so we carry the busy extents through
 * to checkpoint completion, and then unlock all the items in the transaction.
 *
 * Called with the context lock already held in read mode to lock out
 * background commit, returns without it held once background commits are
 * allowed again.
 */
void
xlog_cil_commit(
	struct xlog		*log,
	struct xfs_trans	*tp,
	xfs_csn_t		*commit_seq,
	bool			regrant)
{
	struct xfs_cil		*cil = log->l_cilp;
	struct xfs_log_item	*lip, *next;

	/*
	 * Do all necessary memory allocation before we lock the CIL.
	 * This ensures the allocation does not deadlock with a CIL
	 * push in memory reclaim (e.g. from kswapd).
	 */
	xlog_cil_alloc_shadow_bufs(log, tp);

	/* lock out background commit */
	down_read(&cil->xc_ctx_lock);

	xlog_cil_insert_items(log, tp);

	if (regrant && !XLOG_FORCED_SHUTDOWN(log))
		xfs_log_ticket_regrant(log, tp->t_ticket);
	else
		xfs_log_ticket_ungrant(log, tp->t_ticket);
	tp->t_ticket = NULL;
	xfs_trans_unreserve_and_mod_sb(tp);

	/*
	 * Once all the items of the transaction have been copied to the CIL,
	 * the items can be unlocked and possibly freed.
	 *
	 * This needs to be done before we drop the CIL context lock because we
	 * have to update state in the log items and unlock them before they go
	 * to disk. If we don't, then the CIL checkpoint can race with us and
	 * we can run checkpoint completion before we've updated and unlocked
	 * the log items. This affects (at least) processing of stale buffers,
	 * inodes and EFIs.
	 */
	trace_xfs_trans_commit_items(tp, _RET_IP_);
	list_for_each_entry_safe(lip, next, &tp->t_items, li_trans) {
		xfs_trans_del_item(lip);
		if (lip->li_ops->iop_committing)
			lip->li_ops->iop_committing(lip, cil->xc_ctx->sequence);
	}
	if (commit_seq)
		*commit_seq = cil->xc_ctx->sequence;

	/* xlog_cil_push_background() releases cil->xc_ctx_lock */
	xlog_cil_push_background(log);
}

/*
 * Flush the CIL to stable storage but don't wait for it to complete. This
 * requires the CIL push to ensure the commit record for the push hits the disk,
 * but otherwise is no different to a push done from a log force.
 */
void
xlog_cil_flush(
	struct xlog	*log)
{
	xfs_csn_t	seq = log->l_cilp->xc_current_sequence;

	trace_xfs_log_force(log->l_mp, seq, _RET_IP_);
	xlog_cil_push_now(log, seq, true);
}

/*
 * Conditionally push the CIL based on the sequence passed in.
 *
 * We only need to push if we haven't already pushed the sequence number given.
 * Hence the only time we will trigger a push here is if the push sequence is
 * the same as the current context.
 *
 * We return the current commit lsn to allow the callers to determine if a
 * iclog flush is necessary following this call.
 */
xfs_lsn_t
xlog_cil_force_seq(
	struct xlog	*log,
	xfs_csn_t	sequence)
{
	struct xfs_cil		*cil = log->l_cilp;
	struct xfs_cil_ctx	*ctx;
	xfs_lsn_t		commit_lsn = NULLCOMMITLSN;

	ASSERT(sequence <= cil->xc_current_sequence);

	if (!sequence)
		sequence = cil->xc_current_sequence;
	trace_xfs_log_force(log->l_mp, sequence, _RET_IP_);

	/*
	 * check to see if we need to force out the current context.
	 * xlog_cil_push() handles racing pushes for the same sequence,
	 * so no need to deal with it here.
	 */
restart:
	xlog_cil_push_now(log, sequence, false);

	/*
	 * See if we can find a previous sequence still committing.
	 * We need to wait for all previous sequence commits to complete
	 * before allowing the force of push_seq to go ahead. Hence block
	 * on commits for those as well.
	 */
	spin_lock(&cil->xc_push_lock);
	list_for_each_entry(ctx, &cil->xc_committing, committing) {
		/*
		 * Avoid getting stuck in this loop because we were woken by the
		 * shutdown, but then went back to sleep once already in the
		 * shutdown state.
		 */
		if (XLOG_FORCED_SHUTDOWN(log))
			goto out_shutdown;
		if (ctx->sequence > sequence)
			continue;
		if (!ctx->commit_lsn) {
			/*
			 * It is still being pushed! Wait for the push to
			 * complete, then start again from the beginning.
			 */
			XFS_STATS_INC(log->l_mp, xs_log_force_sleep);
			xlog_wait(&cil->xc_commit_wait, &cil->xc_push_lock);
			goto restart;
		}
		if (ctx->sequence != sequence)
			continue;
		/* found it! */
		commit_lsn = ctx->commit_lsn;
	}

	/*
	 * The call to xlog_cil_push_now() executes the push in the background.
	 * Hence by the time we have got here it our sequence may not have been
	 * pushed yet. This is true if the current sequence still matches the
	 * push sequence after the above wait loop and the CIL still contains
	 * dirty objects. This is guaranteed by the push code first adding the
	 * context to the committing list before emptying the CIL.
	 *
	 * Hence if we don't find the context in the committing list and the
	 * current sequence number is unchanged then the CIL contents are
	 * significant.  If the CIL is empty, if means there was nothing to push
	 * and that means there is nothing to wait for. If the CIL is not empty,
	 * it means we haven't yet started the push, because if it had started
	 * we would have found the context on the committing list.
	 */
	if (sequence == cil->xc_current_sequence &&
	    !test_bit(XLOG_CIL_EMPTY, &cil->xc_flags)) {
		spin_unlock(&cil->xc_push_lock);
		goto restart;
	}

	spin_unlock(&cil->xc_push_lock);
	return commit_lsn;

	/*
	 * We detected a shutdown in progress. We need to trigger the log force
	 * to pass through it's iclog state machine error handling, even though
	 * we are already in a shutdown state. Hence we can't return
	 * NULLCOMMITLSN here as that has special meaning to log forces (i.e.
	 * LSN is already stable), so we return a zero LSN instead.
	 */
out_shutdown:
	spin_unlock(&cil->xc_push_lock);
	return 0;
}

/*
 * Check if the current log item was first committed in this sequence.
 * We can't rely on just the log item being in the CIL, we have to check
 * the recorded commit sequence number.
 *
 * Note: for this to be used in a non-racy manner, it has to be called with
 * CIL flushing locked out. As a result, it should only be used during the
 * transaction commit process when deciding what to format into the item.
 */
bool
xfs_log_item_in_current_chkpt(
	struct xfs_log_item *lip)
{
	struct xfs_cil		*cil = lip->li_mountp->m_log->l_cilp;

	if (test_bit(XLOG_CIL_EMPTY, &cil->xc_flags))
		return false;

	/*
	 * li_seq is written on the first commit of a log item to record the
	 * first checkpoint it is written to. Hence if it is different to the
	 * current sequence, we're in a new checkpoint.
	 */
	return lip->li_seq == cil->xc_ctx->sequence;
}

#ifdef CONFIG_HOTPLUG_CPU
static LIST_HEAD(xlog_cil_pcp_list);
static DEFINE_SPINLOCK(xlog_cil_pcp_lock);

/*
 * Move dead percpu state to the relevant CIL context structures.
 *
 * We have to lock the CIL context here to ensure that nothing is modifying
 * the percpu state, either addition or removal. Both of these are done under
 * the CIL context lock, so grabbing that exclusively here will ensure we can
 * safely drain the cilpcp for the CPU that is dying.
 */
void
xlog_cil_pcp_dead(
	unsigned int		cpu)
{
	struct xfs_cil		*cil, *n;

	spin_lock(&xlog_cil_pcp_lock);
	list_for_each_entry_safe(cil, n, &xlog_cil_pcp_list, xc_pcp_list) {
		struct xlog_cil_pcp	*cilpcp = per_cpu_ptr(cil->xc_pcp, cpu);
		struct xfs_cil_ctx	*ctx;

		spin_unlock(&xlog_cil_pcp_lock);
		down_write(&cil->xc_ctx_lock);
		ctx = cil->xc_ctx;

		atomic_add(cilpcp->space_used, &ctx->space_used);
		if (ctx->ticket) {
			ctx->ticket->t_curr_res += cilpcp->space_reserved;
			ctx->ticket->t_unit_res += cilpcp->space_reserved;
		}
		if (!list_empty(&cilpcp->busy_extents)) {
			list_splice_init(&cilpcp->busy_extents,
					&ctx->busy_extents);
		}
		if (!list_empty(&cilpcp->log_items))
			list_splice_init(&cilpcp->log_items, &ctx->log_items);

		cilpcp->space_used = 0;
		cilpcp->space_reserved = 0;

		up_write(&cil->xc_ctx_lock);
		spin_lock(&xlog_cil_pcp_lock);
	}
	spin_unlock(&xlog_cil_pcp_lock);
}

static int
xlog_cil_pcp_hpadd(
	struct xfs_cil		*cil)
{
	INIT_LIST_HEAD(&cil->xc_pcp_list);
	spin_lock(&xlog_cil_pcp_lock);
	list_add(&cil->xc_pcp_list, &xlog_cil_pcp_list);
	spin_unlock(&xlog_cil_pcp_lock);
	return 0;
}

static void
xlog_cil_pcp_hpremove(
	struct xfs_cil		*cil)
{
	spin_lock(&xlog_cil_pcp_lock);
	list_del(&cil->xc_pcp_list);
	spin_unlock(&xlog_cil_pcp_lock);
}

#else /* !CONFIG_HOTPLUG_CPU */
static inline int xlog_cil_pcp_hpadd(struct xfs_cil *cil) { return 0; }
static inline void xlog_cil_pcp_hpremove(struct xfs_cil *cil) {}
#endif

static void __percpu *
xlog_cil_pcp_alloc(
	struct xfs_cil		*cil)
{
	struct xlog_cil_pcp	*cilpcp;
	void __percpu		*pcp;
	int			cpu;

	pcp = alloc_percpu(struct xlog_cil_pcp);
	if (!pcp)
		return NULL;

	if (xlog_cil_pcp_hpadd(cil) < 0) {
		free_percpu(pcp);
		return NULL;
	}

	for_each_possible_cpu(cpu) {
		cilpcp = per_cpu_ptr(pcp, cpu);
		INIT_LIST_HEAD(&cilpcp->busy_extents);
		INIT_LIST_HEAD(&cilpcp->log_items);
	}
	return pcp;
}

static void
xlog_cil_pcp_free(
	struct xfs_cil		*cil,
	void __percpu		*pcp)
{
	if (!pcp)
		return;
	xlog_cil_pcp_hpremove(cil);
	free_percpu(pcp);
}

/*
 * Perform initial CIL structure initialisation.
 */
int
xlog_cil_init(
	struct xlog	*log)
{
	struct xfs_cil	*cil;
	struct xfs_cil_ctx *ctx;

	cil = kmem_zalloc(sizeof(*cil), KM_MAYFAIL);
	if (!cil)
		return -ENOMEM;

	cil->xc_log = log;
	cil->xc_pcp = xlog_cil_pcp_alloc(cil);
	if (!cil->xc_pcp) {
		kmem_free(cil);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&cil->xc_committing);
	spin_lock_init(&cil->xc_push_lock);
	init_waitqueue_head(&cil->xc_push_wait);
	init_rwsem(&cil->xc_ctx_lock);
	init_waitqueue_head(&cil->xc_commit_wait);
	log->l_cilp = cil;

	ctx = xlog_cil_ctx_alloc();
	xlog_cil_ctx_switch(cil, ctx);

	return 0;
}

void
xlog_cil_destroy(
	struct xlog	*log)
{
	struct xfs_cil	*cil = log->l_cilp;

	if (cil->xc_ctx) {
		if (cil->xc_ctx->ticket)
			xfs_log_ticket_put(cil->xc_ctx->ticket);
		kmem_free(cil->xc_ctx);
	}

	ASSERT(test_bit(XLOG_CIL_EMPTY, &cil->xc_flags));
	xlog_cil_pcp_free(cil, cil->xc_pcp);
	kmem_free(cil);
}

