// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ntfs3/attrib.c
 *
 * Copyright (C) 2019-2020 Paragon Software GmbH, All rights reserved.
 *
 * TODO: merge attr_set_size/attr_data_get_block/attr_allocate_frame?
 */

#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/nls.h>
#include <linux/ratelimit.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>

#include "debug.h"
#include "ntfs.h"
#include "ntfs_fs.h"

/*
 * You can set external NTFS_MIN_LOG2_OF_CLUMP/NTFS_MAX_LOG2_OF_CLUMP to manage
 * preallocate algorithm
 */
#ifndef NTFS_MIN_LOG2_OF_CLUMP
#define NTFS_MIN_LOG2_OF_CLUMP 16
#endif

#ifndef NTFS_MAX_LOG2_OF_CLUMP
#define NTFS_MAX_LOG2_OF_CLUMP 26
#endif

// 16M
#define NTFS_CLUMP_MIN (1 << (NTFS_MIN_LOG2_OF_CLUMP + 8))
// 16G
#define NTFS_CLUMP_MAX (1ull << (NTFS_MAX_LOG2_OF_CLUMP + 8))

/*
 * get_pre_allocated
 *
 */
static inline u64 get_pre_allocated(u64 size)
{
	u32 clump;
	u8 align_shift;
	u64 ret;

	if (size <= NTFS_CLUMP_MIN) {
		clump = 1 << NTFS_MIN_LOG2_OF_CLUMP;
		align_shift = NTFS_MIN_LOG2_OF_CLUMP;
	} else if (size >= NTFS_CLUMP_MAX) {
		clump = 1 << NTFS_MAX_LOG2_OF_CLUMP;
		align_shift = NTFS_MAX_LOG2_OF_CLUMP;
	} else {
		align_shift = NTFS_MIN_LOG2_OF_CLUMP - 1 +
			      __ffs(size >> (8 + NTFS_MIN_LOG2_OF_CLUMP));
		clump = 1u << align_shift;
	}

	ret = (((size + clump - 1) >> align_shift)) << align_shift;

	return ret;
}

/*
 * attr_must_be_resident
 *
 * returns true if attribute must be resident
 */
static inline bool attr_must_be_resident(struct ntfs_sb_info *sbi,
					 enum ATTR_TYPE type)
{
	const struct ATTR_DEF_ENTRY *de;

	switch (type) {
	case ATTR_STD:
	case ATTR_NAME:
	case ATTR_ID:
	case ATTR_LABEL:
	case ATTR_VOL_INFO:
	case ATTR_ROOT:
	case ATTR_EA_INFO:
		return true;
	default:
		de = ntfs_query_def(sbi, type);
		if (de && (de->flags & NTFS_ATTR_MUST_BE_RESIDENT))
			return true;
		return false;
	}
}

/*
 * attr_load_runs
 *
 * load all runs stored in 'attr'
 */
int attr_load_runs(struct ATTRIB *attr, struct ntfs_inode *ni,
		   struct runs_tree *run)
{
	int err;
	CLST svcn = le64_to_cpu(attr->nres.svcn);
	CLST evcn = le64_to_cpu(attr->nres.evcn);
	u32 asize;
	u16 run_off;

	if (svcn >= evcn + 1 || run_is_mapped_full(run, svcn, evcn))
		return 0;

	asize = le32_to_cpu(attr->size);
	run_off = le16_to_cpu(attr->nres.run_off);
	err = run_unpack_ex(run, ni->mi.sbi, ni->mi.rno, svcn, evcn,
			    Add2Ptr(attr, run_off), asize - run_off);
	if (err < 0)
		return err;

	return 0;
}

/*
 * int run_deallocate_ex
 *
 * Deallocate clusters
 */
static int run_deallocate_ex(struct ntfs_sb_info *sbi, struct runs_tree *run,
			     CLST vcn, CLST len, CLST *done, bool trim)
{
	int err = 0;
	CLST vcn0 = vcn, lcn, clen, dn = 0;
	size_t idx;

	if (!len)
		goto out;

	if (!run_lookup_entry(run, vcn, &lcn, &clen, &idx)) {
failed:
		run_truncate(run, vcn0);
		err = -EINVAL;
		goto out;
	}

	for (;;) {
		if (clen > len)
			clen = len;

		if (!clen) {
			err = -EINVAL;
			goto out;
		}

		if (lcn != SPARSE_LCN) {
			mark_as_free_ex(sbi, lcn, clen, trim);
			dn += clen;
		}

		len -= clen;
		if (!len)
			break;

		if (!run_get_entry(run, ++idx, &vcn, &lcn, &clen)) {
			// save memory - don't load entire run
			goto failed;
		}
	}

out:
	if (done)
		*done = dn;

	return err;
}

/*
 * attr_allocate_clusters
 *
 * find free space, mark it as used and store in 'run'
 */
int attr_allocate_clusters(struct ntfs_sb_info *sbi, struct runs_tree *run,
			   CLST vcn, CLST lcn, CLST len, CLST *pre_alloc,
			   enum ALLOCATE_OPT opt, CLST *alen, const size_t fr,
			   CLST *new_lcn)
{
	int err;
	CLST flen, vcn0 = vcn, pre = pre_alloc ? *pre_alloc : 0;
	struct wnd_bitmap *wnd = &sbi->used.bitmap;
	size_t cnt = run->count;

	for (;;) {
		err = ntfs_look_for_free_space(sbi, lcn, len + pre, &lcn, &flen,
					       opt);

		if (err == -ENOSPC && pre) {
			pre = 0;
			if (*pre_alloc)
				*pre_alloc = 0;
			continue;
		}

		if (err)
			goto out;

		if (new_lcn && vcn == vcn0)
			*new_lcn = lcn;

		/* Add new fragment into run storage */
		if (!run_add_entry(run, vcn, lcn, flen)) {
			down_write_nested(&wnd->rw_lock, BITMAP_MUTEX_CLUSTERS);
			wnd_set_free(wnd, lcn, flen);
			up_write(&wnd->rw_lock);
			err = -ENOMEM;
			goto out;
		}

		vcn += flen;

		if (flen >= len || opt == ALLOCATE_MFT ||
		    (fr && run->count - cnt >= fr)) {
			*alen = vcn - vcn0;
			return 0;
		}

		len -= flen;
	}

out:
	/* undo */
	run_deallocate_ex(sbi, run, vcn0, vcn - vcn0, NULL, false);
	run_truncate(run, vcn0);

	return err;
}

/*
 * attr_set_size_res
 *
 * helper for attr_set_size
 */
static int attr_set_size_res(struct ntfs_inode *ni, struct ATTRIB *attr,
			     struct ATTR_LIST_ENTRY *le, struct mft_inode *mi,
			     u64 new_size, struct runs_tree *run,
			     struct ATTRIB **ins_attr)
{
	int err = 0;
	struct ntfs_sb_info *sbi = mi->sbi;
	struct MFT_REC *rec = mi->mrec;
	u32 used = le32_to_cpu(rec->used);
	u32 asize = le32_to_cpu(attr->size);
	u32 aoff = PtrOffset(rec, attr);
	u32 rsize = le32_to_cpu(attr->res.data_size);
	u32 tail = used - aoff - asize;
	char *next = Add2Ptr(attr, asize);
	int dsize = QuadAlign(new_size) - QuadAlign(rsize);
	CLST len, alen;
	struct ATTRIB *attr_s = NULL;
	bool is_ext;

	if (dsize < 0) {
		memmove(next + dsize, next, tail);
	} else if (dsize > 0) {
		if (used + dsize > sbi->max_bytes_per_attr)
			goto resident2nonresident;

		memmove(next + dsize, next, tail);
		memset(next, 0, dsize);
	}

	rec->used = cpu_to_le32(used + dsize);
	attr->size = cpu_to_le32(asize + dsize);
	attr->res.data_size = cpu_to_le32(new_size);
	mi->dirty = true;
	*ins_attr = attr;

	return 0;

resident2nonresident:
	len = bytes_to_cluster(sbi, rsize);

	run_init(run);

	is_ext = is_attr_ext(attr);

	if (!len) {
		alen = 0;
	} else if (is_ext) {
		if (!run_add_entry(run, 0, SPARSE_LCN, len)) {
			err = -ENOMEM;
			goto out;
		}
		alen = len;
	} else {
		err = attr_allocate_clusters(sbi, run, 0, 0, len, NULL,
					     ALLOCATE_DEF, &alen, 0, NULL);
		if (err)
			goto out;

		err = ntfs_sb_write_run(sbi, run, 0, resident_data(attr),
					rsize);
		if (err)
			goto out;
	}

	attr_s = ntfs_memdup(attr, asize);
	if (!attr_s) {
		err = -ENOMEM;
		goto out;
	}

	/*verify(mi_remove_attr(mi, attr));*/
	used -= asize;
	memmove(attr, Add2Ptr(attr, asize), used - aoff);
	rec->used = cpu_to_le32(used);
	mi->dirty = true;
	if (le)
		al_remove_le(ni, le);

	err = ni_insert_nonresident(ni, attr_s->type, attr_name(attr_s),
				    attr_s->name_len, run, 0, alen,
				    attr_s->flags, &attr, NULL);
	if (err)
		goto out;

	ntfs_free(attr_s);
	attr->nres.data_size = cpu_to_le64(rsize);
	attr->nres.valid_size = attr->nres.data_size;

	*ins_attr = attr;

	if (attr_s->type == ATTR_DATA && !attr_s->name_len &&
	    run == &ni->file.run) {
		ni->ni_flags &= ~NI_FLAG_RESIDENT;
	}

	/* Resident attribute becomes non resident */
	return 0;

out:
	/* undo: do not trim new allocated clusters */
	run_deallocate(sbi, run, false);
	run_close(run);

	if (attr_s) {
		memmove(next, Add2Ptr(rec, aoff), used - aoff);
		memcpy(Add2Ptr(rec, aoff), attr_s, asize);
		rec->used = cpu_to_le32(used + asize);
		mi->dirty = true;
		ntfs_free(attr_s);
		/*reinsert le*/
	}

	return err;
}

/*
 * attr_set_size
 *
 * change the size of attribute
 * Extend:
 *   - sparse/compressed: no allocated clusters
 *   - normal: append allocated and preallocated new clusters
 * Shrink:
 *   - no deallocate if keep_prealloc is set
 */
int attr_set_size(struct ntfs_inode *ni, enum ATTR_TYPE type,
		  const __le16 *name, u8 name_len, struct runs_tree *run,
		  u64 new_size, const u64 *new_valid, bool keep_prealloc,
		  struct ATTRIB **ret)
{
	int err = 0;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	u8 cluster_bits = sbi->cluster_bits;
	bool is_mft =
		ni->mi.rno == MFT_REC_MFT && type == ATTR_DATA && !name_len;
	u64 old_valid, old_size, old_alloc, new_alloc, new_alloc_tmp;
	struct ATTRIB *attr, *attr_b;
	struct ATTR_LIST_ENTRY *le, *le_b;
	struct mft_inode *mi, *mi_b;
	CLST alen, vcn, lcn, new_alen, old_alen, svcn, evcn;
	CLST next_svcn, pre_alloc = -1, done = 0;
	bool is_ext;
	u32 align;
	struct MFT_REC *rec;

again:
	le_b = NULL;
	attr_b = ni_find_attr(ni, NULL, &le_b, type, name, name_len, NULL,
			      &mi_b);
	if (!attr_b) {
		err = -ENOENT;
		goto out;
	}

	if (!attr_b->non_res) {
		err = attr_set_size_res(ni, attr_b, le_b, mi_b, new_size, run,
					&attr_b);
		if (err || !attr_b->non_res)
			goto out;

		/* layout of records may be changed, so do a full search */
		goto again;
	}

	is_ext = is_attr_ext(attr_b);

again_1:

	if (is_ext) {
		align = 1u << (attr_b->nres.c_unit + cluster_bits);
		if (is_attr_sparsed(attr_b))
			keep_prealloc = false;
	} else {
		align = sbi->cluster_size;
	}

	old_valid = le64_to_cpu(attr_b->nres.valid_size);
	old_size = le64_to_cpu(attr_b->nres.data_size);
	old_alloc = le64_to_cpu(attr_b->nres.alloc_size);
	old_alen = old_alloc >> cluster_bits;

	new_alloc = (new_size + align - 1) & ~(u64)(align - 1);
	new_alen = new_alloc >> cluster_bits;

	if (keep_prealloc && is_ext)
		keep_prealloc = false;

	if (keep_prealloc && new_size < old_size) {
		attr_b->nres.data_size = cpu_to_le64(new_size);
		mi_b->dirty = true;
		goto ok;
	}

	vcn = old_alen - 1;

	svcn = le64_to_cpu(attr_b->nres.svcn);
	evcn = le64_to_cpu(attr_b->nres.evcn);

	if (svcn <= vcn && vcn <= evcn) {
		attr = attr_b;
		le = le_b;
		mi = mi_b;
	} else if (!le_b) {
		err = -EINVAL;
		goto out;
	} else {
		le = le_b;
		attr = ni_find_attr(ni, attr_b, &le, type, name, name_len, &vcn,
				    &mi);
		if (!attr) {
			err = -EINVAL;
			goto out;
		}

next_le_1:
		svcn = le64_to_cpu(attr->nres.svcn);
		evcn = le64_to_cpu(attr->nres.evcn);
	}

next_le:
	rec = mi->mrec;

	err = attr_load_runs(attr, ni, run);
	if (err)
		goto out;

	if (new_size > old_size) {
		CLST to_allocate;
		size_t free;

		if (new_alloc <= old_alloc) {
			attr_b->nres.data_size = cpu_to_le64(new_size);
			mi_b->dirty = true;
			goto ok;
		}

		to_allocate = new_alen - old_alen;
add_alloc_in_same_attr_seg:
		lcn = 0;
		if (is_mft) {
			/* mft allocates clusters from mftzone */
			pre_alloc = 0;
		} else if (is_ext) {
			/* no preallocate for sparse/compress */
			pre_alloc = 0;
		} else if (pre_alloc == -1) {
			pre_alloc = 0;
			if (type == ATTR_DATA && !name_len &&
			    sbi->options.prealloc) {
				CLST new_alen2 = bytes_to_cluster(
					sbi, get_pre_allocated(new_size));
				pre_alloc = new_alen2 - new_alen;
			}

			/* Get the last lcn to allocate from */
			if (old_alen &&
			    !run_lookup_entry(run, vcn, &lcn, NULL, NULL)) {
				lcn = SPARSE_LCN;
			}

			if (lcn == SPARSE_LCN)
				lcn = 0;
			else if (lcn)
				lcn += 1;

			free = wnd_zeroes(&sbi->used.bitmap);
			if (to_allocate > free) {
				err = -ENOSPC;
				goto out;
			}

			if (pre_alloc && to_allocate + pre_alloc > free)
				pre_alloc = 0;
		}

		vcn = old_alen;

		if (is_ext) {
			if (!run_add_entry(run, vcn, SPARSE_LCN, to_allocate)) {
				err = -ENOMEM;
				goto out;
			}
			alen = to_allocate;
		} else {
			/* ~3 bytes per fragment */
			err = attr_allocate_clusters(
				sbi, run, vcn, lcn, to_allocate, &pre_alloc,
				is_mft ? ALLOCATE_MFT : 0, &alen,
				is_mft ? 0 :
					 (sbi->record_size -
					  le32_to_cpu(rec->used) + 8) /
							 3 +
						 1,
				NULL);
			if (err)
				goto out;
		}

		done += alen;
		vcn += alen;
		if (to_allocate > alen)
			to_allocate -= alen;
		else
			to_allocate = 0;

pack_runs:
		err = mi_pack_runs(mi, attr, run, vcn - svcn);
		if (err)
			goto out;

		next_svcn = le64_to_cpu(attr->nres.evcn) + 1;
		new_alloc_tmp = (u64)next_svcn << cluster_bits;
		attr_b->nres.alloc_size = cpu_to_le64(new_alloc_tmp);
		mi_b->dirty = true;

		if (next_svcn >= vcn && !to_allocate) {
			/* Normal way. update attribute and exit */
			attr_b->nres.data_size = cpu_to_le64(new_size);
			goto ok;
		}

		/* at least two mft to avoid recursive loop*/
		if (is_mft && next_svcn == vcn &&
		    ((u64)done << sbi->cluster_bits) >= 2 * sbi->record_size) {
			new_size = new_alloc_tmp;
			attr_b->nres.data_size = attr_b->nres.alloc_size;
			goto ok;
		}

		if (le32_to_cpu(rec->used) < sbi->record_size) {
			old_alen = next_svcn;
			evcn = old_alen - 1;
			goto add_alloc_in_same_attr_seg;
		}

		if (type == ATTR_LIST) {
			err = ni_expand_list(ni);
			if (err)
				goto out;
			if (next_svcn < vcn)
				goto pack_runs;

			/* layout of records is changed */
			goto again;
		}

		if (!ni->attr_list.size) {
			err = ni_create_attr_list(ni);
			if (err)
				goto out;
			/* layout of records is changed */
		}

		if (next_svcn >= vcn) {
			/* this is mft data, repeat */
			goto again;
		}

		/* insert new attribute segment */
		err = ni_insert_nonresident(ni, type, name, name_len, run,
					    next_svcn, vcn - next_svcn,
					    attr_b->flags, &attr, &mi);
		if (err)
			goto out;

		if (!is_mft)
			run_truncate_head(run, evcn + 1);

		svcn = le64_to_cpu(attr->nres.svcn);
		evcn = le64_to_cpu(attr->nres.evcn);

		le_b = NULL;
		/* layout of records maybe changed */
		/* find base attribute to update*/
		attr_b = ni_find_attr(ni, NULL, &le_b, type, name, name_len,
				      NULL, &mi_b);
		if (!attr_b) {
			err = -ENOENT;
			goto out;
		}

		attr_b->nres.alloc_size = cpu_to_le64((u64)vcn << cluster_bits);
		attr_b->nres.data_size = attr_b->nres.alloc_size;
		attr_b->nres.valid_size = attr_b->nres.alloc_size;
		mi_b->dirty = true;
		goto again_1;
	}

	if (new_size != old_size ||
	    (new_alloc != old_alloc && !keep_prealloc)) {
		vcn = max(svcn, new_alen);
		new_alloc_tmp = (u64)vcn << cluster_bits;

		err = run_deallocate_ex(sbi, run, vcn, evcn - vcn + 1, &alen,
					true);
		if (err)
			goto out;

		run_truncate(run, vcn);

		if (vcn > svcn) {
			err = mi_pack_runs(mi, attr, run, vcn - svcn);
			if (err < 0)
				goto out;
		} else if (le && le->vcn) {
			u16 le_sz = le16_to_cpu(le->size);

			/*
			 * NOTE: list entries for one attribute are always
			 * the same size. We deal with last entry (vcn==0)
			 * and it is not first in entries array
			 * (list entry for std attribute always first)
			 * So it is safe to step back
			 */
			mi_remove_attr(mi, attr);

			if (!al_remove_le(ni, le)) {
				err = -EINVAL;
				goto out;
			}

			le = (struct ATTR_LIST_ENTRY *)((u8 *)le - le_sz);
		} else {
			attr->nres.evcn = cpu_to_le64((u64)vcn - 1);
			mi->dirty = true;
		}

		attr_b->nres.alloc_size = cpu_to_le64(new_alloc_tmp);

		if (vcn == new_alen) {
			attr_b->nres.data_size = cpu_to_le64(new_size);
			if (new_size < old_valid)
				attr_b->nres.valid_size =
					attr_b->nres.data_size;
		} else {
			if (new_alloc_tmp <=
			    le64_to_cpu(attr_b->nres.data_size))
				attr_b->nres.data_size =
					attr_b->nres.alloc_size;
			if (new_alloc_tmp <
			    le64_to_cpu(attr_b->nres.valid_size))
				attr_b->nres.valid_size =
					attr_b->nres.alloc_size;
		}

		if (is_ext)
			le64_sub_cpu(&attr_b->nres.total_size,
				     ((u64)alen << cluster_bits));

		mi_b->dirty = true;

		if (new_alloc_tmp <= new_alloc)
			goto ok;

		old_size = new_alloc_tmp;
		vcn = svcn - 1;

		if (le == le_b) {
			attr = attr_b;
			mi = mi_b;
			evcn = svcn - 1;
			svcn = 0;
			goto next_le;
		}

		if (le->type != type || le->name_len != name_len ||
		    memcmp(le_name(le), name, name_len * sizeof(short))) {
			err = -EINVAL;
			goto out;
		}

		err = ni_load_mi(ni, le, &mi);
		if (err)
			goto out;

		attr = mi_find_attr(mi, NULL, type, name, name_len, &le->id);
		if (!attr) {
			err = -EINVAL;
			goto out;
		}
		goto next_le_1;
	}

ok:
	if (new_valid) {
		__le64 valid = cpu_to_le64(min(*new_valid, new_size));

		if (attr_b->nres.valid_size != valid) {
			attr_b->nres.valid_size = valid;
			mi_b->dirty = true;
		}
	}

out:
	if (!err && attr_b && ret)
		*ret = attr_b;

	/* update inode_set_bytes*/
	if (!err && attr_b && attr_b->non_res &&
	    ((type == ATTR_DATA && !name_len) ||
	     (type == ATTR_ALLOC && name == I30_NAME))) {
		bool dirty = false;

		if (ni->vfs_inode.i_size != new_size) {
			ni->vfs_inode.i_size = new_size;
			dirty = true;
		}

		new_alloc = le64_to_cpu(attr_b->nres.alloc_size);
		if (inode_get_bytes(&ni->vfs_inode) != new_alloc) {
			inode_set_bytes(&ni->vfs_inode, new_alloc);
			dirty = true;
		}

		if (dirty) {
			ni->ni_flags |= NI_FLAG_UPDATE_PARENT;
			mark_inode_dirty(&ni->vfs_inode);
		}
	}

	return err;
}

int attr_data_get_block(struct ntfs_inode *ni, CLST vcn, CLST clen, CLST *lcn,
			CLST *len, bool *new)
{
	int err = 0;
	struct runs_tree *run = &ni->file.run;
	struct ntfs_sb_info *sbi;
	u8 cluster_bits;
	struct ATTRIB *attr, *attr_b;
	struct ATTR_LIST_ENTRY *le, *le_b;
	struct mft_inode *mi, *mi_b;
	CLST hint, svcn, to_alloc, evcn1, new_evcn1, next_svcn;
	u64 new_size, total_size;
	u32 clst_per_frame;
	bool ok;

	if (new)
		*new = false;

	down_read(&ni->file.run_lock);
	ok = run_lookup_entry(run, vcn, lcn, len, NULL);
	up_read(&ni->file.run_lock);

	if (ok && (*lcn != SPARSE_LCN || !new)) {
		/* normal way */
		return 0;
	}

	if (!clen)
		clen = 1;

	if (ok && clen > *len)
		clen = *len;

	sbi = ni->mi.sbi;
	cluster_bits = sbi->cluster_bits;
	new_size = ((u64)vcn + clen) << cluster_bits;

	ni_lock(ni);
	down_write(&ni->file.run_lock);

again:
	le_b = NULL;
	attr_b = ni_find_attr(ni, NULL, &le_b, ATTR_DATA, NULL, 0, NULL, &mi_b);
	if (!attr_b) {
		err = -ENOENT;
		goto out;
	}

	if (!attr_b->non_res) {
		if (!new) {
			*lcn = RESIDENT_LCN;
			goto out;
		}

		err = attr_set_size_res(ni, attr_b, le_b, mi_b, new_size, run,
					&attr_b);
		if (err)
			goto out;

		if (!attr_b->non_res) {
			/* Resident attribute still resident */
			*lcn = RESIDENT_LCN;
			goto out;
		}

		/* Resident attribute becomes non resident */
		goto again;
	}

	clst_per_frame = 1u << attr_b->nres.c_unit;
	to_alloc = (clen + clst_per_frame - 1) & ~(clst_per_frame - 1);

	svcn = le64_to_cpu(attr_b->nres.svcn);
	evcn1 = le64_to_cpu(attr_b->nres.evcn) + 1;

	attr = attr_b;
	le = le_b;
	mi = mi_b;

	if (le_b && (vcn < svcn || evcn1 <= vcn)) {
		attr = ni_find_attr(ni, attr_b, &le, ATTR_DATA, NULL, 0, &vcn,
				    &mi);
		if (!attr) {
			err = -EINVAL;
			goto out;
		}
		svcn = le64_to_cpu(attr->nres.svcn);
		evcn1 = le64_to_cpu(attr->nres.evcn) + 1;
	}

	err = attr_load_runs(attr, ni, run);
	if (err)
		goto out;

	if (!ok) {
		ok = run_lookup_entry(run, vcn, lcn, len, NULL);
		if (ok && (*lcn != SPARSE_LCN || !new)) {
			/* normal way */
			err = 0;
			goto out;
		}

		if (!ok && !new) {
			*len = 0;
			err = 0;
			goto out;
		}

		if (ok && clen > *len) {
			clen = *len;
			new_size = ((u64)vcn + clen) << cluster_bits;
			to_alloc = (clen + clst_per_frame - 1) &
				   ~(clst_per_frame - 1);
		}
	}

	if (!is_attr_ext(attr_b)) {
		err = -EINVAL;
		goto out;
	}

	/* Get the last lcn to allocate from */
	hint = 0;

	if (vcn > evcn1) {
		if (!run_add_entry(run, evcn1, SPARSE_LCN, vcn - evcn1)) {
			err = -ENOMEM;
			goto out;
		}
	} else if (vcn && !run_lookup_entry(run, vcn - 1, &hint, NULL, NULL)) {
		hint = -1;
	}

	err = attr_allocate_clusters(
		sbi, run, vcn, hint + 1, to_alloc, NULL, 0, len,
		(sbi->record_size - le32_to_cpu(mi->mrec->used) + 8) / 3 + 1,
		lcn);
	if (err)
		goto out;
	*new = true;

	new_evcn1 = vcn + *len;
	if (new_evcn1 < evcn1)
		new_evcn1 = evcn1;

	total_size = le64_to_cpu(attr_b->nres.total_size) +
		     ((u64)*len << cluster_bits);

repack:

	err = mi_pack_runs(mi, attr, run, new_evcn1 - svcn);
	if (err < 0)
		goto out;

	attr_b->nres.total_size = cpu_to_le64(total_size);
	inode_set_bytes(&ni->vfs_inode, total_size);

	mi_b->dirty = true;
	ni->ni_flags |= NI_FLAG_UPDATE_PARENT;
	mark_inode_dirty(&ni->vfs_inode);

	next_svcn = le64_to_cpu(attr->nres.evcn) + 1;
	if (next_svcn >= evcn1) {
		/* Normal way. update attribute and exit */
		goto out;
	}

	if (!ni->attr_list.le) {
		err = ni_create_attr_list(ni);
		if (err)
			goto out;
		/* layout of records is changed */
		le_b = NULL;
		attr_b = ni_find_attr(ni, NULL, &le_b, ATTR_DATA, NULL, 0, NULL,
				      &mi_b);
		if (!attr_b) {
			err = -ENOENT;
			goto out;
		}

		attr = attr_b;
		le = le_b;
		mi = mi_b;
		goto repack;
	}

	/* Estimate next attribute */
	attr = ni_find_attr(ni, attr, &le, ATTR_DATA, NULL, 0, &evcn1, &mi);

	if (attr && le32_to_cpu(mi->mrec->used) + 8 <= sbi->record_size) {
		svcn = next_svcn;
		evcn1 = le64_to_cpu(attr->nres.evcn) + 1;

		err = attr_load_runs(attr, ni, run);
		if (err)
			goto out;

		attr->nres.svcn = cpu_to_le64(svcn);
		err = mi_pack_runs(mi, attr, run, evcn1 - svcn);
		if (err < 0)
			goto out;

		le->vcn = cpu_to_le64(svcn);
		ni->attr_list.dirty = true;

		mi->dirty = true;

		next_svcn = le64_to_cpu(attr->nres.evcn) + 1;

		if (next_svcn >= evcn1) {
			/* Normal way. update attribute and exit */
			goto out;
		}
	}

	err = ni_insert_nonresident(ni, ATTR_DATA, NULL, 0, run, next_svcn,
				    evcn1 - next_svcn, attr_b->flags, &attr,
				    &mi);
	if (err)
		goto out;

	run_truncate_head(run, vcn);

out:
	up_write(&ni->file.run_lock);
	ni_unlock(ni);

	return err;
}

/*
 * attr_load_runs_vcn
 *
 * load runs with vcn
 */
int attr_load_runs_vcn(struct ntfs_inode *ni, enum ATTR_TYPE type,
		       const __le16 *name, u8 name_len, struct runs_tree *run,
		       CLST vcn)
{
	struct ATTRIB *attr;
	int err;
	CLST svcn, evcn;
	u16 ro;

	attr = ni_find_attr(ni, NULL, NULL, type, name, name_len, &vcn, NULL);
	if (!attr)
		return -ENOENT;

	svcn = le64_to_cpu(attr->nres.svcn);
	evcn = le64_to_cpu(attr->nres.evcn);

	if (evcn < vcn || vcn < svcn)
		return -EINVAL;

	ro = le16_to_cpu(attr->nres.run_off);
	err = run_unpack_ex(run, ni->mi.sbi, ni->mi.rno, svcn, evcn,
			    Add2Ptr(attr, ro), le32_to_cpu(attr->size) - ro);
	if (err < 0)
		return err;
	return 0;
}

/*
 * attr_is_frame_compressed
 *
 * This function is used to detect compressed frame
 */
int attr_is_frame_compressed(struct ntfs_inode *ni, struct ATTRIB *attr,
			     CLST frame, CLST *clst_data, bool *is_compr)
{
	int err;
	u32 clst_frame;
	CLST len, lcn, vcn, alen, slen, vcn1;
	size_t idx;
	struct runs_tree *run;

	*clst_data = 0;
	*is_compr = false;

	if (!is_attr_compressed(attr))
		return 0;

	if (!attr->non_res)
		return 0;

	clst_frame = 1u << attr->nres.c_unit;
	vcn = frame * clst_frame;
	run = &ni->file.run;

	if (!run_lookup_entry(run, vcn, &lcn, &len, &idx)) {
		err = attr_load_runs_vcn(ni, attr->type, attr_name(attr),
					 attr->name_len, run, vcn);
		if (err)
			return err;

		if (!run_lookup_entry(run, vcn, &lcn, &len, &idx))
			return -ENOENT;
	}

	if (lcn == SPARSE_LCN) {
		/* The frame is sparsed if "clst_frame" clusters are sparsed */
		*is_compr = true;
		return 0;
	}

	if (len >= clst_frame) {
		/*
		 * The frame is not compressed 'cause
		 * it does not contain any sparse clusters
		 */
		*clst_data = clst_frame;
		return 0;
	}

	alen = bytes_to_cluster(ni->mi.sbi, le64_to_cpu(attr->nres.alloc_size));
	slen = 0;
	*clst_data = len;

	/*
	 * The frame is compressed if *clst_data + slen >= clst_frame
	 * Check next fragments
	 */
	while ((vcn += len) < alen) {
		vcn1 = vcn;

		if (!run_get_entry(run, ++idx, &vcn, &lcn, &len) ||
		    vcn1 != vcn) {
			err = attr_load_runs_vcn(ni, attr->type,
						 attr_name(attr),
						 attr->name_len, run, vcn1);
			if (err)
				return err;
			vcn = vcn1;

			if (!run_lookup_entry(run, vcn, &lcn, &len, &idx))
				return -ENOENT;
		}

		if (lcn == SPARSE_LCN) {
			slen += len;
		} else {
			if (slen) {
				/*
				 * data_clusters + sparse_clusters =
				 * not enough for frame
				 */
				return -EINVAL;
			}
			*clst_data += len;
		}

		if (*clst_data + slen >= clst_frame) {
			if (!slen) {
				/*
				 * There is no sparsed clusters in this frame
				 * So it is not compressed
				 */
				*clst_data = clst_frame;
			} else {
				*is_compr = *clst_data < clst_frame;
			}
			break;
		}
	}

	return 0;
}

/*
 * attr_allocate_frame
 *
 * allocate/free clusters for 'frame'
 */
int attr_allocate_frame(struct ntfs_inode *ni, CLST frame, size_t compr_size,
			u64 new_valid)
{
	int err = 0;
	struct runs_tree *run = &ni->file.run;
	struct ntfs_sb_info *sbi = ni->mi.sbi;
	struct ATTRIB *attr, *attr_b;
	struct ATTR_LIST_ENTRY *le, *le_b;
	struct mft_inode *mi, *mi_b;
	CLST svcn, evcn1, next_svcn, lcn, len;
	CLST vcn, clst_data;
	u64 total_size, valid_size, data_size;
	bool is_compr;

	le_b = NULL;
	attr_b = ni_find_attr(ni, NULL, &le_b, ATTR_DATA, NULL, 0, NULL, &mi_b);
	if (!attr_b)
		return -ENOENT;

	if (!is_attr_ext(attr_b))
		return -EINVAL;

	vcn = frame << NTFS_LZNT_CUNIT;
	total_size = le64_to_cpu(attr_b->nres.total_size);

	svcn = le64_to_cpu(attr_b->nres.svcn);
	evcn1 = le64_to_cpu(attr_b->nres.evcn) + 1;
	data_size = le64_to_cpu(attr_b->nres.data_size);

	if (svcn <= vcn && vcn < evcn1) {
		attr = attr_b;
		le = le_b;
		mi = mi_b;
	} else if (!le_b) {
		err = -EINVAL;
		goto out;
	} else {
		le = le_b;
		attr = ni_find_attr(ni, attr_b, &le, ATTR_DATA, NULL, 0, &vcn,
				    &mi);
		if (!attr) {
			err = -EINVAL;
			goto out;
		}
		svcn = le64_to_cpu(attr->nres.svcn);
		evcn1 = le64_to_cpu(attr->nres.evcn) + 1;
	}

	err = attr_load_runs(attr, ni, run);
	if (err)
		goto out;

	err = attr_is_frame_compressed(ni, attr_b, frame, &clst_data,
				       &is_compr);
	if (err)
		goto out;

	total_size -= (u64)clst_data << sbi->cluster_bits;

	len = bytes_to_cluster(sbi, compr_size);

	if (len == clst_data)
		goto out;

	if (len < clst_data) {
		err = run_deallocate_ex(sbi, run, vcn + len, clst_data - len,
					NULL, true);
		if (err)
			goto out;

		if (!run_add_entry(run, vcn + len, SPARSE_LCN,
				   clst_data - len)) {
			err = -ENOMEM;
			goto out;
		}
	} else {
		CLST alen, hint;
		/* Get the last lcn to allocate from */
		if (vcn + clst_data &&
		    !run_lookup_entry(run, vcn + clst_data - 1, &hint, NULL,
				      NULL)) {
			hint = -1;
		}

		err = attr_allocate_clusters(sbi, run, vcn + clst_data,
					     hint + 1, len - clst_data, NULL, 0,
					     &alen, 0, &lcn);
		if (err)
			goto out;
	}

	total_size += (u64)len << sbi->cluster_bits;

repack:
	err = mi_pack_runs(mi, attr, run, evcn1 - svcn);
	if (err < 0)
		goto out;

	attr_b->nres.total_size = cpu_to_le64(total_size);
	inode_set_bytes(&ni->vfs_inode, total_size);

	mi_b->dirty = true;
	mark_inode_dirty(&ni->vfs_inode);

	next_svcn = le64_to_cpu(attr->nres.evcn) + 1;

	if (next_svcn >= evcn1) {
		/* Normal way. update attribute and exit */
		goto out;
	}

	if (!ni->attr_list.size) {
		err = ni_create_attr_list(ni);
		if (err)
			goto out;
		/* layout of records is changed */
		le_b = NULL;
		attr_b = ni_find_attr(ni, NULL, &le_b, ATTR_DATA, NULL, 0, NULL,
				      &mi_b);
		if (!attr_b) {
			err = -ENOENT;
			goto out;
		}

		attr = attr_b;
		le = le_b;
		mi = mi_b;
		goto repack;
	}

	/* Estimate next attribute */
	attr = ni_find_attr(ni, attr, &le, ATTR_DATA, NULL, 0, &evcn1, &mi);

	if (attr && le32_to_cpu(mi->mrec->used) + 8 <= sbi->record_size) {
		svcn = next_svcn;
		evcn1 = le64_to_cpu(attr->nres.evcn) + 1;

		err = attr_load_runs(attr, ni, run);
		if (err)
			goto out;

		attr->nres.svcn = cpu_to_le64(svcn);
		err = mi_pack_runs(mi, attr, run, evcn1 - svcn);
		if (err < 0)
			goto out;

		le->vcn = cpu_to_le64(svcn);
		ni->attr_list.dirty = true;
		mi->dirty = true;

		next_svcn = le64_to_cpu(attr->nres.evcn) + 1;

		if (next_svcn >= evcn1) {
			/* Normal way. update attribute and exit */
			goto out;
		}
	}

	err = ni_insert_nonresident(ni, ATTR_DATA, NULL, 0, run, next_svcn,
				    evcn1 - next_svcn, attr_b->flags, &attr,
				    &mi);
	if (err)
		goto out;

	run_truncate_head(run, vcn);

out:
	if (new_valid > data_size)
		new_valid = data_size;

	valid_size = le64_to_cpu(attr_b->nres.valid_size);
	if (new_valid != valid_size) {
		attr_b->nres.valid_size = cpu_to_le64(valid_size);
		mi_b->dirty = true;
	}

	return err;
}
