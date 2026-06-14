/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2017-2026 Junjiro R. Okajima
 */

/*
 * helpers for hlist_bl.h
 */

#ifndef __AUFS_HBL_H__
#define __AUFS_HBL_H__

#ifdef __KERNEL__

#include <linux/list_bl.h>

static inline void au_hbl_add(struct hlist_bl_node *node,
			      struct hlist_bl_head *hbl)
{
	hlist_bl_lock(hbl);
	hlist_bl_add_head(node, hbl);
	hlist_bl_unlock(hbl);
}

static inline void au_hbl_del(struct hlist_bl_node *node,
			      struct hlist_bl_head *hbl)
{
	hlist_bl_lock(hbl);
	hlist_bl_del(node);
	hlist_bl_unlock(hbl);
}

#define au_hbl_for_each(pos, head)					\
	for (pos = hlist_bl_first(head);				\
	     pos;							\
	     pos = pos->next)

static inline unsigned long au_hbl_count(struct hlist_bl_head *hbl)
{
	unsigned long cnt;
	struct hlist_bl_node *pos;

	cnt = 0;
	hlist_bl_lock(hbl);
	au_hbl_for_each(pos, hbl)
		cnt++;
	hlist_bl_unlock(hbl);
	return cnt;
}

#endif /* __KERNEL__ */
#endif /* __AUFS_HBL_H__ */
