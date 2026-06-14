/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2010-2026 Junjiro R. Okajima
 */

/*
 * dynamically customizable operations (for regular files only)
 */

#ifndef __AUFS_DYNOP_H__
#define __AUFS_DYNOP_H__

#ifdef __KERNEL__

#include <linux/fs.h>
#include <linux/kref.h>

enum {AuDy_AOP, AuDyLast};

struct au_dynop {
	int						dy_type;
	union {
		const void				*dy_hop;
		const struct address_space_operations	*dy_haop;
	};
};

struct au_dykey {
	union {
		struct hlist_bl_node	dk_hnode;
		struct rcu_head		dk_rcu;
	};
	struct au_dynop		dk_op;

	/*
	 * during I am in the branch local array, kref is gotten. when the
	 * branch is removed, kref is put.
	 */
	struct kref		dk_kref;
};

/* stop unioning since their sizes are very different from each other */
struct au_dyaop {
	struct au_dykey			da_key;
	struct address_space_operations	da_op; /* not const */
};
/* make sure that 'struct au_dykey *' can be any type */
static_assert(!offsetof(struct au_dyaop, da_key));

/* ---------------------------------------------------------------------- */

/* dynop.c */
struct au_branch;
void au_dy_put(struct au_dykey *key);
int au_dy_iaop(struct inode *inode, aufs_bindex_t bindex,
		struct inode *h_inode);
int au_dy_irefresh(struct inode *inode);
void au_dy_arefresh(int do_dio);

void __init au_dy_init(void);
void au_dy_fin(void);

#endif /* __KERNEL__ */
#endif /* __AUFS_DYNOP_H__ */
