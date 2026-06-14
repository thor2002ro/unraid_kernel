// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2014-2026 Junjiro R. Okajima
 */

/*
 * posix acl operations
 */

#include <linux/fs.h>
#include "aufs.h"

struct posix_acl *aufs_get_inode_acl(struct inode *inode, int type, bool rcu)
{
	struct posix_acl *acl;
	int err;
	aufs_bindex_t bindex;
	struct inode *h_inode;
	struct super_block *sb;

	acl = ERR_PTR(-ECHILD);
	if (rcu)
		goto out;

	acl = NULL;
	sb = inode->i_sb;
	si_read_lock(sb, AuLock_FLUSH);
	ii_read_lock_child(inode);
	if (!(sb->s_flags & SB_POSIXACL))
		goto unlock;

	bindex = au_ibtop(inode);
	h_inode = au_h_iptr(inode, bindex);
	if (unlikely(!h_inode
		     || ((h_inode->i_mode & S_IFMT)
			 != (inode->i_mode & S_IFMT)))) {
		err = au_busy_or_stale();
		acl = ERR_PTR(err);
		goto unlock;
	}

	/* always topmost only */
	acl = get_inode_acl(h_inode, type);
	if (IS_ERR(acl))
		forget_cached_acl(inode, type);
	else
		set_cached_acl(inode, type, acl);

unlock:
	ii_read_unlock(inode);
	si_read_unlock(sb);

out:
	AuTraceErrPtr(acl);
	return acl;
}

struct posix_acl *aufs_get_acl(struct mnt_idmap *idmap, struct dentry *dentry,
			       int type)
{
	struct posix_acl *acl;
	struct inode *inode;

	inode = d_inode(dentry);
	acl = aufs_get_inode_acl(inode, type, /*rcu*/false);

	return acl;
}

int aufs_set_acl(struct mnt_idmap *idmap, struct dentry *dentry,
		 struct posix_acl *acl, int type)
{
	int err;
	ssize_t ssz;
	struct inode *inode;
	struct au_sxattr arg = {
		.type = AU_ACL_SET,
		.u.acl_set = {
			.acl	= acl,
			.type	= type
		},
	};

	inode = d_inode(dentry);
	IMustLock(inode);

	ssz = au_sxattr(dentry, inode, &arg);
	/* forget even it if succeeds since the branch might set differently */
	forget_cached_acl(inode, type);
	err = ssz;
	if (ssz >= 0)
		err = 0;

	return err;
}
