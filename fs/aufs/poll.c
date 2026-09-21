// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2026 Junjiro R. Okajima
 */

/*
 * poll operation
 * There is only one filesystem which implements ->poll operation, currently.
 */

#include "aufs.h"

__poll_t aufs_poll(struct file *file, struct poll_table_struct *pt)
{
	__poll_t mask;
	struct file *h_file;
	struct super_block *sb;

	/* We should pretend an error happened. */
	mask = EPOLLERR /* | EPOLLIN | EPOLLOUT */;
	sb = file->f_path.dentry->d_sb;
	si_read_lock(sb, AuLock_FLUSH | AuLock_NOPLMW);

	h_file = au_read_pre(file, /*keep_fi*/0, /*lsc*/0);
	if (IS_ERR(h_file)) {
		AuDbg("h_file %ld\n", PTR_ERR(h_file));
		goto out;
	}

	mask = vfs_poll(h_file, pt);
	fput(h_file); /* instead of au_read_post() */

out:
	si_read_unlock(sb);
	if (mask & EPOLLERR)
		AuDbg("mask 0x%x\n", mask);
	return mask;
}
