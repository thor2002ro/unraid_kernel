// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025-2026 Junjiro R. Okajima
 */

/*
 * mmapped files.
 */

#include "aufs.h"

/*
 * File hashtable.
 * It identifies aufs file by branch's file as a key.
 * Used by customized file_user_path() and file_user_inode() in
 * include/linux/fs.h.
 * This table doesn't make get/put call for the elements.
 *
 * INIT_HLIST_BL_HEAD() sets NULL to its member, so we can skip it since this is
 * 'static'.
 */
#define N 0x0ff
static struct hlist_bl_head au_mmapped_finfo[N + 1];

static unsigned int au_mf_hash(const struct file *h_file)
{
	uintptr_t ptr;

	BUILD_BUG_ON(sizeof(ptr) < sizeof(h_file));
	ptr = (uintptr_t)h_file;
	return (ptr >> 8) & N;
}

void au_mf_add(struct file *h_file, struct file *file)
{
	struct au_finfo *finfo;
	unsigned int hash;
	struct hlist_bl_head *hbl_head;

	finfo = au_fi(file);
	AuDebugOn(!au_test_mmapped(file));
	if (atomic_read(&finfo->fi_mmapped) == 1) {
		hash = au_mf_hash(h_file);
		hbl_head = au_mmapped_finfo + hash;
		au_hbl_add(&finfo->fi_mf, hbl_head);
	}
}

void au_mf_del(struct file *h_file, struct file *file)
{
	struct au_finfo *finfo;
	unsigned int hash;
	struct hlist_bl_head *hbl_head;

	finfo = au_fi(file);
	hash = au_mf_hash(h_file);
	hbl_head = au_mmapped_finfo + hash;
	au_hbl_del(&finfo->fi_mf, hbl_head);
}

static struct file *au_mf_find(const struct file *h_file)
{
	struct file *found;
	unsigned int hash;
	struct hlist_bl_head *hbl_head;
	struct hlist_bl_node *hbl_node;
	struct au_finfo *finfo;
	struct au_hfile *hfile;

	found = NULL;
	hash = au_mf_hash(h_file);
	hbl_head = au_mmapped_finfo + hash;
	hlist_bl_lock(hbl_head);
	au_hbl_for_each(hbl_node, hbl_head) {
		if (!hbl_node)
			continue;

		finfo = container_of(hbl_node, struct au_finfo, fi_mf);
		hfile = &finfo->fi_htop;
		if (hfile->hf_file == h_file) {
			found = finfo->fi_file;
			break;
		}
	}
	hlist_bl_unlock(hbl_head);

	return found;
}

/* ---------------------------------------------------------------------- */
/* declared in include/linux/fs.h */

const struct path *au_do_file_user_path(const struct file *h_file)
{
	const struct path *path;
	struct file *file;

	path = NULL;
	file = au_mf_find(h_file);
	if (file)
		path = &file->f_path;

	return path;
}
EXPORT_SYMBOL_GPL(au_do_file_user_path);

const struct inode *au_do_file_user_inode(const struct file *h_file)
{
	struct inode *inode;
	struct file *file;

	inode = NULL;
	file = au_mf_find(h_file);
	if (file)
		inode = file->f_inode;

	return inode;
}
EXPORT_SYMBOL_GPL(au_do_file_user_inode);
