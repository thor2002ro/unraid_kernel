// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005-2026 Junjiro R. Okajima
 */

/*
 * sub-routines for VFS
 */

#include <linux/filelock.h>
#include <linux/namei.h>
#include <linux/splice.h>
#include "aufs.h"

#ifdef CONFIG_AUFS_BR_FUSE
int vfsub_test_mntns(struct vfsmount *mnt, struct super_block *h_sb)
{
	if (!au_test_fuse(h_sb) || !au_userns)
		return 0;

	return our_mnt(mnt) ? 0 : -EACCES;
}
#endif

int vfsub_sync_filesystem(struct super_block *h_sb)
{
	int err;

	lockdep_off();
	down_read(&h_sb->s_umount);
	err = sync_filesystem(h_sb);
	up_read(&h_sb->s_umount);
	lockdep_on();

	return err;
}

/* ---------------------------------------------------------------------- */

unsigned int vfsub_inode_nlink_aufs(struct inode *inode)
{
	unsigned int nlink;

	au_nlink_lock(inode);
	nlink = inode->i_nlink;
	au_nlink_unlock(inode);

	return nlink;
}

void vfsub_inc_nlink(struct inode *inode)
{
	au_nlink_lock(inode);
	inc_nlink(inode);
	au_nlink_unlock(inode);
}

void vfsub_drop_nlink(struct inode *inode)
{
	au_nlink_lock(inode);
	AuDebugOn(!inode->i_nlink);
	drop_nlink(inode);
	au_nlink_unlock(inode);
}

void vfsub_clear_nlink(struct inode *inode)
{
	au_nlink_lock(inode);
	/* it can happen */
	/* AuDebugOn(!inode->i_nlink); */
	clear_nlink(inode);
	au_nlink_unlock(inode);
}

void vfsub_set_nlink(struct inode *inode, unsigned int nlink)
{
	/*
	 * stop setting the value equal to the current one, in order to stop
	 * a useless warning from vfs:destroy_inode() about sb->s_remove_count.
	 */
	au_nlink_lock(inode);
	if (nlink != inode->i_nlink)
		set_nlink(inode, nlink);
	au_nlink_unlock(inode);
}

int vfsub_update_h_iattr(const struct path *h_path, int *did)
{
	int err;
	struct kstat st;
	struct super_block *h_sb;

	/*
	 * Always needs h_path->mnt for LSM or FUSE branch.
	 */
	AuDebugOn(!h_path->mnt);

	/* for remote fs, leave work for its getattr or d_revalidate */
	/* for bad i_attr fs, handle them in aufs_getattr() */
	/* still some fs may acquire i_mutex. we need to skip them */
	err = 0;
	if (!did)
		did = &err;
	h_sb = h_path->dentry->d_sb;
	*did = (!au_test_fs_remote(h_sb) && au_test_fs_refresh_iattr(h_sb));
	if (*did)
		err = vfsub_getattr(h_path, &st);

	return err;
}

/* ---------------------------------------------------------------------- */

struct file *vfsub_dentry_open(struct path *path, int flags)
{
	return dentry_open(path, flags /* | __FMODE_NONOTIFY */,
			   current_cred());
}

struct file *vfsub_filp_open(const char *path, int oflags, int mode)
{
	struct file *file;

	lockdep_off();
	file = filp_open(path,
			 oflags /* | __FMODE_NONOTIFY */,
			 mode);
	lockdep_on();
	if (IS_ERR(file))
		goto out;
	vfsub_update_h_iattr(&file->f_path, /*did*/NULL); /*ignore*/

out:
	return file;
}

/*
 * Ideally this function should call VFS:do_last() in order to keep all its
 * checkings. But it is very hard for aufs to regenerate several VFS internal
 * structure such as nameidata. This is a second (or third) best approach.
 * cf. linux/fs/namei.c:do_last(), lookup_open() and atomic_open().
 */
int vfsub_atomic_open(struct inode *dir, struct dentry *dentry,
		      struct vfsub_aopen_args *args)
{
	int err;
	struct au_branch *br = args->br;
	struct file *file = args->file;
	/* copied from linux/fs/namei.c:atomic_open() */
	struct dentry *const DENTRY_NOT_SET = (void *)-1UL;

	IMustLock(dir);
	AuDebugOn(!dir->i_op->atomic_open);

	err = au_br_test_oflag(args->open_flag, br);
	if (unlikely(err))
		goto out;

	au_lcnt_inc(&br->br_nfiles);
	file->__f_path.dentry = DENTRY_NOT_SET;
	file->__f_path.mnt = au_br_mnt(br);
	AuDbg("%ps\n", dir->i_op->atomic_open);
	err = dir->i_op->atomic_open(dir, dentry, file, args->open_flag,
				     args->create_mode);
	if (unlikely(err < 0)) {
		au_lcnt_dec(&br->br_nfiles);
		goto out;
	}

	/* temporary workaround for nfsv4 branch */
	if (au_test_nfs(dir->i_sb))
		nfs_mark_for_revalidate(dir);

	if (file->f_mode & FMODE_CREATED)
		fsnotify_create(dir, dentry);
	if (!(file->f_mode & FMODE_OPENED)) {
		au_lcnt_dec(&br->br_nfiles);
		goto out;
	}

	/* todo: call VFS:may_open() here */
	/* todo: ima_file_check() too? */
	if (!err)
		fsnotify_open(file);
	else
		au_lcnt_dec(&br->br_nfiles);
	/* note that the file is created and still opened */

out:
	return err;
}

int vfsub_kern_path(const char *name, unsigned int flags, struct path *path)
{
	int err;

	err = kern_path(name, flags, path);
	if (!err && d_is_positive(path->dentry))
		vfsub_update_h_iattr(path, /*did*/NULL); /*ignore*/
	return err;
}

struct dentry *vfsub_lookup_one_len_unlocked(const char *name,
					     struct path *ppath, int len)
{
	struct path path;

	path.dentry = lookup_noperm_unlocked(&QSTR_LEN(name, len),
					     ppath->dentry);
	if (IS_ERR(path.dentry))
		goto out;
	if (d_is_positive(path.dentry)) {
		path.mnt = ppath->mnt;
		vfsub_update_h_iattr(&path, /*did*/NULL); /*ignore*/
	}

out:
	AuTraceErrPtr(path.dentry);
	return path.dentry;
}

struct dentry *vfsub_lookup_one_len(const char *name, struct path *ppath,
				    int len)
{
	struct path path;

	/* VFS checks it too, but by WARN_ON_ONCE() */
	IMustLock(d_inode(ppath->dentry));

	path.dentry = lookup_noperm(&QSTR_LEN(name, len), ppath->dentry);
	if (IS_ERR(path.dentry))
		goto out;
	if (d_is_positive(path.dentry)) {
		path.mnt = ppath->mnt;
		vfsub_update_h_iattr(&path, /*did*/NULL); /*ignore*/
	}

out:
	AuTraceErrPtr(path.dentry);
	return path.dentry;
}

void vfsub_call_lkup_one(void *args)
{
	struct vfsub_lkup_one_args *a = args;
	*a->errp = vfsub_lkup_one(a->name, a->ppath);
}

/* ---------------------------------------------------------------------- */

struct dentry *vfsub_lock_rename(struct dentry *d1, struct au_hinode *hdir1,
				 struct dentry *d2, struct au_hinode *hdir2)
{
	struct dentry *d;

	lockdep_off();
	d = lock_rename(d1, d2);
	lockdep_on();
	if (IS_ERR(d))
		goto out;
	au_hn_suspend(hdir1);
	if (hdir1 != hdir2)
		au_hn_suspend(hdir2);

out:
	return d;
}

void vfsub_unlock_rename(struct dentry *d1, struct au_hinode *hdir1,
			 struct dentry *d2, struct au_hinode *hdir2)
{
	au_hn_resume(hdir1);
	if (hdir1 != hdir2)
		au_hn_resume(hdir2);
	lockdep_off();
	unlock_rename(d1, d2);
	lockdep_on();
}

/* ---------------------------------------------------------------------- */

int vfsub_create(struct inode *dir, struct path *path, int mode, bool want_excl)
{
	int err, e;
	struct dentry *d;
	struct inode *inode;
	struct mnt_idmap *idmap;
	struct delegated_inode deleg = {};

	IMustLock(dir);

	d = path->dentry;
	path->dentry = d->d_parent;
	inode = d_inode(path->dentry);
	err = security_path_mknod(path, d, mode_strip_umask(inode, mode), 0);
	path->dentry = d;
	if (unlikely(err))
		goto out;

	idmap = mnt_idmap(path->mnt);
	do {
		lockdep_off();
		err = vfs_create(idmap, d, mode, &deleg);
		lockdep_on();
		if (is_delegated(&deleg)) {
			e = break_deleg_wait(&deleg);
			if (!e)
				continue;
		}
		break;
	} while (1);
	if (!err) {
		struct path tmp = *path;
		int did;

		security_path_post_mknod(idmap, d);
		vfsub_update_h_iattr(&tmp, &did);
		if (did) {
			tmp.dentry = path->dentry->d_parent;
			vfsub_update_h_iattr(&tmp, /*did*/NULL);
		}
		/*ignore*/
	}

out:
	return err;
}

int vfsub_symlink(struct inode *dir, struct path *path, const char *symname)
{
	int err, e;
	struct dentry *d;
	struct mnt_idmap *idmap;
	struct delegated_inode deleg = {};

	IMustLock(dir);

	d = path->dentry;
	path->dentry = d->d_parent;
	err = security_path_symlink(path, d, symname);
	path->dentry = d;
	if (unlikely(err))
		goto out;

	idmap = mnt_idmap(path->mnt);
	do {
		lockdep_off();
		err = vfs_symlink(idmap, dir, d, symname, &deleg);
		lockdep_on();
		if (is_delegated(&deleg)) {
			e = break_deleg_wait(&deleg);
			if (!e)
				continue;
		}
		break;
	} while (1);
	if (!err) {
		struct path tmp = *path;
		int did;

		vfsub_update_h_iattr(&tmp, &did);
		if (did) {
			tmp.dentry = path->dentry->d_parent;
			vfsub_update_h_iattr(&tmp, /*did*/NULL);
		}
		/*ignore*/
	}

out:
	return err;
}

int vfsub_mknod(struct inode *dir, struct path *path, int mode, dev_t dev)
{
	int err, e;
	struct dentry *d;
	struct inode *inode;
	struct mnt_idmap *idmap;
	struct delegated_inode deleg = {};

	IMustLock(dir);

	d = path->dentry;
	path->dentry = d->d_parent;
	inode = d_inode(path->dentry);
	err = security_path_mknod(path, d, mode_strip_umask(inode, mode),
				  new_encode_dev(dev));
	path->dentry = d;
	if (unlikely(err))
		goto out;

	idmap = mnt_idmap(path->mnt);
	do {
		lockdep_off();
		err = vfs_mknod(idmap, dir, path->dentry, mode, dev, &deleg);
		lockdep_on();
		if (is_delegated(&deleg)) {
			e = break_deleg_wait(&deleg);
			if (!e)
				continue;
		}
		break;
	} while (1);
	if (!err) {
		struct path tmp = *path;
		int did;

		vfsub_update_h_iattr(&tmp, &did);
		if (did) {
			tmp.dentry = path->dentry->d_parent;
			vfsub_update_h_iattr(&tmp, /*did*/NULL);
		}
		/*ignore*/
	}

out:
	return err;
}

static int au_test_nlink(struct inode *inode)
{
	const unsigned int link_max = UINT_MAX >> 1; /* rough margin */

	if (!au_test_fs_no_limit_nlink(inode->i_sb)
	    || vfsub_inode_nlink(inode, AU_I_BRANCH) < link_max)
		return 0;
	return -EMLINK;
}

int vfsub_link(struct dentry *src_dentry, struct inode *dir, struct path *path)
{
	int err, e;
	struct dentry *d;
	struct mnt_idmap *idmap;
	struct delegated_inode deleg = {};

	IMustLock(dir);

	err = au_test_nlink(d_inode(src_dentry));
	if (unlikely(err))
		return err;

	/* we don't call may_linkat() */
	d = path->dentry;
	path->dentry = d->d_parent;
	err = security_path_link(src_dentry, path, d);
	path->dentry = d;
	if (unlikely(err))
		goto out;

	idmap = mnt_idmap(path->mnt);
	do {
		lockdep_off();
		err = vfs_link(src_dentry, idmap, dir, path->dentry, &deleg);
		lockdep_on();
		if (is_delegated(&deleg)) {
			e = break_deleg_wait(&deleg);
			if (!e)
				continue;
		}
		break;
	} while (1);
	if (!err) {
		struct path tmp = *path;
		int did;

		/* fuse has different memory inode for the same inumber */
		vfsub_update_h_iattr(&tmp, &did);
		if (did) {
			tmp.dentry = path->dentry->d_parent;
			vfsub_update_h_iattr(&tmp, /*did*/NULL);
			tmp.dentry = src_dentry;
			vfsub_update_h_iattr(&tmp, /*did*/NULL);
		}
		/*ignore*/
	}

out:
	return err;
}

int vfsub_rename(struct inode *src_dir, struct dentry *src_dentry,
		 struct inode *dir, struct path *path, unsigned int flags)
{
	int err, e;
	struct renamedata rd;
	struct delegated_inode deleg = {};
	struct path tmp = {
		.mnt	= path->mnt
	};
	struct dentry *d;

	IMustLock(dir);
	IMustLock(src_dir);

	d = path->dentry;
	path->dentry = d->d_parent;
	tmp.dentry = src_dentry->d_parent;
	err = security_path_rename(&tmp, src_dentry, path, d, /*flags*/0);
	path->dentry = d;
	if (unlikely(err))
		goto out;

	rd.mnt_idmap = mnt_idmap(path->mnt);
	rd.old_dentry = src_dentry;
	rd.old_parent = rd.old_dentry->d_parent;
	rd.new_dentry = path->dentry;
	rd.new_parent = rd.new_dentry->d_parent;
	rd.delegated_inode = &deleg;
	rd.flags = flags;
	do {
		lockdep_off();
		err = vfs_rename(&rd);
		lockdep_on();
		if (is_delegated(&deleg)) {
			e = break_deleg_wait(&deleg);
			if (!e)
				continue;
		}
		break;
	} while (1);
	if (!err) {
		int did;

		tmp.dentry = d->d_parent;
		vfsub_update_h_iattr(&tmp, &did);
		if (did) {
			tmp.dentry = src_dentry;
			vfsub_update_h_iattr(&tmp, /*did*/NULL);
			tmp.dentry = src_dentry->d_parent;
			vfsub_update_h_iattr(&tmp, /*did*/NULL);
		}
		/*ignore*/
	}

out:
	return err;
}

struct dentry *vfsub_mkdir(struct inode *dir, struct path *path, int mode)
{
	int err, e, did;
	struct dentry *d, *ret;
	struct inode *inode;
	struct mnt_idmap *idmap;
	struct path tmp;
	struct delegated_inode deleg = {};

	IMustLock(dir);

	d = path->dentry;
	path->dentry = d->d_parent;
	inode = d_inode(path->dentry);
	err = security_path_mkdir(path, d, mode_strip_umask(inode, mode));
	path->dentry = d;
	ret = ERR_PTR(err);
	if (unlikely(err))
		goto out;

	idmap = mnt_idmap(path->mnt);
	do {
		/* on error, vfs_mkdir() calls dput() */
		/* and unlocks the parent dir. Ouch! */
		dget(d);
		lockdep_off();
		ret = vfs_mkdir(idmap, dir, d, mode, &deleg);
		if (IS_ERR(ret))
			inode_lock(dir);
		lockdep_on();
		if (is_delegated(&deleg)) {
			e = break_deleg_wait(&deleg);
			if (!e)
				continue;
		}
		break;
	} while (1);
	if (IS_ERR(ret))
		goto out;
	dput(d);

	tmp = *path;
	if (ret)
		tmp.dentry = ret;
	vfsub_update_h_iattr(&tmp, &did); /*ignore*/
	if (did) {
		tmp.dentry = tmp.dentry->d_parent;
		vfsub_update_h_iattr(&tmp, /*did*/NULL); /*ignore*/
	}

out:
	return ret;
}

int vfsub_rmdir(struct inode *dir, struct path *path)
{
	int err, e;
	struct dentry *d;
	struct mnt_idmap *idmap;
	struct delegated_inode deleg = {};

	IMustLock(dir);

	d = path->dentry;
	path->dentry = d->d_parent;
	err = security_path_rmdir(path, d);
	path->dentry = d;
	if (unlikely(err))
		goto out;

	idmap = mnt_idmap(path->mnt);
	do {
		lockdep_off();
		err = vfs_rmdir(idmap, dir, d, &deleg);
		lockdep_on();
		if (is_delegated(&deleg)) {
			e = break_deleg_wait(&deleg);
			if (!e)
				continue;
		}
		break;
	} while (1);
	if (!err) {
		struct path tmp = {
			.dentry	= path->dentry->d_parent,
			.mnt	= path->mnt
		};

		vfsub_update_h_iattr(&tmp, /*did*/NULL); /*ignore*/
	}

out:
	return err;
}

/* ---------------------------------------------------------------------- */

/* todo: support mmap_sem? */
ssize_t vfsub_read_u(struct file *file, char __user *ubuf, size_t count,
		     loff_t *ppos)
{
	ssize_t err;

	lockdep_off();
	err = vfs_read(file, ubuf, count, ppos);
	lockdep_on();
	if (err >= 0)
		vfsub_update_h_iattr(&file->f_path, /*did*/NULL); /*ignore*/
	return err;
}

ssize_t vfsub_read_k(struct file *file, void *kbuf, size_t count,
		     loff_t *ppos)
{
	ssize_t err;

	lockdep_off();
	err = kernel_read(file, kbuf, count, ppos);
	lockdep_on();
	AuTraceErr(err);
	if (err >= 0)
		vfsub_update_h_iattr(&file->f_path, /*did*/NULL); /*ignore*/
	return err;
}

ssize_t vfsub_write_u(struct file *file, const char __user *ubuf, size_t count,
		      loff_t *ppos)
{
	ssize_t err;

	lockdep_off();
	err = vfs_write(file, ubuf, count, ppos);
	lockdep_on();
	if (err >= 0)
		vfsub_update_h_iattr(&file->f_path, /*did*/NULL); /*ignore*/
	return err;
}

ssize_t vfsub_write_k(struct file *file, void *kbuf, size_t count, loff_t *ppos)
{
	ssize_t err;

	lockdep_off();
	err = kernel_write(file, kbuf, count, ppos);
	lockdep_on();
	if (err >= 0)
		vfsub_update_h_iattr(&file->f_path, /*did*/NULL); /*ignore*/
	return err;
}

int vfsub_flush(struct file *file, fl_owner_t id)
{
	int err;

	err = 0;
	if (file->f_op->flush) {
		if (!au_test_nfs(file->f_path.dentry->d_sb))
			err = file->f_op->flush(file, id);
		else {
			lockdep_off();
			err = file->f_op->flush(file, id);
			lockdep_on();
		}
		if (!err)
			vfsub_update_h_iattr(&file->f_path, /*did*/NULL);
		/*ignore*/
	}
	return err;
}

int vfsub_iterate_dir(struct file *file, struct dir_context *ctx)
{
	int err;

	AuDbg("%pD, ctx{%ps, %llu}\n", file, ctx->actor, ctx->pos);

	lockdep_off();
	err = iterate_dir(file, ctx);
	lockdep_on();
	if (err >= 0)
		vfsub_update_h_iattr(&file->f_path, /*did*/NULL); /*ignore*/

	return err;
}

ssize_t vfsub_splice_read(struct file *in, loff_t *ppos,
			  struct pipe_inode_info *pipe, size_t len,
			  unsigned int flags)
{
	ssize_t err;

	lockdep_off();
	err = vfs_splice_read(in, ppos, pipe, len, flags);
	lockdep_on();
	file_accessed(in);
	if (err >= 0)
		vfsub_update_h_iattr(&in->f_path, /*did*/NULL); /*ignore*/
	return err;
}

ssize_t vfsub_splice_from(struct pipe_inode_info *pipe, struct file *out,
			  loff_t *ppos, size_t len, unsigned int flags)
{
	ssize_t err;

	lockdep_off();
	err = do_splice_from(pipe, out, ppos, len, flags);
	lockdep_on();
	if (err >= 0)
		vfsub_update_h_iattr(&out->f_path, /*did*/NULL); /*ignore*/
	return err;
}

int vfsub_fsync(struct file *file, const struct path *path, int datasync)
{
	int err;

	/* file can be NULL */
	lockdep_off();
	err = vfs_fsync(file, datasync);
	lockdep_on();
	if (!err) {
		if (!path) {
			AuDebugOn(!file);
			path = &file->f_path;
		}
		vfsub_update_h_iattr(path, /*did*/NULL); /*ignore*/
	}
	return err;
}

/* cf. open.c:do_sys_truncate() and do_sys_ftruncate() */
int vfsub_trunc(const struct path *h_path, loff_t length, unsigned int attr,
		struct file *h_file)
{
	int err;
	struct inode *h_inode;
	struct super_block *h_sb;
	struct mnt_idmap *h_idmap;

	if (!h_file) {
		err = vfsub_truncate(h_path, length);
		goto out;
	}

	err = security_file_truncate(h_file);
	if (err)
		goto out;
	err = fsnotify_truncate_perm(&h_file->f_path, length);
	if (err)
		goto out;
	h_idmap = mnt_idmap(h_path->mnt);
	h_inode = d_inode(h_path->dentry);
	h_sb = h_inode->i_sb;
	lockdep_off();
	scoped_guard(super_write, h_sb)
		err = do_truncate(h_idmap, h_path->dentry, length, attr,
				  h_file);
	lockdep_on();

out:
	return err;
}

/* ---------------------------------------------------------------------- */

struct au_vfsub_mkdir_args {
	struct dentry **errp;
	struct inode *dir;
	struct path *path;
	int mode;
};

static void au_call_vfsub_mkdir(void *args)
{
	struct au_vfsub_mkdir_args *a = args;
	*a->errp = vfsub_mkdir(a->dir, a->path, a->mode);
}

struct dentry *vfsub_sio_mkdir(struct inode *dir, struct path *path, int mode)
{
	int err, do_sio;
	struct mnt_idmap *idmap;
	struct dentry *ret;

	idmap = mnt_idmap(path->mnt);
	do_sio = au_test_h_perm_sio(idmap, dir, MAY_EXEC | MAY_WRITE);
	if (!do_sio)
		ret = vfsub_mkdir(dir, path, mode);
	else {
		struct au_vfsub_mkdir_args args = {
			.errp	= &ret,
			.dir	= dir,
			.path	= path,
			.mode	= mode
		};
		err = au_wkq_wait(au_call_vfsub_mkdir, &args);
		if (unlikely(err))
			ret = ERR_PTR(err);
	}

	return ret;
}

struct au_vfsub_rmdir_args {
	int *errp;
	struct inode *dir;
	struct path *path;
};

static void au_call_vfsub_rmdir(void *args)
{
	struct au_vfsub_rmdir_args *a = args;
	*a->errp = vfsub_rmdir(a->dir, a->path);
}

int vfsub_sio_rmdir(struct inode *dir, struct path *path)
{
	int err, do_sio, wkq_err;
	struct mnt_idmap *idmap;

	idmap = mnt_idmap(path->mnt);
	do_sio = au_test_h_perm_sio(idmap, dir, MAY_EXEC | MAY_WRITE);
	if (!do_sio) {
		lockdep_off();
		err = vfsub_rmdir(dir, path);
		lockdep_on();
	} else {
		struct au_vfsub_rmdir_args args = {
			.errp	= &err,
			.dir	= dir,
			.path	= path
		};
		wkq_err = au_wkq_wait(au_call_vfsub_rmdir, &args);
		if (unlikely(wkq_err))
			err = wkq_err;
	}

	return err;
}

/* ---------------------------------------------------------------------- */

struct notify_change_args {
	int *errp;
	const struct path *path;
	struct iattr *ia;
};

static void call_notify_change(void *args)
{
	struct notify_change_args *a = args;
	struct inode *h_inode;
	struct mnt_idmap *idmap;
	struct delegated_inode deleg = {};

	h_inode = d_inode(a->path->dentry);
	IMustLock(h_inode);

	*a->errp = -EPERM;
	if (IS_IMMUTABLE(h_inode) || IS_APPEND(h_inode))
		goto out;

	idmap = mnt_idmap(a->path->mnt);
	do {
		lockdep_off();
		*a->errp = notify_change(idmap, a->path->dentry, a->ia, &deleg);
		lockdep_on();
		if (is_delegated(&deleg)) {
			int e;

			e = break_deleg_wait(&deleg);
			if (!e)
				continue;
		}
		break;
	} while (1);
	if (!*a->errp)
		vfsub_update_h_iattr(a->path, /*did*/NULL); /*ignore*/

out:
	AuTraceErr(*a->errp);
}

int vfsub_notify_change(const struct path *path, struct iattr *ia)
{
	int err;
	struct notify_change_args args = {
		.errp	= &err,
		.path	= path,
		.ia	= ia
	};

	call_notify_change(&args);

	return err;
}

int vfsub_sio_notify_change(struct path *path, struct iattr *ia)
{
	int err, wkq_err;
	struct notify_change_args args = {
		.errp	= &err,
		.path	= path,
		.ia	= ia
	};

	wkq_err = au_wkq_wait(call_notify_change, &args);
	if (unlikely(wkq_err))
		err = wkq_err;

	return err;
}

/* ---------------------------------------------------------------------- */

struct unlink_args {
	int *errp;
	struct inode *dir;
	const struct path *path;
};

static void call_unlink(void *args)
{
	struct unlink_args *a = args;
	struct dentry *d = a->path->dentry;
	struct inode *h_inode;
	struct mnt_idmap *idmap;
	struct delegated_inode deleg = {};
	const int stop_sillyrename = (au_test_nfs(d->d_sb)
				      && au_dcount(d) == 1);
	struct path tmp = {
		.dentry = d->d_parent,
		.mnt	= a->path->mnt
	};

	IMustLock(a->dir);

	*a->errp = security_path_unlink(&tmp, d);
	if (unlikely(*a->errp))
		return;

	if (!stop_sillyrename)
		dget(d);
	h_inode = NULL;
	if (d_is_positive(d)) {
		h_inode = d_inode(d);
		ihold(h_inode);
	}

	idmap = mnt_idmap(a->path->mnt);
	do {
		lockdep_off();
		*a->errp = vfs_unlink(idmap, a->dir, d, &deleg);
		lockdep_on();
		if (is_delegated(&deleg)) {
			int e;

			e = break_deleg_wait(&deleg);
			if (!e)
				continue;
		}
		break;
	} while (1);
	if (!*a->errp)
		vfsub_update_h_iattr(&tmp, /*did*/NULL); /*ignore*/

	if (!stop_sillyrename)
		dput(d);
	if (h_inode)
		iput(h_inode);

	AuTraceErr(*a->errp);
}

/*
 * @dir: must be locked.
 * @dentry: target dentry.
 */
int vfsub_unlink(struct inode *dir, const struct path *path, int force)
{
	int err;
	struct unlink_args args = {
		.errp	= &err,
		.dir	= dir,
		.path	= path
	};

	if (!force)
		call_unlink(&args);
	else {
		int wkq_err;

		wkq_err = au_wkq_wait(call_unlink, &args);
		if (unlikely(wkq_err))
			err = wkq_err;
	}

	return err;
}
