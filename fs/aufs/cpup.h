/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2005-2026 Junjiro R. Okajima
 */

/*
 * copy-up/down functions
 */

#ifndef __AUFS_CPUP_H__
#define __AUFS_CPUP_H__

#ifdef __KERNEL__

#include <linux/path.h>
#include <linux/time.h>

struct inode;
struct file;
struct au_pin;

void au_cpup_attr_flags(struct inode *dst, unsigned int iflags);
void au_cpup_attr_timesizes(struct inode *inode);
void au_cpup_attr_nlink(struct inode *inode, int force);
void au_cpup_attr_changeable(struct inode *inode);
void au_cpup_igen(struct inode *inode, struct inode *h_inode);
void au_cpup_attr_all(struct inode *inode, int force);

/* ---------------------------------------------------------------------- */

struct au_cp_generic {
	struct dentry	*dentry;
	aufs_bindex_t	bdst, bsrc;
	loff_t		len;
	struct au_pin	*pin;
	unsigned int	flags;
};

/* cpup flags */
#define AuCpup_DTIME		BIT(0)		/* do dtime_store/revert */
#define AuCpup_KEEPLINO		BIT(1)		/* do not clear the lower xino,
						   for link(2) */
#define AuCpup_RENAME		BIT(2)		/* rename after cpup */
#define AuCpup_HOPEN		BIT(3)		/* call h_open_pre/post() in
						   cpup */
#define AuCpup_OVERWRITE	BIT(4)		/* allow overwriting the
						   existing entry */
#define AuCpup_RWDST		BIT(5)		/* force write target even if
						   the branch is marked as RO */

#ifndef CONFIG_AUFS_BR_HFSPLUS
#undef AuCpup_HOPEN
#define AuCpup_HOPEN		0
#endif

#define au_ftest_cpup(flags, name)	((flags) & AuCpup_##name)
#define au_fset_cpup(flags, name) \
	do { (flags) |= AuCpup_##name; } while (0)
#define au_fclr_cpup(flags, name) \
	do { (flags) &= ~AuCpup_##name; } while (0)

int au_copy_file(struct file *dst, struct file *src, loff_t len);
int au_sio_cpup_simple(struct au_cp_generic *cpg);
int au_sio_cpdown_simple(struct au_cp_generic *cpg);
int au_sio_cpup_wh(struct au_cp_generic *cpg, struct file *file);

int au_cp_dirs(struct dentry *dentry, aufs_bindex_t bdst,
	       int (*cp)(struct dentry *dentry, aufs_bindex_t bdst,
			 struct au_pin *pin,
			 struct dentry *h_parent, void *arg),
	       void *arg);
int au_cpup_dirs(struct dentry *dentry, aufs_bindex_t bdst);
int au_test_and_cpup_dirs(struct dentry *dentry, aufs_bindex_t bdst);

/* ---------------------------------------------------------------------- */

/* keep timestamps when copyup */
struct au_dtime {
	struct dentry *dt_dentry;
	struct path dt_h_path;
	struct timespec64 dt_atime, dt_mtime;
};
void au_dtime_store(struct au_dtime *dt, struct dentry *dentry,
		    struct path *h_path);
void au_dtime_revert(struct au_dtime *dt);

#endif /* __KERNEL__ */
#endif /* __AUFS_CPUP_H__ */
