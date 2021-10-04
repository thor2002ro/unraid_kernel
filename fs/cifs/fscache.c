// SPDX-License-Identifier: LGPL-2.1
/*
 *   CIFS filesystem cache interface
 *
 *   Copyright (c) 2010 Novell, Inc.
 *   Author(s): Suresh Jayaraman <sjayaraman@suse.de>
 *
 */
#include "fscache.h"
#include "cifsglob.h"
#include "cifs_debug.h"
#include "cifs_fs_sb.h"
#include "cifsproto.h"

/*
 * Key layout of CIFS server cache index object
 */
struct cifs_server_key {
	struct {
		uint16_t	family;		/* address family */
		__be16		port;		/* IP port */
	} hdr;
	union {
		struct in_addr	ipv4_addr;
		struct in6_addr	ipv6_addr;
	};
} __packed;

/*
 * Get a cookie for a server object keyed by {IPaddress,port,family} tuple
 */
void cifs_fscache_get_client_cookie(struct TCP_Server_Info *server)
{
	const struct sockaddr *sa = (struct sockaddr *) &server->dstaddr;
	const struct sockaddr_in *addr = (struct sockaddr_in *) sa;
	const struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) sa;
	struct cifs_server_key key;
	uint16_t key_len = sizeof(key.hdr);

	memset(&key, 0, sizeof(key));

	/*
	 * Should not be a problem as sin_family/sin6_family overlays
	 * sa_family field
	 */
	key.hdr.family = sa->sa_family;
	switch (sa->sa_family) {
	case AF_INET:
		key.hdr.port = addr->sin_port;
		key.ipv4_addr = addr->sin_addr;
		key_len += sizeof(key.ipv4_addr);
		break;

	case AF_INET6:
		key.hdr.port = addr6->sin6_port;
		key.ipv6_addr = addr6->sin6_addr;
		key_len += sizeof(key.ipv6_addr);
		break;

	default:
		cifs_dbg(VFS, "Unknown network family '%d'\n", sa->sa_family);
		server->fscache = NULL;
		return;
	}

	server->fscache =
		fscache_acquire_cookie(cifs_fscache_netfs.primary_index,
				       &cifs_fscache_server_index_def,
				       &key, key_len,
				       NULL, 0,
				       server, 0, true);
	cifs_dbg(FYI, "%s: (0x%p/0x%p)\n",
		 __func__, server, server->fscache);
}

void cifs_fscache_release_client_cookie(struct TCP_Server_Info *server)
{
	cifs_dbg(FYI, "%s: (0x%p/0x%p)\n",
		 __func__, server, server->fscache);
	fscache_relinquish_cookie(server->fscache, NULL, false);
	server->fscache = NULL;
}

void cifs_fscache_get_super_cookie(struct cifs_tcon *tcon)
{
	struct TCP_Server_Info *server = tcon->ses->server;
	char *sharename;
	struct cifs_fscache_super_auxdata auxdata;

	sharename = extract_sharename(tcon->treeName);
	if (IS_ERR(sharename)) {
		cifs_dbg(FYI, "%s: couldn't extract sharename\n", __func__);
		tcon->fscache = NULL;
		return;
	}

	memset(&auxdata, 0, sizeof(auxdata));
	auxdata.resource_id = tcon->resource_id;
	auxdata.vol_create_time = tcon->vol_create_time;
	auxdata.vol_serial_number = tcon->vol_serial_number;

	tcon->fscache =
		fscache_acquire_cookie(server->fscache,
				       &cifs_fscache_super_index_def,
				       sharename, strlen(sharename),
				       &auxdata, sizeof(auxdata),
				       tcon, 0, true);
	kfree(sharename);
	cifs_dbg(FYI, "%s: (0x%p/0x%p)\n",
		 __func__, server->fscache, tcon->fscache);
}

void cifs_fscache_release_super_cookie(struct cifs_tcon *tcon)
{
	struct cifs_fscache_super_auxdata auxdata;

	memset(&auxdata, 0, sizeof(auxdata));
	auxdata.resource_id = tcon->resource_id;
	auxdata.vol_create_time = tcon->vol_create_time;
	auxdata.vol_serial_number = tcon->vol_serial_number;

	cifs_dbg(FYI, "%s: (0x%p)\n", __func__, tcon->fscache);
	fscache_relinquish_cookie(tcon->fscache, &auxdata, false);
	tcon->fscache = NULL;
}

static void cifs_fscache_acquire_inode_cookie(struct cifsInodeInfo *cifsi,
					      struct cifs_tcon *tcon)
{
	struct cifs_fscache_inode_auxdata auxdata;

	memset(&auxdata, 0, sizeof(auxdata));
	auxdata.eof = cifsi->server_eof;
	auxdata.last_write_time_sec = cifsi->vfs_inode.i_mtime.tv_sec;
	auxdata.last_change_time_sec = cifsi->vfs_inode.i_ctime.tv_sec;
	auxdata.last_write_time_nsec = cifsi->vfs_inode.i_mtime.tv_nsec;
	auxdata.last_change_time_nsec = cifsi->vfs_inode.i_ctime.tv_nsec;

	cifsi->fscache =
		fscache_acquire_cookie(tcon->fscache,
				       &cifs_fscache_inode_object_def,
				       &cifsi->uniqueid, sizeof(cifsi->uniqueid),
				       &auxdata, sizeof(auxdata),
				       cifsi, cifsi->vfs_inode.i_size, true);
}

static void cifs_fscache_enable_inode_cookie(struct inode *inode)
{
	struct cifsInodeInfo *cifsi = CIFS_I(inode);
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct cifs_tcon *tcon = cifs_sb_master_tcon(cifs_sb);

	if (cifsi->fscache)
		return;

	if (!(cifs_sb->mnt_cifs_flags & CIFS_MOUNT_FSCACHE))
		return;

	cifs_fscache_acquire_inode_cookie(cifsi, tcon);

	cifs_dbg(FYI, "%s: got FH cookie (0x%p/0x%p)\n",
		 __func__, tcon->fscache, cifsi->fscache);
}

void cifs_fscache_release_inode_cookie(struct inode *inode)
{
	struct cifs_fscache_inode_auxdata auxdata;
	struct cifsInodeInfo *cifsi = CIFS_I(inode);

	if (cifsi->fscache) {
		memset(&auxdata, 0, sizeof(auxdata));
		auxdata.eof = cifsi->server_eof;
		auxdata.last_write_time_sec = cifsi->vfs_inode.i_mtime.tv_sec;
		auxdata.last_change_time_sec = cifsi->vfs_inode.i_ctime.tv_sec;
		auxdata.last_write_time_nsec = cifsi->vfs_inode.i_mtime.tv_nsec;
		auxdata.last_change_time_nsec = cifsi->vfs_inode.i_ctime.tv_nsec;

		cifs_dbg(FYI, "%s: (0x%p)\n", __func__, cifsi->fscache);
		/* fscache_relinquish_cookie does not seem to update auxdata */
		fscache_update_cookie(cifsi->fscache, &auxdata);
		fscache_relinquish_cookie(cifsi->fscache, &auxdata, false);
		cifsi->fscache = NULL;
	}
}

void cifs_fscache_update_inode_cookie(struct inode *inode)
{
	struct cifs_fscache_inode_auxdata auxdata;
	struct cifsInodeInfo *cifsi = CIFS_I(inode);

	if (cifsi->fscache) {
		memset(&auxdata, 0, sizeof(auxdata));
		auxdata.eof = cifsi->server_eof;
		auxdata.last_write_time_sec = cifsi->vfs_inode.i_mtime.tv_sec;
		auxdata.last_change_time_sec = cifsi->vfs_inode.i_ctime.tv_sec;
		auxdata.last_write_time_nsec = cifsi->vfs_inode.i_mtime.tv_nsec;
		auxdata.last_change_time_nsec = cifsi->vfs_inode.i_ctime.tv_nsec;

		cifs_dbg(FYI, "%s: (0x%p)\n", __func__, cifsi->fscache);
		fscache_update_cookie(cifsi->fscache, &auxdata);
	}
}

void cifs_fscache_set_inode_cookie(struct inode *inode, struct file *filp)
{
	cifs_fscache_enable_inode_cookie(inode);
}

void cifs_fscache_reset_inode_cookie(struct inode *inode)
{
	struct cifsInodeInfo *cifsi = CIFS_I(inode);
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct cifs_tcon *tcon = cifs_sb_master_tcon(cifs_sb);
	struct fscache_cookie *old = cifsi->fscache;

	if (cifsi->fscache) {
		/* retire the current fscache cache and get a new one */
		fscache_relinquish_cookie(cifsi->fscache, NULL, true);

		cifs_fscache_acquire_inode_cookie(cifsi, tcon);
		cifs_dbg(FYI, "%s: new cookie 0x%p oldcookie 0x%p\n",
			 __func__, cifsi->fscache, old);
	}
}

/*
 * Retrieve a page from FS-Cache
 */
int __cifs_readpage_from_fscache(struct inode *inode, struct page *page)
{
	int ret;

	cifs_dbg(FYI, "%s: (fsc:%p, p:%p, i:0x%p\n",
		 __func__, CIFS_I(inode)->fscache, page, inode);

	ret = fscache_fallback_read_page(cifs_inode_cookie(inode), page);
	switch (ret) {
	case 0: /* page found in fscache, read submitted */
		cifs_dbg(FYI, "%s: submitted\n", __func__);
		return ret;
	case -ENOBUFS:	/* page won't be cached */
	case -ENODATA:	/* page not in cache */
		cifs_dbg(FYI, "%s: %d\n", __func__, ret);
		return 1;

	default:
		cifs_dbg(VFS, "unknown error ret = %d\n", ret);
	}
	return ret;
}

void __cifs_readpage_to_fscache(struct inode *inode, struct page *page)
{
	struct cifsInodeInfo *cifsi = CIFS_I(inode);

	WARN_ON(!cifsi->fscache);

	cifs_dbg(FYI, "%s: (fsc: %p, p: %p, i: %p)\n",
		 __func__, cifsi->fscache, page, inode);

	fscache_fallback_write_page(cifs_inode_cookie(inode), page);
}
