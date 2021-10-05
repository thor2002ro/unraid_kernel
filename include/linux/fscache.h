/* SPDX-License-Identifier: GPL-2.0-or-later */
/* General filesystem caching interface
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * NOTE!!! See:
 *
 *	Documentation/filesystems/caching/netfs-api.rst
 *
 * for a description of the network filesystem interface declared here.
 */

#ifndef _LINUX_FSCACHE_H
#define _LINUX_FSCACHE_H

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/list_bl.h>
#include <linux/netfs.h>

#if defined(CONFIG_FSCACHE) || defined(CONFIG_FSCACHE_MODULE)
#define fscache_available() (1)
#define fscache_cookie_valid(cookie) (cookie)
#define fscache_resources_valid(cres) ((cres)->cache_priv)
#else
#define fscache_available() (0)
#define fscache_cookie_valid(cookie) (0)
#define fscache_resources_valid(cres) (false)
#endif

struct pagevec;
struct fscache_cache_tag;
struct fscache_cookie;
struct fscache_netfs;
struct netfs_read_request;

/* result of index entry consultation */
enum fscache_checkaux {
	FSCACHE_CHECKAUX_OKAY,		/* entry okay as is */
	FSCACHE_CHECKAUX_NEEDS_UPDATE,	/* entry requires update */
	FSCACHE_CHECKAUX_OBSOLETE,	/* entry requires deletion */
};

/*
 * fscache cookie definition
 */
struct fscache_cookie_def {
	/* name of cookie type */
	char name[16];

	/* cookie type */
	uint8_t type;
#define FSCACHE_COOKIE_TYPE_INDEX	0
#define FSCACHE_COOKIE_TYPE_DATAFILE	1

	/* select the cache into which to insert an entry in this index
	 * - optional
	 * - should return a cache identifier or NULL to cause the cache to be
	 *   inherited from the parent if possible or the first cache picked
	 *   for a non-index file if not
	 */
	struct fscache_cache_tag *(*select_cache)(
		const void *parent_netfs_data,
		const void *cookie_netfs_data);

	/* consult the netfs about the state of an object
	 * - this function can be absent if the index carries no state data
	 * - the netfs data from the cookie being used as the target is
	 *   presented, as is the auxiliary data and the object size
	 */
	enum fscache_checkaux (*check_aux)(void *cookie_netfs_data,
					   const void *data,
					   uint16_t datalen,
					   loff_t object_size);
};

/*
 * fscache cached network filesystem type
 * - name, version and ops must be filled in before registration
 * - all other fields will be set during registration
 */
struct fscache_netfs {
	uint32_t			version;	/* indexing version */
	const char			*name;		/* filesystem name */
	struct fscache_cookie		*primary_index;
};

/*
 * data file or index object cookie
 * - a file will only appear in one cache
 * - a request to cache a file may or may not be honoured, subject to
 *   constraints such as disk space
 * - indices are created on disk just-in-time
 */
struct fscache_cookie {
	refcount_t			ref;		/* number of users of this cookie */
	atomic_t			n_children;	/* number of children of this cookie */
	atomic_t			n_active;	/* number of active users of netfs ptrs */
	unsigned int			debug_id;
	spinlock_t			lock;
	struct hlist_head		backing_objects; /* object(s) backing this file/index */
	const struct fscache_cookie_def	*def;		/* definition */
	struct fscache_cookie		*parent;	/* parent of this entry */
	struct hlist_bl_node		hash_link;	/* Link in hash table */
	struct list_head		proc_link;	/* Link in proc list */
	void				*netfs_data;	/* back pointer to netfs */

	unsigned long			flags;
#define FSCACHE_COOKIE_LOOKING_UP	0	/* T if non-index cookie being looked up still */
#define FSCACHE_COOKIE_NO_DATA_YET	1	/* T if new object with no cached data yet */
#define FSCACHE_COOKIE_UNAVAILABLE	2	/* T if cookie is unavailable (error, etc) */
#define FSCACHE_COOKIE_INVALIDATING	3	/* T if cookie is being invalidated */
#define FSCACHE_COOKIE_RELINQUISHED	4	/* T if cookie has been relinquished */
#define FSCACHE_COOKIE_ENABLED		5	/* T if cookie is enabled */
#define FSCACHE_COOKIE_ENABLEMENT_LOCK	6	/* T if cookie is being en/disabled */
#define FSCACHE_COOKIE_AUX_UPDATED	8	/* T if the auxiliary data was updated */
#define FSCACHE_COOKIE_ACQUIRED		9	/* T if cookie is in use */
#define FSCACHE_COOKIE_RELINQUISHING	10	/* T if cookie is being relinquished */

	u8				type;		/* Type of object */
	u8				key_len;	/* Length of index key */
	u8				aux_len;	/* Length of auxiliary data */
	u32				key_hash;	/* Hash of parent, type, key, len */
	union {
		void			*key;		/* Index key */
		u8			inline_key[16];	/* - If the key is short enough */
	};
	union {
		void			*aux;		/* Auxiliary data */
		u8			inline_aux[8];	/* - If the aux data is short enough */
	};
};

static inline bool fscache_cookie_enabled(struct fscache_cookie *cookie)
{
	return (fscache_cookie_valid(cookie) &&
		test_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags));
}

/*
 * slow-path functions for when there is actually caching available, and the
 * netfs does actually have a valid token
 * - these are not to be called directly
 * - these are undefined symbols when FS-Cache is not configured and the
 *   optimiser takes care of not using them
 */
extern int __fscache_register_netfs(struct fscache_netfs *);
extern void __fscache_unregister_netfs(struct fscache_netfs *);
extern struct fscache_cache_tag *__fscache_lookup_cache_tag(const char *);
extern void __fscache_release_cache_tag(struct fscache_cache_tag *);

extern struct fscache_cookie *__fscache_acquire_cookie(
	struct fscache_cookie *,
	const struct fscache_cookie_def *,
	const void *, size_t,
	const void *, size_t,
	void *, loff_t, bool);
extern void __fscache_relinquish_cookie(struct fscache_cookie *, const void *, bool);
extern int __fscache_check_consistency(struct fscache_cookie *, const void *);
extern void __fscache_update_cookie(struct fscache_cookie *, const void *);
extern int __fscache_attr_changed(struct fscache_cookie *);
extern void __fscache_invalidate(struct fscache_cookie *);
extern void __fscache_wait_on_invalidate(struct fscache_cookie *);
#ifdef FSCACHE_USE_NEW_IO_API
extern int __fscache_begin_operation(struct netfs_cache_resources *, struct fscache_cookie *,
				     bool);
#endif
#ifdef FSCACHE_USE_FALLBACK_IO_API
extern int __fscache_fallback_read_page(struct fscache_cookie *, struct page *);
extern int __fscache_fallback_write_page(struct fscache_cookie *, struct page *);
#endif
extern void __fscache_disable_cookie(struct fscache_cookie *, const void *, bool);
extern void __fscache_enable_cookie(struct fscache_cookie *, const void *, loff_t,
				    bool (*)(void *), void *);

/**
 * fscache_register_netfs - Register a filesystem as desiring caching services
 * @netfs: The description of the filesystem
 *
 * Register a filesystem as desiring caching services if they're available.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
int fscache_register_netfs(struct fscache_netfs *netfs)
{
	if (fscache_available())
		return __fscache_register_netfs(netfs);
	else
		return 0;
}

/**
 * fscache_unregister_netfs - Indicate that a filesystem no longer desires
 * caching services
 * @netfs: The description of the filesystem
 *
 * Indicate that a filesystem no longer desires caching services for the
 * moment.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_unregister_netfs(struct fscache_netfs *netfs)
{
	if (fscache_available())
		__fscache_unregister_netfs(netfs);
}

/**
 * fscache_lookup_cache_tag - Look up a cache tag
 * @name: The name of the tag to search for
 *
 * Acquire a specific cache referral tag that can be used to select a specific
 * cache in which to cache an index.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
struct fscache_cache_tag *fscache_lookup_cache_tag(const char *name)
{
	if (fscache_available())
		return __fscache_lookup_cache_tag(name);
	else
		return NULL;
}

/**
 * fscache_release_cache_tag - Release a cache tag
 * @tag: The tag to release
 *
 * Release a reference to a cache referral tag previously looked up.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_release_cache_tag(struct fscache_cache_tag *tag)
{
	if (fscache_available())
		__fscache_release_cache_tag(tag);
}

/**
 * fscache_acquire_cookie - Acquire a cookie to represent a cache object
 * @parent: The cookie that's to be the parent of this one
 * @def: A description of the cache object, including callback operations
 * @index_key: The index key for this cookie
 * @index_key_len: Size of the index key
 * @aux_data: The auxiliary data for the cookie (may be NULL)
 * @aux_data_len: Size of the auxiliary data buffer
 * @netfs_data: An arbitrary piece of data to be kept in the cookie to
 * represent the cache object to the netfs
 * @object_size: The initial size of object
 * @enable: Whether or not to enable a data cookie immediately
 *
 * This function is used to inform FS-Cache about part of an index hierarchy
 * that can be used to locate files.  This is done by requesting a cookie for
 * each index in the path to the file.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
struct fscache_cookie *fscache_acquire_cookie(
	struct fscache_cookie *parent,
	const struct fscache_cookie_def *def,
	const void *index_key,
	size_t index_key_len,
	const void *aux_data,
	size_t aux_data_len,
	void *netfs_data,
	loff_t object_size,
	bool enable)
{
	if (fscache_cookie_valid(parent) && fscache_cookie_enabled(parent))
		return __fscache_acquire_cookie(parent, def,
						index_key, index_key_len,
						aux_data, aux_data_len,
						netfs_data, object_size, enable);
	else
		return NULL;
}

/**
 * fscache_relinquish_cookie - Return the cookie to the cache, maybe discarding
 * it
 * @cookie: The cookie being returned
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 * @retire: True if the cache object the cookie represents is to be discarded
 *
 * This function returns a cookie to the cache, forcibly discarding the
 * associated cache object if retire is set to true.  The opportunity is
 * provided to update the auxiliary data in the cache before the object is
 * disconnected.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_relinquish_cookie(struct fscache_cookie *cookie,
			       const void *aux_data,
			       bool retire)
{
	if (fscache_cookie_valid(cookie))
		__fscache_relinquish_cookie(cookie, aux_data, retire);
}

/**
 * fscache_check_consistency - Request validation of a cache's auxiliary data
 * @cookie: The cookie representing the cache object
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 *
 * Request an consistency check from fscache, which passes the request to the
 * backing cache.  The auxiliary data on the cookie will be updated first if
 * @aux_data is set.
 *
 * Returns 0 if consistent and -ESTALE if inconsistent.  May also
 * return -ENOMEM and -ERESTARTSYS.
 */
static inline
int fscache_check_consistency(struct fscache_cookie *cookie,
			      const void *aux_data)
{
	if (fscache_cookie_valid(cookie) && fscache_cookie_enabled(cookie))
		return __fscache_check_consistency(cookie, aux_data);
	else
		return 0;
}

/**
 * fscache_update_cookie - Request that a cache object be updated
 * @cookie: The cookie representing the cache object
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 *
 * Request an update of the index data for the cache object associated with the
 * cookie.  The auxiliary data on the cookie will be updated first if @aux_data
 * is set.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_update_cookie(struct fscache_cookie *cookie, const void *aux_data)
{
	if (fscache_cookie_valid(cookie) && fscache_cookie_enabled(cookie))
		__fscache_update_cookie(cookie, aux_data);
}

/**
 * fscache_pin_cookie - Pin a data-storage cache object in its cache
 * @cookie: The cookie representing the cache object
 *
 * Permit data-storage cache objects to be pinned in the cache.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
int fscache_pin_cookie(struct fscache_cookie *cookie)
{
	return -ENOBUFS;
}

/**
 * fscache_pin_cookie - Unpin a data-storage cache object in its cache
 * @cookie: The cookie representing the cache object
 *
 * Permit data-storage cache objects to be unpinned from the cache.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_unpin_cookie(struct fscache_cookie *cookie)
{
}

/**
 * fscache_attr_changed - Notify cache that an object's attributes changed
 * @cookie: The cookie representing the cache object
 *
 * Send a notification to the cache indicating that an object's attributes have
 * changed.  This includes the data size.  These attributes will be obtained
 * through the get_attr() cookie definition op.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
int fscache_attr_changed(struct fscache_cookie *cookie)
{
	if (fscache_cookie_valid(cookie) && fscache_cookie_enabled(cookie))
		return __fscache_attr_changed(cookie);
	else
		return -ENOBUFS;
}

/**
 * fscache_invalidate - Notify cache that an object needs invalidation
 * @cookie: The cookie representing the cache object
 *
 * Notify the cache that an object is needs to be invalidated and that it
 * should abort any retrievals or stores it is doing on the cache.  The object
 * is then marked non-caching until such time as the invalidation is complete.
 *
 * This can be called with spinlocks held.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_invalidate(struct fscache_cookie *cookie)
{
	if (fscache_cookie_valid(cookie) && fscache_cookie_enabled(cookie))
		__fscache_invalidate(cookie);
}

/**
 * fscache_wait_on_invalidate - Wait for invalidation to complete
 * @cookie: The cookie representing the cache object
 *
 * Wait for the invalidation of an object to complete.
 *
 * See Documentation/filesystems/caching/netfs-api.rst for a complete
 * description.
 */
static inline
void fscache_wait_on_invalidate(struct fscache_cookie *cookie)
{
	if (fscache_cookie_valid(cookie))
		__fscache_wait_on_invalidate(cookie);
}

#ifdef FSCACHE_USE_NEW_IO_API

/**
 * fscache_begin_read_operation - Begin a read operation for the netfs lib
 * @cres: The cache resources for the read being performed
 * @cookie: The cookie representing the cache object
 *
 * Begin a read operation on behalf of the netfs helper library.  @cres
 * indicates the cache resources to which the operation state should be
 * attached; @cookie indicates the cache object that will be accessed.
 *
 * This is intended to be called from the ->begin_cache_operation() netfs lib
 * operation as implemented by the network filesystem.
 *
 * Returns:
 * * 0		- Success
 * * -ENOBUFS	- No caching available
 * * Other error code from the cache, such as -ENOMEM.
 */
static inline
int fscache_begin_read_operation(struct netfs_cache_resources *cres,
				 struct fscache_cookie *cookie)
{
	if (fscache_cookie_valid(cookie) && fscache_cookie_enabled(cookie))
		return __fscache_begin_operation(cres, cookie, false);
	return -ENOBUFS;
}

/**
 * fscache_operation_valid - Return true if operations resources are usable
 * @cres: The resources to check.
 *
 * Returns a pointer to the operations table if usable or NULL if not.
 */
static inline
const struct netfs_cache_ops *fscache_operation_valid(const struct netfs_cache_resources *cres)
{
	return fscache_resources_valid(cres) ? cres->ops : NULL;
}

/**
 * fscache_read - Start a read from the cache.
 * @cres: The cache resources to use
 * @start_pos: The beginning file offset in the cache file
 * @iter: The buffer to fill - and also the length
 * @read_hole: How to handle a hole in the data.
 * @term_func: The function to call upon completion
 * @term_func_priv: The private data for @term_func
 *
 * Start a read from the cache.  @cres indicates the cache object to read from
 * and must be obtained by a call to fscache_begin_operation() beforehand.
 *
 * The data is read into the iterator, @iter, and that also indicates the size
 * of the operation.  @start_pos is the start position in the file, though if
 * @seek_data is set appropriately, the cache can use SEEK_DATA to find the
 * next piece of data, writing zeros for the hole into the iterator.
 *
 * Upon termination of the operation, @term_func will be called and supplied
 * with @term_func_priv plus the amount of data written, if successful, or the
 * error code otherwise.
 */
static inline
int fscache_read(struct netfs_cache_resources *cres,
		 loff_t start_pos,
		 struct iov_iter *iter,
		 enum netfs_read_from_hole read_hole,
		 netfs_io_terminated_t term_func,
		 void *term_func_priv)
{
	const struct netfs_cache_ops *ops = fscache_operation_valid(cres);
	return ops->read(cres, start_pos, iter, read_hole,
			 term_func, term_func_priv);
}

/**
 * fscache_write - Start a write to the cache.
 * @cres: The cache resources to use
 * @start_pos: The beginning file offset in the cache file
 * @iter: The data to write - and also the length
 * @term_func: The function to call upon completion
 * @term_func_priv: The private data for @term_func
 *
 * Start a write to the cache.  @cres indicates the cache object to write to and
 * must be obtained by a call to fscache_begin_operation() beforehand.
 *
 * The data to be written is obtained from the iterator, @iter, and that also
 * indicates the size of the operation.  @start_pos is the start position in
 * the file.
 *
 * Upon termination of the operation, @term_func will be called and supplied
 * with @term_func_priv plus the amount of data written, if successful, or the
 * error code otherwise.
 */
static inline
int fscache_write(struct netfs_cache_resources *cres,
		  loff_t start_pos,
		  struct iov_iter *iter,
		  netfs_io_terminated_t term_func,
		  void *term_func_priv)
{
	const struct netfs_cache_ops *ops = fscache_operation_valid(cres);
	return ops->write(cres, start_pos, iter, term_func, term_func_priv);
}

#endif /* FSCACHE_USE_NEW_IO_API */

/**
 * fscache_disable_cookie - Disable a cookie
 * @cookie: The cookie representing the cache object
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 * @invalidate: Invalidate the backing object
 *
 * Disable a cookie from accepting further alloc, read, write, invalidate,
 * update or acquire operations.  Outstanding operations can still be waited
 * upon and pages can still be uncached and the cookie relinquished.
 *
 * This will not return until all outstanding operations have completed.
 *
 * If @invalidate is set, then the backing object will be invalidated and
 * detached, otherwise it will just be detached.
 *
 * If @aux_data is set, then auxiliary data will be updated from that.
 */
static inline
void fscache_disable_cookie(struct fscache_cookie *cookie,
			    const void *aux_data,
			    bool invalidate)
{
	if (fscache_cookie_valid(cookie) && fscache_cookie_enabled(cookie))
		__fscache_disable_cookie(cookie, aux_data, invalidate);
}

/**
 * fscache_enable_cookie - Reenable a cookie
 * @cookie: The cookie representing the cache object
 * @aux_data: The updated auxiliary data for the cookie (may be NULL)
 * @object_size: Current size of object
 * @can_enable: A function to permit enablement once lock is held
 * @data: Data for can_enable()
 *
 * Reenable a previously disabled cookie, allowing it to accept further alloc,
 * read, write, invalidate, update or acquire operations.  An attempt will be
 * made to immediately reattach the cookie to a backing object.  If @aux_data
 * is set, the auxiliary data attached to the cookie will be updated.
 *
 * The can_enable() function is called (if not NULL) once the enablement lock
 * is held to rule on whether enablement is still permitted to go ahead.
 */
static inline
void fscache_enable_cookie(struct fscache_cookie *cookie,
			   const void *aux_data,
			   loff_t object_size,
			   bool (*can_enable)(void *data),
			   void *data)
{
	if (fscache_cookie_valid(cookie) && !fscache_cookie_enabled(cookie))
		__fscache_enable_cookie(cookie, aux_data, object_size,
					can_enable, data);
}

#ifdef FSCACHE_USE_FALLBACK_IO_API

/**
 * fscache_fallback_read_page - Read a page from a cache object (DANGEROUS)
 * @cookie: The cookie representing the cache object
 * @page: The page to be read to
 *
 * Synchronously read a page from the cache.  The page's offset is used to
 * indicate where to read.
 *
 * This is dangerous and should be moved away from as it relies on the
 * assumption that the backing filesystem will exactly record the blocks we
 * have stored there.
 */
static inline
int fscache_fallback_read_page(struct fscache_cookie *cookie, struct page *page)
{
	if (fscache_cookie_enabled(cookie))
		return __fscache_fallback_read_page(cookie, page);
	return -ENOBUFS;
}

/**
 * fscache_fallback_write_page - Write a page to a cache object (DANGEROUS)
 * @cookie: The cookie representing the cache object
 * @page: The page to be written from
 *
 * Synchronously write a page to the cache.  The page's offset is used to
 * indicate where to write.
 *
 * This is dangerous and should be moved away from as it relies on the
 * assumption that the backing filesystem will exactly record the blocks we
 * have stored there.
 */
static inline
int fscache_fallback_write_page(struct fscache_cookie *cookie, struct page *page)
{
	if (fscache_cookie_enabled(cookie))
		return __fscache_fallback_write_page(cookie, page);
	return -ENOBUFS;
}

#endif /* FSCACHE_USE_FALLBACK_IO_API */

#endif /* _LINUX_FSCACHE_H */
