.. SPDX-License-Identifier: GPL-2.0

===============================
FS-Cache Network Filesystem API
===============================

There's an API by which a network filesystem can make use of the FS-Cache
facilities.  This is based around a number of principles:

 (1) Caches can store a number of different object types.  There are two main
     object types: indices and files.  The first is a special type used by
     FS-Cache to make finding objects faster and to make retiring of groups of
     objects easier.

 (2) Every index, file or other object is represented by a cookie.  This cookie
     may or may not have anything associated with it, but the netfs doesn't
     need to care.

 (3) Barring the top-level index (one entry per cached netfs), the index
     hierarchy for each netfs is structured according the whim of the netfs.

This API is declared in <linux/fscache.h>.

.. This document contains the following sections:

	 (1) Network filesystem definition
	 (2) Index definition
	 (3) Object definition
	 (4) Network filesystem (un)registration
	 (5) Cache tag lookup
	 (6) Index registration
	 (7) Data file registration
	 (8) Miscellaneous object registration
 	 (9) Setting the data file size
	(10) Page read/write
	(11) Index and data file consistency
	(12) Cookie enablement
	(13) Miscellaneous cookie operations
	(14) Cookie unregistration
	(15) Index invalidation
	(16) Data file invalidation


Network Filesystem Definition
=============================

FS-Cache needs a description of the network filesystem.  This is specified
using a record of the following structure::

	struct fscache_netfs {
		uint32_t			version;
		const char			*name;
		struct fscache_cookie		*primary_index;
		...
	};

This first two fields should be filled in before registration, and the third
will be filled in by the registration function; any other fields should just be
ignored and are for internal use only.

The fields are:

 (1) The name of the netfs (used as the key in the toplevel index).

 (2) The version of the netfs (if the name matches but the version doesn't, the
     entire in-cache hierarchy for this netfs will be scrapped and begun
     afresh).

 (3) The cookie representing the primary index will be allocated according to
     another parameter passed into the registration function.

For example, kAFS (linux/fs/afs/) uses the following definitions to describe
itself::

	struct fscache_netfs afs_cache_netfs = {
		.version	= 0,
		.name		= "afs",
	};


Index Definition
================

Indices are used for two purposes:

 (1) To aid the finding of a file based on a series of keys (such as AFS's
     "cell", "volume ID", "vnode ID").

 (2) To make it easier to discard a subset of all the files cached based around
     a particular key - for instance to mirror the removal of an AFS volume.

However, since it's unlikely that any two netfs's are going to want to define
their index hierarchies in quite the same way, FS-Cache tries to impose as few
restraints as possible on how an index is structured and where it is placed in
the tree.  The netfs can even mix indices and data files at the same level, but
it's not recommended.

Each index entry consists of a key of indeterminate length plus some auxiliary
data, also of indeterminate length.

There are some limits on indices:

 (1) Any index containing non-index objects should be restricted to a single
     cache.  Any such objects created within an index will be created in the
     first cache only.  The cache in which an index is created can be
     controlled by cache tags (see below).

 (2) The entry data must be atomically journallable, so it is limited to about
     400 bytes at present.  At least 400 bytes will be available.

 (3) The depth of the index tree should be judged with care as the search
     function is recursive.  Too many layers will run the kernel out of stack.


Object Definition
=================

To define an object, a structure of the following type should be filled out::

	struct fscache_cookie_def
	{
		uint8_t name[16];
		uint8_t type;

		struct fscache_cache_tag *(*select_cache)(
			const void *parent_netfs_data,
			const void *cookie_netfs_data);

		enum fscache_checkaux (*check_aux)(void *cookie_netfs_data,
						   const void *data,
						   uint16_t datalen,
						   loff_t object_size);
	};

This has the following fields:

 (1) The type of the object [mandatory].

     This is one of the following values:

	FSCACHE_COOKIE_TYPE_INDEX
	    This defines an index, which is a special FS-Cache type.

	FSCACHE_COOKIE_TYPE_DATAFILE
	    This defines an ordinary data file.

	Any other value between 2 and 255
	    This defines an extraordinary object such as an XATTR.

 (2) The name of the object type (NUL terminated unless all 16 chars are used)
     [optional].

 (3) A function to select the cache in which to store an index [optional].

     This function is invoked when an index needs to be instantiated in a cache
     during the instantiation of a non-index object.  Only the immediate index
     parent for the non-index object will be queried.  Any indices above that
     in the hierarchy may be stored in multiple caches.  This function does not
     need to be supplied for any non-index object or any index that will only
     have index children.

     If this function is not supplied or if it returns NULL then the first
     cache in the parent's list will be chosen, or failing that, the first
     cache in the master list.

 (4) A function to check the auxiliary data [optional].

     This function will be called to check that a match found in the cache for
     this object is valid.  For instance with AFS it could check the auxiliary
     data against the data version number returned by the server to determine
     whether the index entry in a cache is still valid.

     If this function is absent, it will be assumed that matching objects in a
     cache are always valid.

     The function is also passed the cache's idea of the object size and may
     use this to manage coherency also.

     If present, the function should return one of the following values:

	FSCACHE_CHECKAUX_OKAY
	    - the entry is okay as is

	FSCACHE_CHECKAUX_NEEDS_UPDATE
	    - the entry requires update

	FSCACHE_CHECKAUX_OBSOLETE
	    - the entry should be deleted

     This function can also be used to extract data from the auxiliary data in
     the cache and copy it into the netfs's structures.


Network Filesystem (Un)registration
===================================

The first step is to declare the network filesystem to the cache.  This also
involves specifying the layout of the primary index (for AFS, this would be the
"cell" level).

The registration function is::

	int fscache_register_netfs(struct fscache_netfs *netfs);

It just takes a pointer to the netfs definition.  It returns 0 or an error as
appropriate.

For kAFS, registration is done as follows::

	ret = fscache_register_netfs(&afs_cache_netfs);

The last step is, of course, unregistration::

	void fscache_unregister_netfs(struct fscache_netfs *netfs);


Cache Tag Lookup
================

FS-Cache permits the use of more than one cache.  To permit particular index
subtrees to be bound to particular caches, the second step is to look up cache
representation tags.  This step is optional; it can be left entirely up to
FS-Cache as to which cache should be used.  The problem with doing that is that
FS-Cache will always pick the first cache that was registered.

To get the representation for a named tag::

	struct fscache_cache_tag *fscache_lookup_cache_tag(const char *name);

This takes a text string as the name and returns a representation of a tag.  It
will never return an error.  It may return a dummy tag, however, if it runs out
of memory; this will inhibit caching with this tag.

Any representation so obtained must be released by passing it to this function::

	void fscache_release_cache_tag(struct fscache_cache_tag *tag);

The tag will be retrieved by FS-Cache when it calls the object definition
operation select_cache().


Index Registration
==================

The third step is to inform FS-Cache about part of an index hierarchy that can
be used to locate files.  This is done by requesting a cookie for each index in
the path to the file::

	struct fscache_cookie *
	fscache_acquire_cookie(struct fscache_cookie *parent,
			       const struct fscache_object_def *def,
			       const void *index_key,
			       size_t index_key_len,
			       const void *aux_data,
			       size_t aux_data_len,
			       void *netfs_data,
			       loff_t object_size,
			       bool enable);

This function creates an index entry in the index represented by parent,
filling in the index entry by calling the operations pointed to by def.

A unique key that represents the object within the parent must be pointed to by
index_key and is of length index_key_len.

An optional blob of auxiliary data that is to be stored within the cache can be
pointed to with aux_data and should be of length aux_data_len.  This would
typically be used for storing coherency data.

The netfs may pass an arbitrary value in netfs_data and this will be presented
to it in the event of any calling back.  This may also be used in tracing or
logging of messages.

The cache tracks the size of the data attached to an object and this set to be
object_size.  For indices, this should be 0.  This value will be passed to the
->check_aux() callback.

Note that this function never returns an error - all errors are handled
internally.  It may, however, return NULL to indicate no cookie.  It is quite
acceptable to pass this token back to this function as the parent to another
acquisition (or even to the relinquish cookie, read page and write page
functions - see below).

Note also that no indices are actually created in a cache until a non-index
object needs to be created somewhere down the hierarchy.  Furthermore, an index
may be created in several different caches independently at different times.
This is all handled transparently, and the netfs doesn't see any of it.

A cookie will be created in the disabled state if enabled is false.  A cookie
must be enabled to do anything with it.  A disabled cookie can be enabled by
calling fscache_enable_cookie() (see below).

For example, with AFS, a cell would be added to the primary index.  This index
entry would have a dependent inode containing volume mappings within this cell::

	cell->cache =
		fscache_acquire_cookie(afs_cache_netfs.primary_index,
				       &afs_cell_cache_index_def,
				       cell->name, strlen(cell->name),
				       NULL, 0,
				       cell, 0, true);

And then a particular volume could be added to that index by ID, creating
another index for vnodes (AFS inode equivalents)::

	volume->cache =
		fscache_acquire_cookie(volume->cell->cache,
				       &afs_volume_cache_index_def,
				       &volume->vid, sizeof(volume->vid),
				       NULL, 0,
				       volume, 0, true);


Data File Registration
======================

The fourth step is to request a data file be created in the cache.  This is
identical to index cookie acquisition.  The only difference is that the type in
the object definition should be something other than index type::

	vnode->cache =
		fscache_acquire_cookie(volume->cache,
				       &afs_vnode_cache_object_def,
				       &key, sizeof(key),
				       &aux, sizeof(aux),
				       vnode, vnode->status.size, true);


Miscellaneous Object Registration
=================================

An optional step is to request an object of miscellaneous type be created in
the cache.  This is almost identical to index cookie acquisition.  The only
difference is that the type in the object definition should be something other
than index type.  While the parent object could be an index, it's more likely
it would be some other type of object such as a data file::

	xattr->cache =
		fscache_acquire_cookie(vnode->cache,
				       &afs_xattr_cache_object_def,
				       &xattr->name, strlen(xattr->name),
				       NULL, 0,
				       xattr, strlen(xattr->val), true);

Miscellaneous objects might be used to store extended attributes or directory
entries for example.


Setting the Data File Size
==========================

The fifth step is to set the physical attributes of the file, such as its size.
This doesn't automatically reserve any space in the cache, but permits the
cache to adjust its metadata for data tracking appropriately::

	int fscache_attr_changed(struct fscache_cookie *cookie);

The cache will return -ENOBUFS if there is no backing cache or if there is no
space to allocate any extra metadata required in the cache.

Note that attempts to read or write data pages in the cache over this size may
be rebuffed with -ENOBUFS.

This operation schedules an attribute adjustment to happen asynchronously at
some point in the future, and as such, it may happen after the function returns
to the caller.  The attribute adjustment excludes read and write operations.


Page Read/Write
=====================

And the sixth step is to store and retrieve pages in the cache.  The functions
provided may do direct I/O calls on the backing filesystem and it is up to the
network filesystem to prevent clashes.  Typically, a page would be locked for
the duration of a read and a page would be marked with PageFsCache whilst it is
being written out.

By preference, reading would be performed through the netfs library's helper
functions, but there is a fallback API, though this should be considered
deprecated as it may lead to data corruption, depending on the characteristics
of the backing filesystem.  If the fallback API is to be used, the filesystem
must do::

	#define FSCACHE_USE_FALLBACK_IO_API
	#include <linux/fscache.h>


Fallback Page Read
------------------

A page may be synchronously read from the backing filesystem::

	int fscache_fallback_read_page(struct fscache_cookie *cookie,
				       struct page *page);

The cookie argument must specify a cookie for an object that isn't an index and
the page specified will have the data loaded into it (and is also used to
specify the page number).  The function will return 0 if the page was
read, -ENODATA if there was no data and -ENOBUFS if there was no cache
attached.  It may also return errors such as -ENOMEM or -EINTR.  It might also
return some other error from the backing filesystem, but this should be treated
as -ENOBUS.


Fallback Page Write
-------------------

A page may be synchronously written to the backing filesystem::

	int fscache_fallback_write_page(struct fscache_cookie *cookie,
					struct page *page);

The cookie argument must specify a cookie for an object that isn't an index and
the page specified will have the data written from it (and is also used to
specify the page number).  The function will return 0 if the page was read
and -ENOBUFS if there was no cache attached or no space available in the cache.
It may also return errors such as -ENOMEM or -EINTR.  It might also return some
other error from the backing filesystem, but this should be treated as -ENOBUS.


Index and Data File consistency
===============================

To find out whether auxiliary data for an object is up to data within the
cache, the following function can be called::

	int fscache_check_consistency(struct fscache_cookie *cookie,
				      const void *aux_data);

This will call back to the netfs to check whether the auxiliary data associated
with a cookie is correct; if aux_data is non-NULL, it will update the auxiliary
data buffer first.  It returns 0 if it is and -ESTALE if it isn't; it may also
return -ENOMEM and -ERESTARTSYS.

To request an update of the index data for an index or other object, the
following function should be called::

	void fscache_update_cookie(struct fscache_cookie *cookie,
				   const void *aux_data);

This function will update the cookie's auxiliary data buffer from aux_data if
that is non-NULL and then schedule this to be stored on disk.  The update
method in the parent index definition will be called to transfer the data.

Note that partial updates may happen automatically at other times, such as when
data blocks are added to a data file object.


Cookie Enablement
=================

Cookies exist in one of two states: enabled and disabled.  If a cookie is
disabled, it ignores all attempts to acquire child cookies; check, update or
invalidate its state; allocate, read or write backing pages - though it is
still possible to uncache pages and relinquish the cookie.

The initial enablement state is set by fscache_acquire_cookie(), but the cookie
can be enabled or disabled later.  To disable a cookie, call::

	void fscache_disable_cookie(struct fscache_cookie *cookie,
				    const void *aux_data,
    				    bool invalidate);

If the cookie is not already disabled, this locks the cookie against other
enable and disable ops, marks the cookie as being disabled, discards or
invalidates any backing objects and waits for cessation of activity on any
associated object before unlocking the cookie.

All possible failures are handled internally.  The caller should consider
calling fscache_uncache_all_inode_pages() afterwards to make sure all page
markings are cleared up.

Cookies can be enabled or reenabled with::

    	void fscache_enable_cookie(struct fscache_cookie *cookie,
				   const void *aux_data,
				   loff_t object_size,
    				   bool (*can_enable)(void *data),
    				   void *data)

If the cookie is not already enabled, this locks the cookie against other
enable and disable ops, invokes can_enable() and, if the cookie is not an index
cookie, will begin the procedure of acquiring backing objects.

The optional can_enable() function is passed the data argument and returns a
ruling as to whether or not enablement should actually be permitted to begin.

All possible failures are handled internally.  The cookie will only be marked
as enabled if provisional backing objects are allocated.

The object's data size is updated from object_size and is passed to the
->check_aux() function.

In both cases, the cookie's auxiliary data buffer is updated from aux_data if
that is non-NULL inside the enablement lock before proceeding.


Miscellaneous Cookie operations
===============================

There are a number of operations that can be used to control cookies:

     * Cookie pinning::

	int fscache_pin_cookie(struct fscache_cookie *cookie);
	void fscache_unpin_cookie(struct fscache_cookie *cookie);

     These operations permit data cookies to be pinned into the cache and to
     have the pinning removed.  They are not permitted on index cookies.

     The pinning function will return 0 if successful, -ENOBUFS in the cookie
     isn't backed by a cache, -EOPNOTSUPP if the cache doesn't support pinning,
     -ENOSPC if there isn't enough space to honour the operation, -ENOMEM or
     -EIO if there's any other problem.

   * Data space reservation::

	int fscache_reserve_space(struct fscache_cookie *cookie, loff_t size);

     This permits a netfs to request cache space be reserved to store up to the
     given amount of a file.  It is permitted to ask for more than the current
     size of the file to allow for future file expansion.

     If size is given as zero then the reservation will be cancelled.

     The function will return 0 if successful, -ENOBUFS in the cookie isn't
     backed by a cache, -EOPNOTSUPP if the cache doesn't support reservations,
     -ENOSPC if there isn't enough space to honour the operation, -ENOMEM or
     -EIO if there's any other problem.

     Note that this doesn't pin an object in a cache; it can still be culled to
     make space if it's not in use.


Cookie Unregistration
=====================

To get rid of a cookie, this function should be called::

	void fscache_relinquish_cookie(struct fscache_cookie *cookie,
				       const void *aux_data,
				       bool retire);

If retire is non-zero, then the object will be marked for recycling, and all
copies of it will be removed from all active caches in which it is present.
Not only that but all child objects will also be retired.

If retire is zero, then the object may be available again when next the
acquisition function is called.  Retirement here will overrule the pinning on a
cookie.

The cookie's auxiliary data will be updated from aux_data if that is non-NULL
so that the cache can lazily update it on disk.

One very important note - relinquish must NOT be called for a cookie unless all
the cookies for "child" indices, objects and pages have been relinquished
first.


Index Invalidation
==================

There is no direct way to invalidate an index subtree.  To do this, the caller
should relinquish and retire the cookie they have, and then acquire a new one.


Data File Invalidation
======================

Sometimes it will be necessary to invalidate an object that contains data.
Typically this will be necessary when the server tells the netfs of a foreign
change - at which point the netfs has to throw away all the state it had for an
inode and reload from the server.

To indicate that a cache object should be invalidated, the following function
can be called::

	void fscache_invalidate(struct fscache_cookie *cookie);

This can be called with spinlocks held as it defers the work to a thread pool.
All extant storage, retrieval and attribute change ops at this point are
cancelled and discarded.  Some future operations will be rejected until the
cache has had a chance to insert a barrier in the operations queue.  After
that, operations will be queued again behind the invalidation operation.

The invalidation operation will perform an attribute change operation and an
auxiliary data update operation as it is very likely these will have changed.

Using the following function, the netfs can wait for the invalidation operation
to have reached a point at which it can start submitting ordinary operations
once again::

	void fscache_wait_on_invalidate(struct fscache_cookie *cookie);
