// SPDX-License-Identifier: GPL-2.0
/* User-mappable watch queue
 *
 * Copyright (C) 2019 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * See Documentation/watch_queue.rst
 */

#define pr_fmt(fmt) "watchq: " fmt
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/file.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/sched/signal.h>
#include <linux/watch_queue.h>

MODULE_DESCRIPTION("Watch queue");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

struct watch_type_filter {
	enum watch_notification_type type;
	__u32		subtype_filter[1];	/* Bitmask of subtypes to filter on */
	__u32		info_filter;		/* Filter on watch_notification::info */
	__u32		info_mask;		/* Mask of relevant bits in info_filter */
};

struct watch_filter {
	union {
		struct rcu_head	rcu;
		unsigned long	type_filter[2];	/* Bitmask of accepted types */
	};
	u32		nr_filters;		/* Number of filters */
	struct watch_type_filter filters[];
};

struct watch_queue {
	struct rcu_head		rcu;
	struct address_space	mapping;
	struct user_struct	*owner;		/* Owner of the queue for rlimit purposes */
	struct watch_filter __rcu *filter;
	wait_queue_head_t	waiters;
	struct hlist_head	watches;	/* Contributory watches */
	struct kref		usage;		/* Object usage count */
	spinlock_t		lock;
	bool			defunct;	/* T when queues closed */
	u8			nr_pages;	/* Size of pages[] */
	u8			flag_next;	/* Flag to apply to next item */
	u32			size;
	struct watch_queue_buffer *buffer;	/* Pointer to first record */

	/* The mappable pages.  The zeroth page holds the ring pointers. */
	struct page		**pages;
};

/*
 * Write a notification of an event into an mmap'd queue and let the user know.
 * Returns true if successful and false on failure (eg. buffer overrun or
 * userspace mucked up the ring indices).
 */
static bool write_one_notification(struct watch_queue *wqueue,
				   struct watch_notification *n)
{
	struct watch_queue_buffer *buf = wqueue->buffer;
	struct watch_notification *p;
	unsigned int gran = WATCH_LENGTH_GRANULARITY;
	unsigned int metalen = sizeof(buf->meta) / gran;
	unsigned int size = wqueue->size, mask = size - 1;
	unsigned int len;
	unsigned int ring_tail, tail, head, used, gap, h;

	/* Barrier against userspace, ordering data read before tail read */
	ring_tail = READ_ONCE(buf->meta.tail);

	head = READ_ONCE(buf->meta.head);
	used = head - ring_tail;

	/* Check to see if userspace mucked up the pointers */
	if (used >= size)
		goto lost_event; /* Inconsistent */
	tail = ring_tail & mask;
	if (tail > 0 && tail < metalen)
		goto lost_event; /* Inconsistent */

	len = (n->info & WATCH_INFO_LENGTH) >> WATCH_INFO_LENGTH__SHIFT;
	h = head & mask;
	if (h >= tail) {
		/* Head is at or after tail in the buffer.  There may then be
		 * two gaps: one to the end of buffer and one at the beginning
		 * of the buffer between the metadata block and the tail
		 * pointer.
		 */
		gap = size - h;
		if (len > gap) {
			/* Not enough space in the post-head gap; we need to
			 * wrap.  When wrapping, we will have to skip the
			 * metadata at the beginning of the buffer.
			 */
			if (len > tail - metalen)
				goto lost_event; /* Overrun */

			/* Fill the space at the end of the page */
			p = &buf->slots[h];
			p->type		= WATCH_TYPE_META;
			p->subtype	= WATCH_META_SKIP_NOTIFICATION;
			p->info		= gap << WATCH_INFO_LENGTH__SHIFT;
			head += gap;
			h = 0;
			if (h >= tail)
				goto lost_event; /* Overrun */
		}
	}

	if (h == 0) {
		/* Reset and skip the header metadata */
		p = &buf->meta.watch;
		p->type		= WATCH_TYPE_META;
		p->subtype	= WATCH_META_SKIP_NOTIFICATION;
		p->info		= metalen << WATCH_INFO_LENGTH__SHIFT;
		head += metalen;
		h = metalen;
		if (h == tail)
			goto lost_event; /* Overrun */
	}

	if (h < tail) {
		/* Head is before tail in the buffer. */
		gap = tail - h;
		if (len > gap)
			goto lost_event; /* Overrun */
	}

	n->info |= wqueue->flag_next;
	wqueue->flag_next = 0;
	p = &buf->slots[h];
	memcpy(p, n, len * gran);
	head += len;

	/* Barrier against userspace, ordering head update after data write. */
	smp_store_release(&buf->meta.head, head);
	if (used == 0)
		wake_up(&wqueue->waiters);
	return true;

lost_event:
	WRITE_ONCE(buf->meta.watch.info,
		   buf->meta.watch.info | WATCH_INFO_NOTIFICATIONS_LOST);
	return false;
}

/*
 * Post a notification to a watch queue.
 */
static bool post_one_notification(struct watch_queue *wqueue,
				  struct watch_notification *n)
{
	bool done = false;

	if (!wqueue->buffer)
		return false;

	spin_lock_bh(&wqueue->lock); /* Protect head pointer */

	if (!wqueue->defunct)
		done = write_one_notification(wqueue, n);
	spin_unlock_bh(&wqueue->lock);
	return done;
}

/*
 * Apply filter rules to a notification.
 */
static bool filter_watch_notification(const struct watch_filter *wf,
				      const struct watch_notification *n)
{
	const struct watch_type_filter *wt;
	unsigned int st_bits = sizeof(wt->subtype_filter[0]) * 8;
	unsigned int st_index = n->subtype / st_bits;
	unsigned int st_bit = 1U << (n->subtype % st_bits);
	int i;

	if (!test_bit(n->type, wf->type_filter))
		return false;

	for (i = 0; i < wf->nr_filters; i++) {
		wt = &wf->filters[i];
		if (n->type == wt->type &&
		    (wt->subtype_filter[st_index] & st_bit) &&
		    (n->info & wt->info_mask) == wt->info_filter)
			return true;
	}

	return false; /* If there is a filter, the default is to reject. */
}

/**
 * __post_watch_notification - Post an event notification
 * @wlist: The watch list to post the event to.
 * @n: The notification record to post.
 * @cred: The creds of the process that triggered the notification.
 * @id: The ID to match on the watch.
 *
 * Post a notification of an event into a set of watch queues and let the users
 * know.
 *
 * The size of the notification should be set in n->info & WATCH_INFO_LENGTH and
 * should be in units of sizeof(*n).
 */
void __post_watch_notification(struct watch_list *wlist,
			       struct watch_notification *n,
			       const struct cred *cred,
			       u64 id)
{
	const struct watch_filter *wf;
	struct watch_queue *wqueue;
	struct watch *watch;

	if (((n->info & WATCH_INFO_LENGTH) >> WATCH_INFO_LENGTH__SHIFT) == 0) {
		WARN_ON(1);
		return;
	}

	rcu_read_lock();

	hlist_for_each_entry_rcu(watch, &wlist->watchers, list_node) {
		if (watch->id != id)
			continue;
		n->info &= ~WATCH_INFO_ID;
		n->info |= watch->info_id;

		wqueue = rcu_dereference(watch->queue);
		wf = rcu_dereference(wqueue->filter);
		if (wf && !filter_watch_notification(wf, n))
			continue;

		if (security_post_notification(watch->cred, cred, n) < 0)
			continue;

		post_one_notification(wqueue, n);
	}

	rcu_read_unlock();
}
EXPORT_SYMBOL(__post_watch_notification);

/*
 * Allow the queue to be polled.
 */
static __poll_t watch_queue_poll(struct file *file, poll_table *wait)
{
	struct watch_queue *wqueue = file->private_data;
	struct watch_queue_buffer *buf = wqueue->buffer;
	unsigned int head, tail;
	__poll_t mask = 0;

	if (!buf)
		return EPOLLERR;

	poll_wait(file, &wqueue->waiters, wait);

	head = READ_ONCE(buf->meta.head);
	tail = READ_ONCE(buf->meta.tail);
	if (head != tail)
		mask |= EPOLLIN | EPOLLRDNORM;
	if (head - tail > wqueue->size)
		mask |= EPOLLERR;
	return mask;
}

static int watch_queue_set_page_dirty(struct page *page)
{
	SetPageDirty(page);
	return 0;
}

static const struct address_space_operations watch_queue_aops = {
	.set_page_dirty	= watch_queue_set_page_dirty,
};

static vm_fault_t watch_queue_fault(struct vm_fault *vmf)
{
	struct watch_queue *wqueue = vmf->vma->vm_file->private_data;
	struct page *page;

	page = wqueue->pages[vmf->pgoff];
	get_page(page);
	if (!lock_page_or_retry(page, vmf->vma->vm_mm, vmf->flags)) {
		put_page(page);
		return VM_FAULT_RETRY;
	}
	vmf->page = page;
	return VM_FAULT_LOCKED;
}

static int watch_queue_account_mem(struct watch_queue *wqueue,
				   unsigned long nr_pages)
{
	struct user_struct *user = wqueue->owner;
	unsigned long page_limit, cur_pages, new_pages;

	/* Don't allow more pages than we can safely lock */
	page_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	cur_pages = atomic_long_read(&user->locked_vm);

	do {
		new_pages = cur_pages + nr_pages;
		if (new_pages > page_limit && !capable(CAP_IPC_LOCK))
			return -ENOMEM;
	} while (atomic_long_try_cmpxchg_relaxed(&user->locked_vm, &cur_pages,
						 new_pages));

	wqueue->nr_pages = nr_pages;
	return 0;
}

static void watch_queue_unaccount_mem(struct watch_queue *wqueue)
{
	struct user_struct *user = wqueue->owner;

	if (wqueue->nr_pages) {
		atomic_long_sub(wqueue->nr_pages, &user->locked_vm);
		wqueue->nr_pages = 0;
	}
}

static void watch_queue_map_pages(struct vm_fault *vmf,
				  pgoff_t start_pgoff, pgoff_t end_pgoff)
{
	struct watch_queue *wqueue = vmf->vma->vm_file->private_data;
	struct page *page;

	rcu_read_lock();

	do {
		page = wqueue->pages[start_pgoff];
		if (trylock_page(page)) {
			vm_fault_t ret;
			get_page(page);
			ret = alloc_set_pte(vmf, NULL, page);
			if (ret != 0)
				put_page(page);

			unlock_page(page);
		}
	} while (++start_pgoff < end_pgoff);

	rcu_read_unlock();
}

static const struct vm_operations_struct watch_queue_vm_ops = {
	.fault		= watch_queue_fault,
	.map_pages	= watch_queue_map_pages,
};

/*
 * Map the buffer.
 */
static int watch_queue_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct watch_queue *wqueue = file->private_data;
	struct inode *inode = file_inode(file);
	u8 nr_pages;

	inode_lock(inode);
	nr_pages = wqueue->nr_pages;
	inode_unlock(inode);

	if (nr_pages == 0 ||
	    vma->vm_pgoff != 0 ||
	    vma->vm_end - vma->vm_start > nr_pages * PAGE_SIZE ||
	    !(pgprot_val(vma->vm_page_prot) & pgprot_val(PAGE_SHARED)))
		return -EINVAL;

	vma->vm_flags |= VM_DONTEXPAND;
	vma->vm_ops = &watch_queue_vm_ops;
	return 0;
}

/*
 * Allocate the required number of pages.
 */
static long watch_queue_set_size(struct watch_queue *wqueue, unsigned long nr_pages)
{
	struct watch_queue_buffer *buf;
	unsigned int gran = WATCH_LENGTH_GRANULARITY;
	unsigned int metalen = sizeof(buf->meta) / gran;
	int i;

	BUILD_BUG_ON(gran != sizeof(__u64));

	if (wqueue->buffer)
		return -EBUSY;

	if (nr_pages == 0 ||
	    nr_pages > 16 || /* TODO: choose a better hard limit */
	    !is_power_of_2(nr_pages))
		return -EINVAL;

	if (watch_queue_account_mem(wqueue, nr_pages) < 0)
		goto err;

	wqueue->pages = kcalloc(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!wqueue->pages)
		goto err_unaccount;

	for (i = 0; i < nr_pages; i++) {
		wqueue->pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!wqueue->pages[i])
			goto err_some_pages;
		wqueue->pages[i]->mapping = &wqueue->mapping;
		SetPageUptodate(wqueue->pages[i]);
	}

	buf = vmap(wqueue->pages, nr_pages, VM_MAP, PAGE_SHARED);
	if (!buf)
		goto err_some_pages;

	wqueue->buffer = buf;
	wqueue->size = ((nr_pages * PAGE_SIZE) / sizeof(struct watch_notification));

	/* The first four slots in the buffer contain metadata about the ring,
	 * including the head and tail indices and mask.
	 */
	buf->meta.watch.info	= metalen << WATCH_INFO_LENGTH__SHIFT;
	buf->meta.watch.type	= WATCH_TYPE_META;
	buf->meta.watch.subtype	= WATCH_META_SKIP_NOTIFICATION;
	buf->meta.mask		= wqueue->size - 1;
	buf->meta.head		= metalen;
	buf->meta.tail		= metalen;
	return 0;

err_some_pages:
	for (i--; i >= 0; i--) {
		ClearPageUptodate(wqueue->pages[i]);
		wqueue->pages[i]->mapping = NULL;
		put_page(wqueue->pages[i]);
	}

	kfree(wqueue->pages);
	wqueue->pages = NULL;
err_unaccount:
	watch_queue_unaccount_mem(wqueue);
err:
	return -ENOMEM;
}

/*
 * Set the filter on a watch queue.
 */
static long watch_queue_set_filter(struct inode *inode,
				   struct watch_queue *wqueue,
				   struct watch_notification_filter __user *_filter)
{
	struct watch_notification_type_filter *tf;
	struct watch_notification_filter filter;
	struct watch_type_filter *q;
	struct watch_filter *wfilter;
	int ret, nr_filter = 0, i;

	if (!_filter) {
		/* Remove the old filter */
		wfilter = NULL;
		goto set;
	}

	/* Grab the user's filter specification */
	if (copy_from_user(&filter, _filter, sizeof(filter)) != 0)
		return -EFAULT;
	if (filter.nr_filters == 0 ||
	    filter.nr_filters > 16 ||
	    filter.__reserved != 0)
		return -EINVAL;

	tf = memdup_user(_filter->filters, filter.nr_filters * sizeof(*tf));
	if (IS_ERR(tf))
		return PTR_ERR(tf);

	ret = -EINVAL;
	for (i = 0; i < filter.nr_filters; i++) {
		if ((tf[i].info_filter & ~tf[i].info_mask) ||
		    tf[i].info_mask & WATCH_INFO_LENGTH)
			goto err_filter;
		/* Ignore any unknown types */
		if (tf[i].type >= sizeof(wfilter->type_filter) * 8)
			continue;
		nr_filter++;
	}

	/* Now we need to build the internal filter from only the relevant
	 * user-specified filters.
	 */
	ret = -ENOMEM;
	wfilter = kzalloc(struct_size(wfilter, filters, nr_filter), GFP_KERNEL);
	if (!wfilter)
		goto err_filter;
	wfilter->nr_filters = nr_filter;

	q = wfilter->filters;
	for (i = 0; i < filter.nr_filters; i++) {
		if (tf[i].type >= sizeof(wfilter->type_filter) * BITS_PER_LONG)
			continue;

		q->type			= tf[i].type;
		q->info_filter		= tf[i].info_filter;
		q->info_mask		= tf[i].info_mask;
		q->subtype_filter[0]	= tf[i].subtype_filter[0];
		__set_bit(q->type, wfilter->type_filter);
		q++;
	}

	kfree(tf);
set:
	inode_lock(inode);
	rcu_swap_protected(wqueue->filter, wfilter,
			   lockdep_is_held(&inode->i_rwsem));
	inode_unlock(inode);
	if (wfilter)
		kfree_rcu(wfilter, rcu);
	return 0;

err_filter:
	kfree(tf);
	return ret;
}

/*
 * Set parameters.
 */
static long watch_queue_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct watch_queue *wqueue = file->private_data;
	struct inode *inode = file_inode(file);
	long ret;

	switch (cmd) {
	case IOC_WATCH_QUEUE_SET_SIZE:
		inode_lock(inode);
		ret = watch_queue_set_size(wqueue, arg);
		inode_unlock(inode);
		return ret;

	case IOC_WATCH_QUEUE_SET_FILTER:
		ret = watch_queue_set_filter(
			inode, wqueue,
			(struct watch_notification_filter __user *)arg);
		return ret;

	default:
		return -ENOTTY;
	}
}

/*
 * Open the file.
 */
static int watch_queue_open(struct inode *inode, struct file *file)
{
	struct watch_queue *wqueue;

	wqueue = kzalloc(sizeof(*wqueue), GFP_KERNEL);
	if (!wqueue)
		return -ENOMEM;

	wqueue->mapping.a_ops = &watch_queue_aops;
	wqueue->mapping.i_mmap = RB_ROOT_CACHED;
	init_rwsem(&wqueue->mapping.i_mmap_rwsem);
	spin_lock_init(&wqueue->mapping.private_lock);

	kref_init(&wqueue->usage);
	spin_lock_init(&wqueue->lock);
	init_waitqueue_head(&wqueue->waiters);
	wqueue->owner = get_uid(file->f_cred->user);

	file->private_data = wqueue;
	return 0;
}

static void __put_watch_queue(struct kref *kref)
{
	struct watch_queue *wqueue =
		container_of(kref, struct watch_queue, usage);
	struct watch_filter *wfilter;

	wfilter = rcu_access_pointer(wqueue->filter);
	if (wfilter)
		kfree_rcu(wfilter, rcu);
	free_uid(wqueue->owner);
	kfree_rcu(wqueue, rcu);
}

/**
 * put_watch_queue - Dispose of a ref on a watchqueue.
 * @wqueue: The watch queue to unref.
 */
void put_watch_queue(struct watch_queue *wqueue)
{
	kref_put(&wqueue->usage, __put_watch_queue);
}
EXPORT_SYMBOL(put_watch_queue);

static void free_watch(struct rcu_head *rcu)
{
	struct watch *watch = container_of(rcu, struct watch, rcu);

	put_watch_queue(rcu_access_pointer(watch->queue));
	put_cred(watch->cred);
}

static void __put_watch(struct kref *kref)
{
	struct watch *watch = container_of(kref, struct watch, usage);

	call_rcu(&watch->rcu, free_watch);
}

/*
 * Discard a watch.
 */
static void put_watch(struct watch *watch)
{
	kref_put(&watch->usage, __put_watch);
}

/**
 * init_watch_queue - Initialise a watch
 * @watch: The watch to initialise.
 * @wqueue: The queue to assign.
 *
 * Initialise a watch and set the watch queue.
 */
void init_watch(struct watch *watch, struct watch_queue *wqueue)
{
	kref_init(&watch->usage);
	INIT_HLIST_NODE(&watch->list_node);
	INIT_HLIST_NODE(&watch->queue_node);
	rcu_assign_pointer(watch->queue, wqueue);
}

/**
 * add_watch_to_object - Add a watch on an object to a watch list
 * @watch: The watch to add
 * @wlist: The watch list to add to
 *
 * @watch->queue must have been set to point to the queue to post notifications
 * to and the watch list of the object to be watched.  @watch->cred must also
 * have been set to the appropriate credentials and a ref taken on them.
 *
 * The caller must pin the queue and the list both and must hold the list
 * locked against racing watch additions/removals.
 */
int add_watch_to_object(struct watch *watch, struct watch_list *wlist)
{
	struct watch_queue *wqueue = rcu_access_pointer(watch->queue);
	struct watch *w;

	hlist_for_each_entry(w, &wlist->watchers, list_node) {
		struct watch_queue *wq = rcu_access_pointer(w->queue);
		if (wqueue == wq && watch->id == w->id)
			return -EBUSY;
	}

	watch->cred = get_current_cred();
	rcu_assign_pointer(watch->watch_list, wlist);

	spin_lock_bh(&wqueue->lock);
	kref_get(&wqueue->usage);
	hlist_add_head(&watch->queue_node, &wqueue->watches);
	spin_unlock_bh(&wqueue->lock);

	hlist_add_head(&watch->list_node, &wlist->watchers);
	return 0;
}
EXPORT_SYMBOL(add_watch_to_object);

/**
 * remove_watch_from_object - Remove a watch or all watches from an object.
 * @wlist: The watch list to remove from
 * @wq: The watch queue of interest (ignored if @all is true)
 * @id: The ID of the watch to remove (ignored if @all is true)
 * @all: True to remove all objects
 *
 * Remove a specific watch or all watches from an object.  A notification is
 * sent to the watcher to tell them that this happened.
 */
int remove_watch_from_object(struct watch_list *wlist, struct watch_queue *wq,
			     u64 id, bool all)
{
	struct watch_notification_removal n;
	struct watch_queue *wqueue;
	struct watch *watch;
	int ret = -EBADSLT;

	rcu_read_lock();

again:
	spin_lock(&wlist->lock);
	hlist_for_each_entry(watch, &wlist->watchers, list_node) {
		if (all ||
		    (watch->id == id && rcu_access_pointer(watch->queue) == wq))
			goto found;
	}
	spin_unlock(&wlist->lock);
	goto out;

found:
	ret = 0;
	hlist_del_init_rcu(&watch->list_node);
	rcu_assign_pointer(watch->watch_list, NULL);
	spin_unlock(&wlist->lock);

	/* We now own the reference on watch that used to belong to wlist. */

	n.watch.type = WATCH_TYPE_META;
	n.watch.subtype = WATCH_META_REMOVAL_NOTIFICATION;
	n.watch.info = watch->info_id | watch_sizeof(n.watch);
	n.id = id;
	if (id != 0)
		n.watch.info = watch->info_id | watch_sizeof(n);

	wqueue = rcu_dereference(watch->queue);

	/* We don't need the watch list lock for the next bit as RCU is
	 * protecting *wqueue from deallocation.
	 */
	if (wqueue) {
		post_one_notification(wqueue, &n.watch);

		spin_lock_bh(&wqueue->lock);

		if (!hlist_unhashed(&watch->queue_node)) {
			hlist_del_init_rcu(&watch->queue_node);
			put_watch(watch);
		}

		spin_unlock_bh(&wqueue->lock);
	}

	if (wlist->release_watch) {
		void (*release_watch)(struct watch *);

		release_watch = wlist->release_watch;
		rcu_read_unlock();
		(*release_watch)(watch);
		rcu_read_lock();
	}
	put_watch(watch);

	if (all && !hlist_empty(&wlist->watchers))
		goto again;
out:
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(remove_watch_from_object);

/*
 * Remove all the watches that are contributory to a queue.  This has the
 * potential to race with removal of the watches by the destruction of the
 * objects being watched or with the distribution of notifications.
 */
static void watch_queue_clear(struct watch_queue *wqueue)
{
	struct watch_list *wlist;
	struct watch *watch;
	bool release;

	rcu_read_lock();
	spin_lock_bh(&wqueue->lock);

	/* Prevent new additions and prevent notifications from happening */
	wqueue->defunct = true;

	while (!hlist_empty(&wqueue->watches)) {
		watch = hlist_entry(wqueue->watches.first, struct watch, queue_node);
		hlist_del_init_rcu(&watch->queue_node);
		/* We now own a ref on the watch. */
		spin_unlock_bh(&wqueue->lock);

		/* We can't do the next bit under the queue lock as we need to
		 * get the list lock - which would cause a deadlock if someone
		 * was removing from the opposite direction at the same time or
		 * posting a notification.
		 */
		wlist = rcu_dereference(watch->watch_list);
		if (wlist) {
			void (*release_watch)(struct watch *);

			spin_lock(&wlist->lock);

			release = !hlist_unhashed(&watch->list_node);
			if (release) {
				hlist_del_init_rcu(&watch->list_node);
				rcu_assign_pointer(watch->watch_list, NULL);

				/* We now own a second ref on the watch. */
			}

			release_watch = wlist->release_watch;
			spin_unlock(&wlist->lock);

			if (release) {
				if (release_watch) {
					rcu_read_unlock();
					/* This might need to call dput(), so
					 * we have to drop all the locks.
					 */
					(*release_watch)(watch);
					rcu_read_lock();
				}
				put_watch(watch);
			}
		}

		put_watch(watch);
		spin_lock_bh(&wqueue->lock);
	}

	spin_unlock_bh(&wqueue->lock);
	rcu_read_unlock();
}

/*
 * Release the file.
 */
static int watch_queue_release(struct inode *inode, struct file *file)
{
	struct watch_queue *wqueue = file->private_data;
	int i;

	watch_queue_clear(wqueue);

	if (wqueue->buffer)
		vunmap(wqueue->buffer);

	for (i = 0; i < wqueue->nr_pages; i++) {
		ClearPageUptodate(wqueue->pages[i]);
		wqueue->pages[i]->mapping = NULL;
		__free_page(wqueue->pages[i]);
	}

	kfree(wqueue->pages);
	watch_queue_unaccount_mem(wqueue);
	put_watch_queue(wqueue);
	return 0;
}

static const struct file_operations watch_queue_fops = {
	.owner		= THIS_MODULE,
	.open		= watch_queue_open,
	.release	= watch_queue_release,
	.unlocked_ioctl	= watch_queue_ioctl,
	.poll		= watch_queue_poll,
	.mmap		= watch_queue_mmap,
	.llseek		= no_llseek,
};

/**
 * get_watch_queue - Get a watch queue from its file descriptor.
 * @fd: The fd to query.
 */
struct watch_queue *get_watch_queue(int fd)
{
	struct watch_queue *wqueue = ERR_PTR(-EBADF);
	struct fd f;

	f = fdget(fd);
	if (f.file) {
		wqueue = ERR_PTR(-EINVAL);
		if (f.file->f_op == &watch_queue_fops) {
			wqueue = f.file->private_data;
			kref_get(&wqueue->usage);
		}
		fdput(f);
	}

	return wqueue;
}
EXPORT_SYMBOL(get_watch_queue);

static struct miscdevice watch_queue_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "watch_queue",
	.fops	= &watch_queue_fops,
	.mode	= 0666,
};
builtin_misc_device(watch_queue_dev);
