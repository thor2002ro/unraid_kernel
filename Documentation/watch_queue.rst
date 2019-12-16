============================
Mappable notifications queue
============================

This is a misc device that acts as a mapped ring buffer by which userspace can
receive notifications from the kernel.  This can be used in conjunction with::

  * Key/keyring notifications

  * General device event notifications, including::

    * Block layer event notifications

    * USB subsystem event notifications


The notifications buffers can be enabled by:

	"Device Drivers"/"Misc devices"/"Mappable notification queue"
	(CONFIG_WATCH_QUEUE)

This document has the following sections:

.. contents:: :local:


Overview
========

This facility appears as a misc device file that is opened and then mapped and
polled.  Each time it is opened, it creates a new buffer specific to the
returned file descriptor.  Then, when the opening process sets watches, it
indicates the particular buffer it wants notifications from that watch to be
written into.  Note that there are no read() and write() methods (except for
debugging).  The user is expected to access the ring directly and to use poll
to wait for new data.

If a watch is in place, notifications are only written into the buffer if the
filter criteria are passed and if there's sufficient space available in the
ring.  If neither of those is so, a notification will be discarded.  In the
latter case, an overrun indicator will also be set.

Note that when producing a notification, the kernel does not wait for the
consumers to collect it, but rather just continues on.  This means that
notifications can be generated whilst spinlocks are held and also protects the
kernel from being held up indefinitely by a userspace malfunction.

As far as the ring goes, the head index belongs to the kernel and the tail
index belongs to userspace.  The kernel will refuse to write anything if the
tail index becomes invalid.  Userspace *must* use appropriate memory barriers
between reading or updating the tail index and reading the ring.


Record Structure
================

Notification records in the ring may occupy a variable number of slots within
the buffer, beginning with a 1-slot header::

	struct watch_notification {
		__u32	type:24;
		__u32	subtype:8;
		__u32	info;
	} __attribute__((aligned(WATCH_LENGTH_GRANULARITY)));

"type" indicates the source of the notification record and "subtype" indicates
the type of record from that source (see the Watch Sources section below).  The
type may also be "WATCH_TYPE_META".  This is a special record type generated
internally by the watch queue driver itself.  There are two subtypes, one of
which indicates records that should be just skipped (padding or metadata):

  * WATCH_META_SKIP_NOTIFICATION
  * WATCH_META_REMOVAL_NOTIFICATION

The former indicates a record that should just be skipped and the latter
indicates that an object on which a watch was installed was removed or
destroyed.

"info" indicates a bunch of things, including:

  * The length of the record in units of buffer slots (mask with
    WATCH_INFO_LENGTH and shift by WATCH_INFO_LENGTH__SHIFT).  This indicates
    the size of the record, which may be between 1 and 63 slots.  To turn this
    into a number of bytes, multiply by WATCH_LENGTH_GRANULARITY.

  * The watch ID (mask with WATCH_INFO_ID and shift by WATCH_INFO_ID__SHIFT).
    This indicates that caller's ID of the watch, which may be between 0
    and 255.  Multiple watches may share a queue, and this provides a means to
    distinguish them.

  * In the metadata header in slot 0, a flag (WATCH_INFO_NOTIFICATIONS_LOST)
    that indicates that some notifications were lost for some reason, including
    buffer overrun, insufficient memory and inconsistent tail index.

  * A type-specific field (WATCH_INFO_TYPE_INFO).  This is set by the
    notification producer to indicate some meaning specific to the type and
    subtype.

Everything in info apart from the length can be used for filtering.


Ring Structure
==============

The ring is divided into slots of size WATCH_LENGTH_GRANULARITY (8 bytes).  The
caller uses an ioctl() to set the size of the ring after opening and this must
be a power-of-2 multiple of the system page size (so that the mask can be used
with AND).

The head and tail indices are stored in the first two slots in the ring, which
are marked out as a skippable entry::

	struct watch_queue_buffer {
		union {
			struct {
				struct watch_notification watch;
				volatile __u32	head;
				volatile __u32	tail;
				__u32		mask;
			} meta;
			struct watch_notification slots[0];
		};
	};

In "meta.watch", type will be set to WATCH_TYPE_META and subtype to
WATCH_META_SKIP_NOTIFICATION so that anyone processing the buffer will just
skip this record.  Also, because this record is here, records cannot wrap round
the end of the buffer, so a skippable padding element will be inserted at the
end of the buffer if needed.  Thus the contents of a notification record in the
buffer are always contiguous.

"meta.mask" is an AND'able mask to turn the index counters into slots array
indices.

The buffer is empty if "meta.head" == "meta.tail".

[!] NOTE that the ring indices "meta.head" and "meta.tail" are indices into
"slots[]" not byte offsets into the buffer.

[!] NOTE that userspace must never change the head pointer.  This belongs to
the kernel and will be updated by that.  The kernel will never change the tail
pointer.

[!] NOTE that userspace must never AND-off the tail pointer before updating it,
but should just keep adding to it and letting it wrap naturally.  The value
*should* be masked off when used as an index into slots[].

[!] NOTE that if the distance between head and tail becomes too great, the
kernel will assume the buffer is full and write no more until the issue is
resolved.


Watch List (Notification Source) API
====================================

A "watch list" is a list of watchers that are subscribed to a source of
notifications.  A list may be attached to an object (say a key or a superblock)
or may be global (say for device events).  From a userspace perspective, a
non-global watch list is typically referred to by reference to the object it
belongs to (such as using KEYCTL_NOTIFY and giving it a key serial number to
watch that specific key).

To manage a watch list, the following functions are provided:

  * ``void init_watch_list(struct watch_list *wlist,
			   void (*release_watch)(struct watch *wlist));``

    Initialise a watch list.  If ``release_watch`` is not NULL, then this
    indicates a function that should be called when the watch_list object is
    destroyed to discard any references the watch list holds on the watched
    object.

  * ``void remove_watch_list(struct watch_list *wlist);``

    This removes all of the watches subscribed to a watch_list and frees them
    and then destroys the watch_list object itself.


Watch Queue (Notification Buffer) API
=====================================

A "watch queue" is the buffer allocated by or on behalf of the application that
notification records will be written into.  The workings of this are hidden
entirely inside of the watch_queue device driver, but it is necessary to gain a
reference to it to place a watch.  These can be managed with:

  * ``struct watch_queue *get_watch_queue(int fd);``

    Since watch queues are indicated to the kernel by the fd of the character
    device that implements the buffer, userspace must hand that fd through a
    system call.  This can be used to look up an opaque pointer to the watch
    queue from the system call.

  * ``void put_watch_queue(struct watch_queue *wqueue);``

    This discards the reference obtained from ``get_watch_queue()``.


Watch Subscription API
======================

A "watch" is a subscription on a watch list, indicating the watch queue, and
thus the buffer, into which notification records should be written.  The watch
queue object may also carry filtering rules for that object, as set by
userspace.  Some parts of the watch struct can be set by the driver::

	struct watch {
		union {
			u32		info_id;	/* ID to be OR'd in to info field */
			...
		};
		void			*private;	/* Private data for the watched object */
		u64			id;		/* Internal identifier */
		...
	};

The ``info_id`` value should be an 8-bit number obtained from userspace and
shifted by WATCH_INFO_ID__SHIFT.  This is OR'd into the WATCH_INFO_ID field of
struct watch_notification::info when and if the notification is written into
the associated watch queue buffer.

The ``private`` field is the driver's data associated with the watch_list and
is cleaned up by the ``watch_list::release_watch()`` method.

The ``id`` field is the source's ID.  Notifications that are posted with a
different ID are ignored.

The following functions are provided to manage watches:

  * ``void init_watch(struct watch *watch, struct watch_queue *wqueue);``

    Initialise a watch object, setting its pointer to the watch queue, using
    appropriate barriering to avoid lockdep complaints.

  * ``int add_watch_to_object(struct watch *watch, struct watch_list *wlist);``

    Subscribe a watch to a watch list (notification source).  The
    driver-settable fields in the watch struct must have been set before this
    is called.

  * ``int remove_watch_from_object(struct watch_list *wlist,
				   struct watch_queue *wqueue,
				   u64 id, false);``

    Remove a watch from a watch list, where the watch must match the specified
    watch queue (``wqueue``) and object identifier (``id``).  A notification
    (``WATCH_META_REMOVAL_NOTIFICATION``) is sent to the watch queue to
    indicate that the watch got removed.

  * ``int remove_watch_from_object(struct watch_list *wlist, NULL, 0, true);``

    Remove all the watches from a watch list.  It is expected that this will be
    called preparatory to destruction and that the watch list will be
    inaccessible to new watches by this point.  A notification
    (``WATCH_META_REMOVAL_NOTIFICATION``) is sent to the watch queue of each
    subscribed watch to indicate that the watch got removed.


Notification Posting API
========================

To post a notification to watch list so that the subscribed watches can see it,
the following function should be used::

	void post_watch_notification(struct watch_list *wlist,
				     struct watch_notification *n,
				     const struct cred *cred,
				     u64 id);

The notification should be preformatted and a pointer to the header (``n``)
should be passed in.  The notification may be larger than this and the size in
units of buffer slots is noted in ``n->info & WATCH_INFO_LENGTH``.

The ``cred`` struct indicates the credentials of the source (subject) and is
passed to the LSMs, such as SELinux, to allow or suppress the recording of the
note in each individual queue according to the credentials of that queue
(object).

The ``id`` is the ID of the source object (such as the serial number on a key).
Only watches that have the same ID set in them will see this notification.


Global Device Watch List
========================

There is a global watch list that hardware generated events, such as device
connection, disconnection, failure and error can be posted upon.  It must be
enabled using::

	CONFIG_DEVICE_NOTIFICATIONS

Watchpoints are set in userspace using the device_notify(2) system call.
Within the kernel events are posted upon it using::

	void post_device_notification(struct watch_notification *n, u64 id);

where ``n`` is the formatted notification record to post.  ``id`` is an
identifier that can be used to direct to specific watches, but it should be 0
for general use on this queue.


Watch Sources
=============

Any particular buffer can be fed from multiple sources.  Sources include:

  * WATCH_TYPE_KEY_NOTIFY

    Notifications of this type indicate changes to keys and keyrings, including
    the changes of keyring contents or the attributes of keys.

    See Documentation/security/keys/core.rst for more information.

  * WATCH_TYPE_BLOCK_NOTIFY

    Notifications of this type indicate block layer events, such as I/O errors
    or temporary link loss.  Watches of this type are set on the global device
    watch list.

  * WATCH_TYPE_USB_NOTIFY

    Notifications of this type indicate USB subsystem events, such as
    attachment, removal, reset and I/O errors.  Separate events are generated
    for buses and devices.  Watchpoints of this type are set on the global
    device watch list.


Event Filtering
===============

Once a watch queue has been created, a set of filters can be applied to limit
the events that are received using::

	struct watch_notification_filter filter = {
		...
	};
	ioctl(fd, IOC_WATCH_QUEUE_SET_FILTER, &filter)

The filter description is a variable of type::

	struct watch_notification_filter {
		__u32	nr_filters;
		__u32	__reserved;
		struct watch_notification_type_filter filters[];
	};

Where "nr_filters" is the number of filters in filters[] and "__reserved"
should be 0.  The "filters" array has elements of the following type::

	struct watch_notification_type_filter {
		__u32	type;
		__u32	info_filter;
		__u32	info_mask;
		__u32	subtype_filter[8];
	};

Where:

  * ``type`` is the event type to filter for and should be something like
    "WATCH_TYPE_KEY_NOTIFY"

  * ``info_filter`` and ``info_mask`` act as a filter on the info field of the
    notification record.  The notification is only written into the buffer if::

	(watch.info & info_mask) == info_filter

    This could be used, for example, to ignore events that are not exactly on
    the watched point in a mount tree.

  * ``subtype_filter`` is a bitmask indicating the subtypes that are of
    interest.  Bit 0 of subtype_filter[0] corresponds to subtype 0, bit 1 to
    subtype 1, and so on.

If the argument to the ioctl() is NULL, then the filters will be removed and
all events from the watched sources will come through.


Waiting For Events
==================

The file descriptor that holds the buffer may be used with poll() and similar.
POLLIN and POLLRDNORM are set if the buffer indices differ.  POLLERR is set if
the buffer indices are further apart than the size of the buffer.  Wake-up
events are only generated if the buffer is transitioned from an empty state.


Userspace Code Example
======================

A buffer is created with something like the following::

	fd = open("/dev/watch_queue", O_RDWR);

	#define BUF_SIZE 4
	ioctl(fd, IOC_WATCH_QUEUE_SET_SIZE, BUF_SIZE);

	page_size = sysconf(_SC_PAGESIZE);
	buf = mmap(NULL, BUF_SIZE * page_size,
		   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

It can then be set to receive keyring change notifications and device event
notifications::

	keyctl(KEYCTL_WATCH_KEY, KEY_SPEC_SESSION_KEYRING, fd, 0x01);

	watch_devices(fd, 0x2);

The notifications can then be consumed by something like the following::

	extern void saw_key_change(struct watch_notification *n);
	extern void saw_block_event(struct watch_notification *n);
	extern void saw_usb_event(struct watch_notification *n);

	static int consumer(int fd, struct watch_queue_buffer *buf)
	{
		struct watch_notification *n;
		struct pollfd p[1];
		unsigned int len, head, tail, mask = buf->meta.mask;

		for (;;) {
			p[0].fd = fd;
			p[0].events = POLLIN | POLLERR;
			p[0].revents = 0;

			if (poll(p, 1, -1) == -1 || p[0].revents & POLLERR)
				goto went_wrong;

			while (head = _atomic_load_acquire(buf->meta.head),
			       tail = buf->meta.tail,
			       tail != head
			       ) {
				n = &buf->slots[tail & mask];
				len = (n->info & WATCH_INFO_LENGTH) >>
					WATCH_INFO_LENGTH__SHIFT;
				if (len == 0)
					goto went_wrong;

				switch (n->type) {
				case WATCH_TYPE_KEY_NOTIFY:
					saw_key_change(n);
					break;
				case WATCH_TYPE_BLOCK_NOTIFY:
					saw_block_event(n);
					break;
				case WATCH_TYPE_USB_NOTIFY:
					saw_usb_event(n);
					break;
				}

				tail += len;
				_atomic_store_release(buf->meta.tail, tail);
			}
		}

	went_wrong:
		return 0;
	}

Note the memory barriers when loading the head pointer and storing the tail
pointer!
