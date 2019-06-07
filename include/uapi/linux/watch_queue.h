/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_WATCH_QUEUE_H
#define _UAPI_LINUX_WATCH_QUEUE_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define IOC_WATCH_QUEUE_SET_SIZE	_IO('W', 0x60)	/* Set the size in pages */
#define IOC_WATCH_QUEUE_SET_FILTER	_IO('W', 0x61)	/* Set the filter */

enum watch_notification_type {
	WATCH_TYPE_META		= 0,	/* Special record */
	WATCH_TYPE_KEY_NOTIFY	= 1,	/* Key change event notification */
	WATCH_TYPE_BLOCK_NOTIFY	= 2,	/* Block layer event notification */
	WATCH_TYPE_USB_NOTIFY	= 3,	/* USB subsystem event notification */
	WATCH_TYPE___NR		= 4
};

enum watch_meta_notification_subtype {
	WATCH_META_SKIP_NOTIFICATION	= 0,	/* Just skip this record */
	WATCH_META_REMOVAL_NOTIFICATION	= 1,	/* Watched object was removed */
};

#define WATCH_LENGTH_GRANULARITY sizeof(__u64)

/*
 * Notification record header.  This is aligned to 64-bits so that subclasses
 * can contain __u64 fields.
 */
struct watch_notification {
	__u32			type:24;	/* enum watch_notification_type */
	__u32			subtype:8;	/* Type-specific subtype (filterable) */
	__u32			info;
#define WATCH_INFO_LENGTH	0x0000003f	/* Length of record / sizeof(watch_notification) */
#define WATCH_INFO_LENGTH__SHIFT 0
#define WATCH_INFO_ID		0x0000ff00	/* ID of watchpoint, if type-appropriate */
#define WATCH_INFO_ID__SHIFT	8
#define WATCH_INFO_TYPE_INFO	0xffff0000	/* Type-specific info */
#define WATCH_INFO_TYPE_INFO__SHIFT 16
#define WATCH_INFO_FLAG_0	0x00010000	/* Type-specific info, flag bit 0 */
#define WATCH_INFO_FLAG_1	0x00020000	/* ... */
#define WATCH_INFO_FLAG_2	0x00040000
#define WATCH_INFO_FLAG_3	0x00080000
#define WATCH_INFO_FLAG_4	0x00100000
#define WATCH_INFO_FLAG_5	0x00200000
#define WATCH_INFO_FLAG_6	0x00400000
#define WATCH_INFO_FLAG_7	0x00800000
} __attribute__((aligned(WATCH_LENGTH_GRANULARITY)));

struct watch_queue_buffer {
	union {
		/* The first few entries are special, containing the
		 * ring management variables.
		 */
		struct {
			struct watch_notification watch; /* WATCH_TYPE_META */
			__u32		head;		/* Ring head index */
			__u32		tail;		/* Ring tail index */
			__u32		mask;		/* Ring index mask */
			__u32		__reserved;
		} meta;
		struct watch_notification slots[0];
	};
};

/*
 * The Metadata pseudo-notification message uses a flag bits in the information
 * field to convey the fact that messages have been lost.  We can only use a
 * single bit in this manner per word as some arches that support SMP
 * (eg. parisc) have no kernel<->user atomic bit ops.
 */
#define WATCH_INFO_NOTIFICATIONS_LOST WATCH_INFO_FLAG_0

/*
 * Notification filtering rules (IOC_WATCH_QUEUE_SET_FILTER).
 */
struct watch_notification_type_filter {
	__u32	type;			/* Type to apply filter to */
	__u32	info_filter;		/* Filter on watch_notification::info */
	__u32	info_mask;		/* Mask of relevant bits in info_filter */
	__u32	subtype_filter[8];	/* Bitmask of subtypes to filter on */
};

struct watch_notification_filter {
	__u32	nr_filters;		/* Number of filters */
	__u32	__reserved;		/* Must be 0 */
	struct watch_notification_type_filter filters[];
};

/*
 * Extended watch removal notification.  This is used optionally if the type
 * wants to indicate an identifier for the object being watched, if there is
 * such.  This can be distinguished by the length.
 *
 * type -> WATCH_TYPE_META
 * subtype -> WATCH_META_REMOVAL_NOTIFICATION
 * length -> 2 * gran
 */
struct watch_notification_removal {
	struct watch_notification watch;
	__u64	id;		/* Type-dependent identifier */
};

/*
 * Type of key/keyring change notification.
 */
enum key_notification_subtype {
	NOTIFY_KEY_INSTANTIATED	= 0, /* Key was instantiated (aux is error code) */
	NOTIFY_KEY_UPDATED	= 1, /* Key was updated */
	NOTIFY_KEY_LINKED	= 2, /* Key (aux) was added to watched keyring */
	NOTIFY_KEY_UNLINKED	= 3, /* Key (aux) was removed from watched keyring */
	NOTIFY_KEY_CLEARED	= 4, /* Keyring was cleared */
	NOTIFY_KEY_REVOKED	= 5, /* Key was revoked */
	NOTIFY_KEY_INVALIDATED	= 6, /* Key was invalidated */
	NOTIFY_KEY_SETATTR	= 7, /* Key's attributes got changed */
};

/*
 * Key/keyring notification record.
 * - watch.type = WATCH_TYPE_KEY_NOTIFY
 * - watch.subtype = enum key_notification_type
 */
struct key_notification {
	struct watch_notification watch;
	__u32	key_id;		/* The key/keyring affected */
	__u32	aux;		/* Per-type auxiliary data */
};

/*
 * Type of block layer notification.
 */
enum block_notification_type {
	NOTIFY_BLOCK_ERROR_TIMEOUT		= 1, /* Timeout error */
	NOTIFY_BLOCK_ERROR_NO_SPACE		= 2, /* Critical space allocation error */
	NOTIFY_BLOCK_ERROR_RECOVERABLE_TRANSPORT = 3, /* Recoverable transport error */
	NOTIFY_BLOCK_ERROR_CRITICAL_TARGET	= 4, /* Critical target error */
	NOTIFY_BLOCK_ERROR_CRITICAL_NEXUS	= 5, /* Critical nexus error */
	NOTIFY_BLOCK_ERROR_CRITICAL_MEDIUM	= 6, /* Critical medium error */
	NOTIFY_BLOCK_ERROR_PROTECTION		= 7, /* Protection error */
	NOTIFY_BLOCK_ERROR_KERNEL_RESOURCE	= 8, /* Kernel resource error */
	NOTIFY_BLOCK_ERROR_DEVICE_RESOURCE	= 9, /* Device resource error */
	NOTIFY_BLOCK_ERROR_IO			= 10, /* Other I/O error */
};

/*
 * Block layer notification record.
 * - watch.type = WATCH_TYPE_BLOCK_NOTIFY
 * - watch.subtype = enum block_notification_type
 */
struct block_notification {
	struct watch_notification watch; /* WATCH_TYPE_BLOCK_NOTIFY */
	__u64	dev;			/* Device number */
	__u64	sector;			/* Affected sector */
};

/*
 * Type of USB layer notification.
 */
enum usb_notification_type {
	NOTIFY_USB_DEVICE_ADD		= 0, /* USB device added */
	NOTIFY_USB_DEVICE_REMOVE	= 1, /* USB device removed */
	NOTIFY_USB_DEVICE_RESET		= 2, /* USB device reset */
	NOTIFY_USB_DEVICE_ERROR		= 3, /* USB device error */
};

/*
 * USB subsystem notification record.
 * - watch.type = WATCH_TYPE_USB_NOTIFY
 * - watch.subtype = enum usb_notification_type
 */
struct usb_notification {
	struct watch_notification watch; /* WATCH_TYPE_USB_NOTIFY */
	__u32	error;
	__u32	reserved;
	__u8	name_len;		/* Length of device name */
	__u8	name[0];		/* Device name (padded to __u64, truncated at 63 chars) */
};

#define USB_NOTIFICATION_MAX_NAME_LEN 63

#endif /* _UAPI_LINUX_WATCH_QUEUE_H */
