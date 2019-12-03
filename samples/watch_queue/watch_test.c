// SPDX-License-Identifier: GPL-2.0
/* Use /dev/watch_queue to watch for notifications.
 *
 * Copyright (C) 2019 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include <limits.h>
#include <linux/watch_queue.h>
#include <linux/unistd.h>
#include <linux/keyctl.h>

#ifndef KEYCTL_WATCH_KEY
#define KEYCTL_WATCH_KEY -1
#endif
#ifndef __NR_watch_devices
#define __NR_watch_devices -1
#endif

#define BUF_SIZE 4

static long keyctl_watch_key(int key, int watch_fd, int watch_id)
{
	return syscall(__NR_keyctl, KEYCTL_WATCH_KEY, key, watch_fd, watch_id);
}

static const char *key_subtypes[256] = {
	[NOTIFY_KEY_INSTANTIATED]	= "instantiated",
	[NOTIFY_KEY_UPDATED]		= "updated",
	[NOTIFY_KEY_LINKED]		= "linked",
	[NOTIFY_KEY_UNLINKED]		= "unlinked",
	[NOTIFY_KEY_CLEARED]		= "cleared",
	[NOTIFY_KEY_REVOKED]		= "revoked",
	[NOTIFY_KEY_INVALIDATED]	= "invalidated",
	[NOTIFY_KEY_SETATTR]		= "setattr",
};

static void saw_key_change(struct watch_notification *n)
{
	struct key_notification *k = (struct key_notification *)n;
	unsigned int len = (n->info & WATCH_INFO_LENGTH) >> WATCH_INFO_LENGTH__SHIFT;

	if (len != sizeof(struct key_notification) / WATCH_LENGTH_GRANULARITY)
		return;

	printf("KEY %08x change=%u[%s] aux=%u\n",
	       k->key_id, n->subtype, key_subtypes[n->subtype], k->aux);
}

static const char *block_subtypes[256] = {
	[NOTIFY_BLOCK_ERROR_TIMEOUT]			= "timeout",
	[NOTIFY_BLOCK_ERROR_NO_SPACE]			= "critical space allocation",
	[NOTIFY_BLOCK_ERROR_RECOVERABLE_TRANSPORT]	= "recoverable transport",
	[NOTIFY_BLOCK_ERROR_CRITICAL_TARGET]		= "critical target",
	[NOTIFY_BLOCK_ERROR_CRITICAL_NEXUS]		= "critical nexus",
	[NOTIFY_BLOCK_ERROR_CRITICAL_MEDIUM]		= "critical medium",
	[NOTIFY_BLOCK_ERROR_PROTECTION]			= "protection",
	[NOTIFY_BLOCK_ERROR_KERNEL_RESOURCE]		= "kernel resource",
	[NOTIFY_BLOCK_ERROR_DEVICE_RESOURCE]		= "device resource",
	[NOTIFY_BLOCK_ERROR_IO]				= "I/O",
};

static void saw_block_change(struct watch_notification *n)
{
	struct block_notification *b = (struct block_notification *)n;
	unsigned int len = (n->info & WATCH_INFO_LENGTH) >> WATCH_INFO_LENGTH__SHIFT;

	if (len < sizeof(struct block_notification) / WATCH_LENGTH_GRANULARITY)
		return;

	printf("BLOCK %08llx e=%u[%s] s=%llx\n",
	       (unsigned long long)b->dev,
	       n->subtype, block_subtypes[n->subtype],
	       (unsigned long long)b->sector);
}

static const char *usb_subtypes[256] = {
	[NOTIFY_USB_DEVICE_ADD]		= "dev-add",
	[NOTIFY_USB_DEVICE_REMOVE]	= "dev-remove",
	[NOTIFY_USB_DEVICE_RESET]	= "dev-reset",
	[NOTIFY_USB_DEVICE_ERROR]	= "dev-error",
};

static void saw_usb_event(struct watch_notification *n)
{
	struct usb_notification *u = (struct usb_notification *)n;
	unsigned int len = (n->info & WATCH_INFO_LENGTH) >> WATCH_INFO_LENGTH__SHIFT;

	if (len < sizeof(struct usb_notification) / WATCH_LENGTH_GRANULARITY)
		return;

	printf("USB %*.*s %s e=%x r=%x\n",
	       u->name_len, u->name_len, u->name,
	       usb_subtypes[n->subtype],
	       u->error, u->reserved);
}

/*
 * Consume and display events.
 */
static int consumer(int fd, struct watch_queue_buffer *buf)
{
	struct watch_notification *n;
	struct pollfd p[1];
	unsigned int head, tail, mask = buf->meta.mask;

	for (;;) {
		p[0].fd = fd;
		p[0].events = POLLIN | POLLERR;
		p[0].revents = 0;

		if (poll(p, 1, -1) == -1) {
			perror("poll");
			break;
		}

		printf("ptrs h=%x t=%x m=%x\n",
		       buf->meta.head, buf->meta.tail, buf->meta.mask);

		while (head = __atomic_load_n(&buf->meta.head, __ATOMIC_ACQUIRE),
		       tail = buf->meta.tail,
		       tail != head
		       ) {
			n = &buf->slots[tail & mask];
			printf("NOTIFY[%08x-%08x] ty=%04x sy=%04x i=%08x\n",
			       head, tail, n->type, n->subtype, n->info);
			if ((n->info & WATCH_INFO_LENGTH) == 0)
				goto out;

			switch (n->type) {
			case WATCH_TYPE_META:
				if (n->subtype == WATCH_META_REMOVAL_NOTIFICATION)
					printf("REMOVAL of watchpoint %08x\n",
					       (n->info & WATCH_INFO_ID) >>
					       WATCH_INFO_ID__SHIFT);
				break;
			case WATCH_TYPE_KEY_NOTIFY:
				saw_key_change(n);
				break;
			case WATCH_TYPE_BLOCK_NOTIFY:
				saw_block_change(n);
				break;
			case WATCH_TYPE_USB_NOTIFY:
				saw_usb_event(n);
				break;
			}

			tail += (n->info & WATCH_INFO_LENGTH) >> WATCH_INFO_LENGTH__SHIFT;
			__atomic_store_n(&buf->meta.tail, tail, __ATOMIC_RELEASE);
		}
	}

out:
	return 0;
}

static struct watch_notification_filter filter = {
	.nr_filters	= 3,
	.__reserved	= 0,
	.filters = {
		[0]	= {
			.type			= WATCH_TYPE_KEY_NOTIFY,
			.subtype_filter[0]	= UINT_MAX,
		},
		[1]	= {
			.type			= WATCH_TYPE_BLOCK_NOTIFY,
			.subtype_filter[0]	= UINT_MAX,
		},
		[2]	= {
			.type			= WATCH_TYPE_USB_NOTIFY,
			.subtype_filter[0]	= UINT_MAX,
		},
	},
};

int main(int argc, char **argv)
{
	struct watch_queue_buffer *buf;
	size_t page_size;
	int fd;

	fd = open("/dev/watch_queue", O_RDWR);
	if (fd == -1) {
		perror("/dev/watch_queue");
		exit(1);
	}

	if (ioctl(fd, IOC_WATCH_QUEUE_SET_SIZE, BUF_SIZE) == -1) {
		perror("/dev/watch_queue(size)");
		exit(1);
	}

	if (ioctl(fd, IOC_WATCH_QUEUE_SET_FILTER, &filter) == -1) {
		perror("/dev/watch_queue(filter)");
		exit(1);
	}

	page_size = sysconf(_SC_PAGESIZE);
	buf = mmap(NULL, BUF_SIZE * page_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	if (keyctl_watch_key(KEY_SPEC_SESSION_KEYRING, fd, 0x01) == -1) {
		perror("keyctl");
		exit(1);
	}

	if (syscall(__NR_watch_devices, fd, 0x04, 0) == -1) {
		perror("watch_devices");
		exit(1);
	}

	return consumer(fd, buf);
}
