// SPDX-License-Identifier: GPL-2.0
/*
 * Event notifications.
 *
 * Copyright (C) 2019 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/device.h>
#include <linux/watch_queue.h>
#include <linux/syscalls.h>
#include <linux/init_task.h>
#include <linux/security.h>

/*
 * Global queue for watching for device layer events.
 */
static struct watch_list device_watchers = {
	.watchers	= HLIST_HEAD_INIT,
	.lock		= __SPIN_LOCK_UNLOCKED(&device_watchers.lock),
};

static DEFINE_SPINLOCK(device_watchers_lock);

/**
 * post_device_notification - Post notification of a device event
 * @n - The notification to post
 * @id - The device ID
 *
 * Note that there's only a global queue to which all events are posted.  Might
 * want to provide per-dev queues also.
 */
void post_device_notification(struct watch_notification *n, u64 id)
{
	post_watch_notification(&device_watchers, n, &init_cred, id);
}
EXPORT_SYMBOL(post_device_notification);

/**
 * sys_watch_devices - Watch for device events.
 * @watch_fd: The watch queue to send notifications to.
 * @watch_id: The watch ID to be placed in the notification (-1 to remove watch)
 * @flags: Flags (reserved for future)
 */
SYSCALL_DEFINE3(watch_devices, int, watch_fd, int, watch_id, unsigned int, flags)
{
	struct watch_queue *wqueue;
	struct watch *watch = NULL;
	long ret = -ENOMEM;

	if (watch_id < -1 || watch_id > 0xff || flags)
		return -EINVAL;

	wqueue = get_watch_queue(watch_fd);
	if (IS_ERR(wqueue)) {
		ret = PTR_ERR(wqueue);
		goto err;
	}

	if (watch_id >= 0) {
		watch = kzalloc(sizeof(*watch), GFP_KERNEL);
		if (!watch)
			goto err_wqueue;

		init_watch(watch, wqueue);
		watch->info_id = (u32)watch_id << WATCH_INFO_ID__SHIFT;

		ret = security_watch_devices();
		if (ret < 0)
			goto err_watch;

		spin_lock(&device_watchers_lock);
		ret = add_watch_to_object(watch, &device_watchers);
		spin_unlock(&device_watchers_lock);
		if (ret == 0)
			watch = NULL;
	} else {
		spin_lock(&device_watchers_lock);
		ret = remove_watch_from_object(&device_watchers, wqueue, 0,
					       false);
		spin_unlock(&device_watchers_lock);
	}

err_watch:
	kfree(watch);
err_wqueue:
	put_watch_queue(wqueue);
err:
	return ret;
}
