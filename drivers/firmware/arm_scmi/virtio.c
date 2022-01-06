// SPDX-License-Identifier: GPL-2.0
/*
 * Virtio Transport driver for Arm System Control and Management Interface
 * (SCMI).
 *
 * Copyright (C) 2020-2022 OpenSynergy.
 * Copyright (C) 2021-2022 ARM Ltd.
 */

/**
 * DOC: Theory of Operation
 *
 * The scmi-virtio transport implements a driver for the virtio SCMI device.
 *
 * There is one Tx channel (virtio cmdq, A2P channel) and at most one Rx
 * channel (virtio eventq, P2A channel). Each channel is implemented through a
 * virtqueue. Access to each virtqueue is protected by spinlocks.
 */

#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include <uapi/linux/virtio_ids.h>
#include <uapi/linux/virtio_scmi.h>

#include "common.h"

#define VIRTIO_SCMI_MAX_MSG_SIZE 128 /* Value may be increased. */
#define VIRTIO_SCMI_MAX_PDU_SIZE \
	(VIRTIO_SCMI_MAX_MSG_SIZE + SCMI_MSG_MAX_PROT_OVERHEAD)
#define DESCRIPTORS_PER_TX_MSG 2

/**
 * struct scmi_vio_channel - Transport channel information
 *
 * @vqueue: Associated virtqueue
 * @cinfo: SCMI Tx or Rx channel
 * @free_list: List of unused scmi_vio_msg, maintained for Tx channels only
 * @deferred_tx_work: Worker for TX deferred replies processing
 * @deferred_tx_wq: Workqueue for TX deferred replies
 * @pending_cmds_list: List of pre-fetched commands queueud for later processing
 * @is_rx: Whether channel is an Rx channel
 * @ready: Whether transport user is ready to hear about channel
 * @max_msg: Maximum number of pending messages for this channel.
 * @lock: Protects access to all members except ready.
 * @ready_lock: Protects access to ready. If required, it must be taken before
 *              lock.
 */
struct scmi_vio_channel {
	struct virtqueue *vqueue;
	struct scmi_chan_info *cinfo;
	struct list_head free_list;
	struct list_head pending_cmds_list;
	struct work_struct deferred_tx_work;
	struct workqueue_struct *deferred_tx_wq;
	bool is_rx;
	bool ready;
	unsigned int max_msg;
	/* lock to protect access to all members except ready. */
	spinlock_t lock;
	/* lock to rotects access to ready flag. */
	spinlock_t ready_lock;
};

/**
 * struct scmi_vio_msg - Transport PDU information
 *
 * @request: SDU used for commands
 * @input: SDU used for (delayed) responses and notifications
 * @list: List which scmi_vio_msg may be part of
 * @rx_len: Input SDU size in bytes, once input has been received
 * @poll_idx: Last used index registered for polling purposes if this message
 *	      transaction reply was configured for polling.
 *	      Note that since virtqueue used index is an unsigned 16-bit we can
 *	      use some out-of-scale values to signify particular conditions.
 * @poll_lock: Protect access to @poll_idx.
 */
struct scmi_vio_msg {
	struct scmi_msg_payld *request;
	struct scmi_msg_payld *input;
	struct list_head list;
	unsigned int rx_len;
#define VIO_MSG_NOT_POLLED	0xeeeeeeeeUL
#define VIO_MSG_POLL_DONE	0xffffffffUL
	unsigned int poll_idx;
	/* lock to protect access to poll_idx. */
	spinlock_t poll_lock;
};

/* Only one SCMI VirtIO device can possibly exist */
static struct virtio_device *scmi_vdev;

static bool scmi_vio_have_vq_rx(struct virtio_device *vdev)
{
	return virtio_has_feature(vdev, VIRTIO_SCMI_F_P2A_CHANNELS);
}

/* Expect to be called with vioch->lock acquired by the caller and IRQs off */
static int scmi_vio_feed_vq_rx(struct scmi_vio_channel *vioch,
			       struct scmi_vio_msg *msg,
			       struct device *dev)
{
	struct scatterlist sg_in;
	int rc;

	sg_init_one(&sg_in, msg->input, VIRTIO_SCMI_MAX_PDU_SIZE);

	rc = virtqueue_add_inbuf(vioch->vqueue, &sg_in, 1, msg, GFP_ATOMIC);
	if (rc)
		dev_err(dev, "failed to add to RX virtqueue (%d)\n", rc);
	else
		virtqueue_kick(vioch->vqueue);

	return rc;
}

/* Expect to be called with vioch->lock acquired by the caller and IRQs off */
static inline void scmi_vio_feed_vq_tx(struct scmi_vio_channel *vioch,
				       struct scmi_vio_msg *msg)
{
	spin_lock(&msg->poll_lock);
	msg->poll_idx = VIO_MSG_NOT_POLLED;
	spin_unlock(&msg->poll_lock);

	list_add(&msg->list, &vioch->free_list);
}

static void scmi_finalize_message(struct scmi_vio_channel *vioch,
				  struct scmi_vio_msg *msg)
{
	if (vioch->is_rx)
		scmi_vio_feed_vq_rx(vioch, msg, vioch->cinfo->dev);
	else
		scmi_vio_feed_vq_tx(vioch, msg);
}

static void scmi_vio_complete_cb(struct virtqueue *vqueue)
{
	unsigned long ready_flags;
	unsigned int length;
	struct scmi_vio_channel *vioch;
	struct scmi_vio_msg *msg;
	bool cb_enabled = true;

	if (WARN_ON_ONCE(!vqueue->vdev->priv))
		return;
	vioch = &((struct scmi_vio_channel *)vqueue->vdev->priv)[vqueue->index];

	for (;;) {
		spin_lock_irqsave(&vioch->ready_lock, ready_flags);

		if (!vioch->ready) {
			if (!cb_enabled)
				(void)virtqueue_enable_cb(vqueue);
			goto unlock_ready_out;
		}

		/* IRQs already disabled here no need to irqsave */
		spin_lock(&vioch->lock);
		if (cb_enabled) {
			virtqueue_disable_cb(vqueue);
			cb_enabled = false;
		}

		msg = virtqueue_get_buf(vqueue, &length);
		if (!msg) {
			if (virtqueue_enable_cb(vqueue))
				goto unlock_out;
			cb_enabled = true;
		}
		spin_unlock(&vioch->lock);

		if (msg) {
			msg->rx_len = length;
			scmi_rx_callback(vioch->cinfo,
					 msg_read_header(msg->input), msg);

			spin_lock(&vioch->lock);
			scmi_finalize_message(vioch, msg);
			spin_unlock(&vioch->lock);
		}

		/*
		 * Release ready_lock and re-enable IRQs between loop iterations
		 * to allow virtio_chan_free() to possibly kick in and set the
		 * flag vioch->ready to false even in between processing of
		 * messages, so as to force outstanding messages to be ignored
		 * when system is shutting down.
		 */
		spin_unlock_irqrestore(&vioch->ready_lock, ready_flags);
	}

unlock_out:
	spin_unlock(&vioch->lock);
unlock_ready_out:
	spin_unlock_irqrestore(&vioch->ready_lock, ready_flags);
}

static void scmi_vio_deferred_tx_worker(struct work_struct *work)
{
	unsigned long flags;
	struct scmi_vio_channel *vioch;
	struct scmi_vio_msg *msg, *tmp;

	vioch = container_of(work, struct scmi_vio_channel, deferred_tx_work);

	/* Process pre-fetched messages */
	spin_lock_irqsave(&vioch->lock, flags);

	/* Scan the list of possibly pre-fetched messages during polling. */
	list_for_each_entry_safe(msg, tmp, &vioch->pending_cmds_list, list) {
		list_del(&msg->list);

		scmi_rx_callback(vioch->cinfo,
				 msg_read_header(msg->input), msg);

		/* Free the processed message once done */
		scmi_vio_feed_vq_tx(vioch, msg);
	}

	spin_unlock_irqrestore(&vioch->lock, flags);

	/* Process possibly still pending messages */
	scmi_vio_complete_cb(vioch->vqueue);
}

static const char *const scmi_vio_vqueue_names[] = { "tx", "rx" };

static vq_callback_t *scmi_vio_complete_callbacks[] = {
	scmi_vio_complete_cb,
	scmi_vio_complete_cb
};

static unsigned int virtio_get_max_msg(struct scmi_chan_info *base_cinfo)
{
	struct scmi_vio_channel *vioch = base_cinfo->transport_info;

	return vioch->max_msg;
}

static int virtio_link_supplier(struct device *dev)
{
	if (!scmi_vdev) {
		dev_notice(dev,
			   "Deferring probe after not finding a bound scmi-virtio device\n");
		return -EPROBE_DEFER;
	}

	if (!device_link_add(dev, &scmi_vdev->dev,
			     DL_FLAG_AUTOREMOVE_CONSUMER)) {
		dev_err(dev, "Adding link to supplier virtio device failed\n");
		return -ECANCELED;
	}

	return 0;
}

static bool virtio_chan_available(struct device *dev, int idx)
{
	struct scmi_vio_channel *channels, *vioch = NULL;

	if (WARN_ON_ONCE(!scmi_vdev))
		return false;

	channels = (struct scmi_vio_channel *)scmi_vdev->priv;

	switch (idx) {
	case VIRTIO_SCMI_VQ_TX:
		vioch = &channels[VIRTIO_SCMI_VQ_TX];
		break;
	case VIRTIO_SCMI_VQ_RX:
		if (scmi_vio_have_vq_rx(scmi_vdev))
			vioch = &channels[VIRTIO_SCMI_VQ_RX];
		break;
	default:
		return false;
	}

	return vioch && !vioch->cinfo;
}

static int virtio_chan_setup(struct scmi_chan_info *cinfo, struct device *dev,
			     bool tx)
{
	unsigned long flags;
	struct scmi_vio_channel *vioch;
	int index = tx ? VIRTIO_SCMI_VQ_TX : VIRTIO_SCMI_VQ_RX;
	int i;

	if (!scmi_vdev)
		return -EPROBE_DEFER;

	vioch = &((struct scmi_vio_channel *)scmi_vdev->priv)[index];

	/* Setup a deferred worker for polling. */
	if (tx && !vioch->deferred_tx_wq) {
		vioch->deferred_tx_wq =
			alloc_workqueue(dev_name(&scmi_vdev->dev),
					WQ_UNBOUND | WQ_FREEZABLE | WQ_SYSFS,
					0);
		if (!vioch->deferred_tx_wq)
			return -ENOMEM;

		INIT_WORK(&vioch->deferred_tx_work,
			  scmi_vio_deferred_tx_worker);
	}

	for (i = 0; i < vioch->max_msg; i++) {
		struct scmi_vio_msg *msg;

		msg = devm_kzalloc(cinfo->dev, sizeof(*msg), GFP_KERNEL);
		if (!msg)
			return -ENOMEM;

		if (tx) {
			msg->request = devm_kzalloc(cinfo->dev,
						    VIRTIO_SCMI_MAX_PDU_SIZE,
						    GFP_KERNEL);
			if (!msg->request)
				return -ENOMEM;
			spin_lock_init(&msg->poll_lock);
		}

		msg->input = devm_kzalloc(cinfo->dev, VIRTIO_SCMI_MAX_PDU_SIZE,
					  GFP_KERNEL);
		if (!msg->input)
			return -ENOMEM;

		spin_lock_irqsave(&vioch->lock, flags);
		if (tx)
			scmi_vio_feed_vq_tx(vioch, msg);
		else
			scmi_vio_feed_vq_rx(vioch, msg, cinfo->dev);
		spin_unlock_irqrestore(&vioch->lock, flags);
	}

	spin_lock_irqsave(&vioch->lock, flags);
	cinfo->transport_info = vioch;
	/* Indirectly setting channel not available any more */
	vioch->cinfo = cinfo;
	spin_unlock_irqrestore(&vioch->lock, flags);

	spin_lock_irqsave(&vioch->ready_lock, flags);
	vioch->ready = true;
	spin_unlock_irqrestore(&vioch->ready_lock, flags);

	return 0;
}

static int virtio_chan_free(int id, void *p, void *data)
{
	unsigned long flags;
	struct scmi_chan_info *cinfo = p;
	struct scmi_vio_channel *vioch = cinfo->transport_info;
	void *deferred_wq = NULL;

	spin_lock_irqsave(&vioch->ready_lock, flags);
	vioch->ready = false;
	spin_unlock_irqrestore(&vioch->ready_lock, flags);

	spin_lock_irqsave(&vioch->lock, flags);
	if (!vioch->is_rx && vioch->deferred_tx_wq) {
		deferred_wq = vioch->deferred_tx_wq;
		vioch->deferred_tx_wq = NULL;
	}
	spin_unlock_irqrestore(&vioch->lock, flags);

	if (deferred_wq)
		destroy_workqueue(deferred_wq);

	scmi_free_channel(cinfo, data, id);

	spin_lock_irqsave(&vioch->lock, flags);
	vioch->cinfo = NULL;
	spin_unlock_irqrestore(&vioch->lock, flags);

	return 0;
}

static int virtio_send_message(struct scmi_chan_info *cinfo,
			       struct scmi_xfer *xfer)
{
	struct scmi_vio_channel *vioch = cinfo->transport_info;
	struct scatterlist sg_out;
	struct scatterlist sg_in;
	struct scatterlist *sgs[DESCRIPTORS_PER_TX_MSG] = { &sg_out, &sg_in };
	unsigned long flags;
	int rc;
	struct scmi_vio_msg *msg;

	spin_lock_irqsave(&vioch->lock, flags);

	if (list_empty(&vioch->free_list)) {
		spin_unlock_irqrestore(&vioch->lock, flags);
		return -EBUSY;
	}

	msg = list_first_entry(&vioch->free_list, typeof(*msg), list);
	/* Re-init element so we can discern anytime if it is still in-flight */
	list_del_init(&msg->list);

	msg_tx_prepare(msg->request, xfer);

	sg_init_one(&sg_out, msg->request, msg_command_size(xfer));
	sg_init_one(&sg_in, msg->input, msg_response_size(xfer));

	rc = virtqueue_add_sgs(vioch->vqueue, sgs, 1, 1, msg, GFP_ATOMIC);
	if (rc) {
		list_add(&msg->list, &vioch->free_list);
		dev_err(vioch->cinfo->dev,
			"failed to add to TX virtqueue (%d)\n", rc);
	} else {
		/*
		 * If polling was requested for this transaction:
		 *  - retrieve last used index (will be used as polling reference)
		 *  - bind the polled message to the xfer via .priv
		 */
		if (xfer->hdr.poll_completion) {
			spin_lock(&msg->poll_lock);
			msg->poll_idx =
				virtqueue_enable_cb_prepare(vioch->vqueue);
			spin_unlock(&msg->poll_lock);
			/* Ensure initialized msg is visibly bound to xfer */
			smp_store_mb(xfer->priv, msg);
		}
		virtqueue_kick(vioch->vqueue);
	}

	spin_unlock_irqrestore(&vioch->lock, flags);

	return rc;
}

static void virtio_fetch_response(struct scmi_chan_info *cinfo,
				  struct scmi_xfer *xfer)
{
	struct scmi_vio_msg *msg = xfer->priv;

	if (msg)
		msg_fetch_response(msg->input, msg->rx_len, xfer);
}

static void virtio_fetch_notification(struct scmi_chan_info *cinfo,
				      size_t max_len, struct scmi_xfer *xfer)
{
	struct scmi_vio_msg *msg = xfer->priv;

	if (msg)
		msg_fetch_notification(msg->input, msg->rx_len, max_len, xfer);
}

/**
 * virtio_mark_txdone  - Mark transmission done
 *
 * Free only successfully completed polling transfer messages.
 *
 * Note that in the SCMI VirtIO transport we never explicitly release timed-out
 * messages by forcibly re-adding them to the free-list, even on timeout, inside
 * the TX code path; we instead let IRQ/RX callbacks eventually clean up such
 * messages once, finally, a late reply is received and discarded (if ever).
 *
 * This approach was deemed preferable since those pending timed-out buffers are
 * still effectively owned by the SCMI platform VirtIO device even after timeout
 * expiration: forcibly freeing and reusing them before they had been returned
 * explicitly by the SCMI platform could lead to subtle bugs due to message
 * corruption.
 * An SCMI platform VirtIO device which never returns message buffers is
 * anyway broken and it will quickly lead to exhaustion of available messages.
 *
 * For this same reason, here, we take care to free only the successfully
 * completed polled messages, since they won't be freed elsewhere; late replies
 * to timed-out polled messages would be anyway freed by RX callbacks instead.
 *
 * @cinfo: SCMI channel info
 * @ret: Transmission return code
 * @xfer: Transfer descriptor
 */
static void virtio_mark_txdone(struct scmi_chan_info *cinfo, int ret,
			       struct scmi_xfer *xfer)
{
	unsigned long flags;
	struct scmi_vio_channel *vioch = cinfo->transport_info;
	struct scmi_vio_msg *msg = xfer->priv;

	if (!msg)
		return;

	/* Ensure msg is unbound from xfer before pushing onto the free list  */
	smp_store_mb(xfer->priv, NULL);

	/* Is a successfully completed polled message still to be finalized ? */
	spin_lock_irqsave(&vioch->lock, flags);
	if (!ret && xfer->hdr.poll_completion && list_empty(&msg->list))
		scmi_vio_feed_vq_tx(vioch, msg);
	spin_unlock_irqrestore(&vioch->lock, flags);
}

/**
 * virtio_poll_done  - Provide polling support for VirtIO transport
 *
 * @cinfo: SCMI channel info
 * @xfer: Reference to the transfer being poll for.
 *
 * VirtIO core provides a polling mechanism based only on last used indexes:
 * this means that it is possible to poll the virtqueues waiting for something
 * new to arrive from the host side but the only way to check if the freshly
 * arrived buffer was what we were waiting for is to compare the newly arrived
 * message descriptors with the one we are polling on.
 *
 * As a consequence it can happen to dequeue something different from the buffer
 * we were poll-waiting for: if that is the case such early fetched buffers are
 * then added to a the @pending_cmds_list list for later processing by a
 * dedicated deferred worker.
 *
 * So, basically, once something new is spotted we proceed to de-queue all the
 * freshly received used buffers until we found the one we were polling on, or,
 * we have 'seemingly' emptied the virtqueue; if some buffers are still pending
 * in the vqueue at the end of the polling loop (possible due to inherent races
 * in virtqueues handling mechanisms), we similarly kick the deferred worker
 * and let it process those, to avoid indefinitely looping in the .poll_done
 * helper.
 *
 * Note that we do NOT suppress notification with VIRTQ_USED_F_NO_NOTIFY even
 * when polling since such flag is per-virtqueues and we do not want to
 * suppress notifications as a whole: so, if the message we are polling for is
 * delivered via usual IRQs callbacks, on another core which are IRQs-on, it
 * will be handled as such by scmi_rx_callback() and the polling loop in the
 * SCMI Core TX path will be transparently terminated anyway.
 *
 * Return: True once polling has successfully completed.
 */
static bool virtio_poll_done(struct scmi_chan_info *cinfo,
			     struct scmi_xfer *xfer)
{
	bool pending, ret = false;
	unsigned int length, any_prefetched = 0;
	unsigned long flags;
	struct scmi_vio_msg *next_msg, *msg = xfer->priv;
	struct scmi_vio_channel *vioch = cinfo->transport_info;

	if (!msg)
		return true;

	spin_lock_irqsave(&msg->poll_lock, flags);
	/* Processed already by other polling loop on another CPU ? */
	if (msg->poll_idx == VIO_MSG_POLL_DONE) {
		spin_unlock_irqrestore(&msg->poll_lock, flags);
		return true;
	}

	/* Has cmdq index moved at all ? */
	pending = virtqueue_poll(vioch->vqueue, msg->poll_idx);
	spin_unlock_irqrestore(&msg->poll_lock, flags);
	if (!pending)
		return false;

	spin_lock_irqsave(&vioch->lock, flags);
	virtqueue_disable_cb(vioch->vqueue);

	/*
	 * If something arrived we cannot be sure, without dequeueing, if it
	 * was the reply to the xfer we are polling for, or, to other, even
	 * possibly non-polling, pending xfers: process all new messages
	 * till the polled-for message is found OR the vqueue is empty.
	 */
	while ((next_msg = virtqueue_get_buf(vioch->vqueue, &length))) {
		next_msg->rx_len = length;
		/* Is the message we were polling for ? */
		if (next_msg == msg) {
			ret = true;
			break;
		}

		spin_lock(&next_msg->poll_lock);
		if (next_msg->poll_idx == VIO_MSG_NOT_POLLED) {
			any_prefetched++;
			list_add_tail(&next_msg->list,
				      &vioch->pending_cmds_list);
		} else {
			next_msg->poll_idx = VIO_MSG_POLL_DONE;
		}
		spin_unlock(&next_msg->poll_lock);
	}

	/*
	 * When the polling loop has successfully terminated if something
	 * else was queued in the meantime, it will be served by a deferred
	 * worker OR by the normal IRQ/callback OR by other poll loops.
	 *
	 * If we are still looking for the polled reply, the polling index has
	 * to be updated to the current vqueue last used index.
	 */
	if (ret) {
		pending = !virtqueue_enable_cb(vioch->vqueue);
	} else {
		spin_lock(&msg->poll_lock);
		msg->poll_idx = virtqueue_enable_cb_prepare(vioch->vqueue);
		pending = virtqueue_poll(vioch->vqueue, msg->poll_idx);
		spin_unlock(&msg->poll_lock);
	}

	if (vioch->deferred_tx_wq && (any_prefetched || pending))
		queue_work(vioch->deferred_tx_wq, &vioch->deferred_tx_work);

	spin_unlock_irqrestore(&vioch->lock, flags);

	return ret;
}

static const struct scmi_transport_ops scmi_virtio_ops = {
	.link_supplier = virtio_link_supplier,
	.chan_available = virtio_chan_available,
	.chan_setup = virtio_chan_setup,
	.chan_free = virtio_chan_free,
	.get_max_msg = virtio_get_max_msg,
	.send_message = virtio_send_message,
	.fetch_response = virtio_fetch_response,
	.fetch_notification = virtio_fetch_notification,
	.mark_txdone = virtio_mark_txdone,
	.poll_done = virtio_poll_done,
};

static int scmi_vio_probe(struct virtio_device *vdev)
{
	struct device *dev = &vdev->dev;
	struct scmi_vio_channel *channels;
	bool have_vq_rx;
	int vq_cnt;
	int i;
	int ret;
	struct virtqueue *vqs[VIRTIO_SCMI_VQ_MAX_CNT];

	/* Only one SCMI VirtiO device allowed */
	if (scmi_vdev) {
		dev_err(dev,
			"One SCMI Virtio device was already initialized: only one allowed.\n");
		return -EBUSY;
	}

	have_vq_rx = scmi_vio_have_vq_rx(vdev);
	vq_cnt = have_vq_rx ? VIRTIO_SCMI_VQ_MAX_CNT : 1;

	channels = devm_kcalloc(dev, vq_cnt, sizeof(*channels), GFP_KERNEL);
	if (!channels)
		return -ENOMEM;

	if (have_vq_rx)
		channels[VIRTIO_SCMI_VQ_RX].is_rx = true;

	ret = virtio_find_vqs(vdev, vq_cnt, vqs, scmi_vio_complete_callbacks,
			      scmi_vio_vqueue_names, NULL);
	if (ret) {
		dev_err(dev, "Failed to get %d virtqueue(s)\n", vq_cnt);
		return ret;
	}

	for (i = 0; i < vq_cnt; i++) {
		unsigned int sz;

		spin_lock_init(&channels[i].lock);
		spin_lock_init(&channels[i].ready_lock);
		INIT_LIST_HEAD(&channels[i].free_list);
		INIT_LIST_HEAD(&channels[i].pending_cmds_list);
		channels[i].vqueue = vqs[i];

		sz = virtqueue_get_vring_size(channels[i].vqueue);
		/* Tx messages need multiple descriptors. */
		if (!channels[i].is_rx)
			sz /= DESCRIPTORS_PER_TX_MSG;

		if (sz > MSG_TOKEN_MAX) {
			dev_info(dev,
				 "%s virtqueue could hold %d messages. Only %ld allowed to be pending.\n",
				 channels[i].is_rx ? "rx" : "tx",
				 sz, MSG_TOKEN_MAX);
			sz = MSG_TOKEN_MAX;
		}
		channels[i].max_msg = sz;
	}

	vdev->priv = channels;
	/* Ensure initialized scmi_vdev is visible */
	smp_store_mb(scmi_vdev, vdev);

	return 0;
}

static void scmi_vio_remove(struct virtio_device *vdev)
{
	/*
	 * Once we get here, virtio_chan_free() will have already been called by
	 * the SCMI core for any existing channel and, as a consequence, all the
	 * virtio channels will have been already marked NOT ready, causing any
	 * outstanding message on any vqueue to be ignored by complete_cb: now
	 * we can just stop processing buffers and destroy the vqueues.
	 */
	virtio_reset_device(vdev);
	vdev->config->del_vqs(vdev);
	/* Ensure scmi_vdev is visible as NULL */
	smp_store_mb(scmi_vdev, NULL);
}

static int scmi_vio_validate(struct virtio_device *vdev)
{
#ifdef CONFIG_ARM_SCMI_TRANSPORT_VIRTIO_VERSION1_COMPLIANCE
	if (!virtio_has_feature(vdev, VIRTIO_F_VERSION_1)) {
		dev_err(&vdev->dev,
			"device does not comply with spec version 1.x\n");
		return -EINVAL;
	}
#endif
	return 0;
}

static unsigned int features[] = {
	VIRTIO_SCMI_F_P2A_CHANNELS,
};

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_SCMI, VIRTIO_DEV_ANY_ID },
	{ 0 }
};

static struct virtio_driver virtio_scmi_driver = {
	.driver.name = "scmi-virtio",
	.driver.owner = THIS_MODULE,
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.id_table = id_table,
	.probe = scmi_vio_probe,
	.remove = scmi_vio_remove,
	.validate = scmi_vio_validate,
};

static int __init virtio_scmi_init(void)
{
	return register_virtio_driver(&virtio_scmi_driver);
}

static void virtio_scmi_exit(void)
{
	unregister_virtio_driver(&virtio_scmi_driver);
}

const struct scmi_desc scmi_virtio_desc = {
	.transport_init = virtio_scmi_init,
	.transport_exit = virtio_scmi_exit,
	.ops = &scmi_virtio_ops,
	.max_rx_timeout_ms = 60000, /* for non-realtime virtio devices */
	.max_msg = 0, /* overridden by virtio_get_max_msg() */
	.max_msg_size = VIRTIO_SCMI_MAX_MSG_SIZE,
	.atomic_enabled = IS_ENABLED(CONFIG_ARM_SCMI_TRANSPORT_VIRTIO_ATOMIC_ENABLE),
};
