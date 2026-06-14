// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * HID driver for ZOTAC Gaming Zone Controller - RGB LED control
 *
 * Copyright (c) 2025 Luke D. Jones <luke@ljones.dev>
 */

#include "linux/input-event-codes.h"
#include <linux/device.h>
#include <linux/hid.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/atomic.h>

#include "zotac-zone.h"

#define ZOTAC_GAMEPAD_REPORT_SIZE 64
#define ZOTAC_GAMEPAD_URB_INTERVAL 1

static void zotac_gamepad_urb_irq(struct urb *urb)
{
	struct zotac_device *zotac = urb->context;
	struct zotac_gamepad *gamepad;
	unsigned char *data = urb->transfer_buffer;
	int retval, status = urb->status;

	if (!zotac || !zotac->gamepad)
		return;

	gamepad = zotac->gamepad;

	/* Use memory barrier before reading disconnect flag to ensure latest value */
	smp_rmb();
	if (READ_ONCE(gamepad->disconnect)) {
		return;
	}

	switch (status) {
	case 0:
		break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		return;
	default:
		goto exit;
	}

	zotac_process_gamepad_report(zotac, data, urb->actual_length);

exit:
	/* Use memory barrier before reading disconnect flag to ensure latest value */
	smp_rmb();
	if (!READ_ONCE(gamepad->disconnect)) {
		retval = usb_submit_urb(urb, GFP_ATOMIC);
		if (retval)
			dev_err(&urb->dev->dev,
				"usb_submit_urb failed with result %d\n",
				retval);
	}
}

static void zotac_gamepad_ff_urb_complete(struct urb *urb)
{
	struct zotac_device *zotac = urb->context;
	struct zotac_gamepad *gamepad;
	int i;

	if (!zotac || !zotac->gamepad)
		return;

	gamepad = zotac->gamepad;

	if (urb->status)
		dev_dbg(&urb->dev->dev, "FF urb status %d\n", urb->status);

	for (i = 0; i < ZOTAC_NUM_FF_URBS; i++) {
		if (gamepad->ff_urbs[i] == urb) {
			gamepad->ff_urbs[i]->transfer_flags &=
				~URB_NO_TRANSFER_DMA_MAP;
			atomic_set(&gamepad->ff_active[i], 0);
			break;
		}
	}
}

static int zotac_gamepad_play_effect(struct input_dev *dev, void *data,
				     struct ff_effect *effect)
{
	struct zotac_device *zotac = input_get_drvdata(dev);
	struct zotac_gamepad *gamepad = zotac->gamepad;
	int retval = -EBUSY, i;
	u16 strong, weak;

	if (!gamepad || READ_ONCE(gamepad->disconnect))
		return -ENODEV;
	if (effect->type != FF_RUMBLE)
		return 0;

	strong = effect->u.rumble.strong_magnitude;
	weak = effect->u.rumble.weak_magnitude;

	for (i = 0; i < ZOTAC_NUM_FF_URBS; i++) {
		if (atomic_read(&gamepad->ff_active[i]) == 0) {
			gamepad->ff_data[i][0] = ZOTAC_FF_REPORT_ID;
			gamepad->ff_data[i][1] = 0x08;
			gamepad->ff_data[i][2] = 0x00;
			gamepad->ff_data[i][3] = strong / 256;
			gamepad->ff_data[i][4] = weak / 256;
			gamepad->ff_data[i][5] = 0x00;
			gamepad->ff_data[i][6] = 0x00;
			gamepad->ff_data[i][7] = 0x00;

			/* Use atomic compare-and-swap to claim this URB */
			if (atomic_cmpxchg(&gamepad->ff_active[i], 0, 1) == 0) {
				retval = usb_submit_urb(gamepad->ff_urbs[i],
							GFP_ATOMIC);
				if (retval) {
					dev_err(&zotac->hdev->dev,
						"usb_submit_urb(ff) failed: %d\n",
						retval);
					atomic_set(&gamepad->ff_active[i], 0);
				}
				break;
			}
		}
	}
	return retval;
}

void zotac_process_gamepad_report(struct zotac_device *zotac, u8 *data,
				  int size)
{
	struct zotac_gamepad *gamepad = zotac->gamepad;
	struct input_dev *input_dev;

	if (!gamepad || size < 14 || !(input_dev = gamepad->dev) ||
	    data[0] != 0x00)
		return;

	input_report_abs(input_dev, ABS_HAT0X,
			 !!(data[2] & 0x08) - !!(data[2] & 0x04));
	input_report_abs(input_dev, ABS_HAT0Y,
			 !!(data[2] & 0x02) - !!(data[2] & 0x01));
	input_report_key(input_dev, BTN_START, data[2] & BIT(4));
	input_report_key(input_dev, BTN_SELECT, data[2] & BIT(5));
	input_report_key(input_dev, BTN_THUMBL, data[2] & BIT(6));
	input_report_key(input_dev, BTN_THUMBR, data[2] & BIT(7));
	input_report_key(input_dev, BTN_A, data[3] & BIT(4));
	input_report_key(input_dev, BTN_B, data[3] & BIT(5));
	input_report_key(input_dev, BTN_X, data[3] & BIT(6));
	input_report_key(input_dev, BTN_Y, data[3] & BIT(7));
	input_report_key(input_dev, BTN_TL, data[3] & BIT(0));
	input_report_key(input_dev, BTN_TR, data[3] & BIT(1));
	input_report_key(input_dev, BTN_MODE, data[3] & BIT(2));
	input_report_abs(input_dev, ABS_X,
			 (__s16)le16_to_cpup((__le16 *)(data + 6)));
	input_report_abs(input_dev, ABS_Y,
			 ~(__s16)le16_to_cpup((__le16 *)(data + 8)));
	input_report_abs(input_dev, ABS_RX,
			 (__s16)le16_to_cpup((__le16 *)(data + 10)));
	input_report_abs(input_dev, ABS_RY,
			 ~(__s16)le16_to_cpup((__le16 *)(data + 12)));
	input_report_abs(input_dev, ABS_Z, data[4]);
	input_report_abs(input_dev, ABS_RZ, data[5]);
	input_sync(input_dev);
}

static void zotac_button_work_func(struct work_struct *work)
{
	struct zotac_gamepad *gamepad = container_of(
		to_delayed_work(work), struct zotac_gamepad, button_work);
	unsigned int button2, button;
	bool qam_update;

	if (READ_ONCE(gamepad->disconnect) || !gamepad->dev)
		return;

	/* Access these values atomically without a spinlock */
	/* We copy them locally to avoid races */
	button = READ_ONCE(gamepad->button_to_press);
	button2 = READ_ONCE(gamepad->button_to_press2);
	qam_update = READ_ONCE(gamepad->update_qam);

	/* Update the state variables */
	WRITE_ONCE(gamepad->update_qam, false);
	WRITE_ONCE(gamepad->button_to_press, 0);
	WRITE_ONCE(gamepad->button_to_press2, 0);

	/* Memory barrier to ensure these writes complete before proceeding */
	smp_wmb();

	if (qam_update) {
		input_report_key(gamepad->dev, button, 1);
		input_sync(gamepad->dev);
		msleep(150);
		input_report_key(gamepad->dev, button2, 1);
		input_sync(gamepad->dev);
		input_report_key(gamepad->dev, button2, 0);
		input_sync(gamepad->dev);
		input_report_key(gamepad->dev, button, 0);
		input_sync(gamepad->dev);
	} else if (button) {
		input_report_key(gamepad->dev, button, 1);
		input_sync(gamepad->dev);
		input_report_key(gamepad->dev, button, 0);
		input_sync(gamepad->dev);
	}

	/* Release the button press lock so others can schedule button presses */
	atomic_set(&gamepad->button_press_in_progress, 0);
}

void zotac_gamepad_send_button(struct zotac_device *zotac, int buttons[],
			       int num_buttons)
{
	struct zotac_gamepad *gamepad;

	if (!zotac || !zotac->gamepad || !zotac->gamepad->dev ||
	    READ_ONCE(zotac->gamepad->disconnect))
		return;

	gamepad = zotac->gamepad;

	/* Try to atomically take the button press lock */
	if (atomic_cmpxchg(&gamepad->button_press_in_progress, 0, 1) == 0) {
		/* We got the lock, update button values */

		/* Reset button state first */
		WRITE_ONCE(gamepad->button_to_press, 0);
		WRITE_ONCE(gamepad->button_to_press2, 0);
		WRITE_ONCE(gamepad->update_qam, false);

		/* Set new button values */
		if (num_buttons == 1) {
			WRITE_ONCE(gamepad->button_to_press, buttons[0]);
		} else if (num_buttons == 2) {
			WRITE_ONCE(gamepad->update_qam, true);
			WRITE_ONCE(gamepad->button_to_press, buttons[0]);
			WRITE_ONCE(gamepad->button_to_press2, buttons[1]);
		} else {
			/* No buttons to press, release the lock */
			atomic_set(&gamepad->button_press_in_progress, 0);
			return;
		}

		/* Memory barrier to ensure writes complete before scheduling work */
		smp_wmb();

		/* Schedule the work */
		schedule_delayed_work(&gamepad->button_work,
				      msecs_to_jiffies(5));
	}
}

static void zotac_find_endpoints(struct usb_interface *intf,
				 struct usb_endpoint_descriptor **ep_in,
				 struct usb_endpoint_descriptor **ep_out)
{
	struct usb_host_interface *host_interface = intf->cur_altsetting;
	int i;

	*ep_in = *ep_out = NULL;
	for (i = 0; i < host_interface->desc.bNumEndpoints; i++) {
		struct usb_endpoint_descriptor *ep =
			&host_interface->endpoint[i].desc;
		if (usb_endpoint_is_int_in(ep))
			*ep_in = ep;
		else if (usb_endpoint_is_int_out(ep))
			*ep_out = ep;
	}
}

int zotac_init_gamepad(struct zotac_device *zotac, struct usb_interface *intf)
{
	struct usb_endpoint_descriptor *ep_in = NULL, *ep_out = NULL;
	struct usb_device *udev = interface_to_usbdev(intf);
	struct hid_device *hdev = zotac->hdev;
	int pipe, maxp, interval, ret = 0, i;

	struct usb_interface *gamepad_intf;
	struct zotac_gamepad *gamepad;
	struct input_dev *input_dev;

	if (!(gamepad = kzalloc(sizeof(*gamepad), GFP_KERNEL)))
		return -ENOMEM;

	WRITE_ONCE(gamepad->disconnect, false);
	gamepad->zotac = zotac;
	zotac->gamepad = gamepad;
	zotac->udev = udev;

	if (!(gamepad_intf = usb_ifnum_to_if(udev, ZOTAC_GAMEPAD_INTERFACE))) {
		ret = -ENODEV;
		goto err_free_gamepad;
	}

	zotac_find_endpoints(gamepad_intf, &ep_in, &ep_out);
	if (!ep_in) {
		ret = -ENODEV;
		goto err_free_gamepad;
	}

	gamepad->qam_mode = QAM_MODE_STEAM;
	gamepad->ep_in = ep_in;
	gamepad->ep_out = ep_out;

	if (!(input_dev = input_allocate_device())) {
		ret = -ENOMEM;
		goto err_free_gamepad;
	}

	gamepad->dev = input_dev;
	zotac_init_input_device(input_dev, hdev, "ZOTAC Gaming Zone Gamepad");
	input_set_drvdata(input_dev, zotac);

	input_set_abs_params(input_dev, ABS_X, -32768, 32767, 16, 128);
	input_set_abs_params(input_dev, ABS_Y, -32768, 32767, 16, 128);
	input_set_abs_params(input_dev, ABS_RX, -32768, 32767, 16, 128);
	input_set_abs_params(input_dev, ABS_RY, -32768, 32767, 16, 128);
	input_set_abs_params(input_dev, ABS_Z, 0, 255, 0, 0);
	input_set_abs_params(input_dev, ABS_RZ, 0, 255, 0, 0);
	input_set_abs_params(input_dev, ABS_HAT0X, -1, 1, 0, 0);
	input_set_abs_params(input_dev, ABS_HAT0Y, -1, 1, 0, 0);

	input_set_capability(input_dev, EV_KEY, BTN_A);
	input_set_capability(input_dev, EV_KEY, BTN_B);
	input_set_capability(input_dev, EV_KEY, BTN_X);
	input_set_capability(input_dev, EV_KEY, BTN_Y);
	input_set_capability(input_dev, EV_KEY, BTN_TL);
	input_set_capability(input_dev, EV_KEY, BTN_TR);
	input_set_capability(input_dev, EV_KEY, BTN_MODE);
	input_set_capability(input_dev, EV_KEY, BTN_START);
	input_set_capability(input_dev, EV_KEY, BTN_SELECT);
	input_set_capability(input_dev, EV_KEY, BTN_THUMBL);
	input_set_capability(input_dev, EV_KEY, BTN_THUMBR);

	/* Allow the gamepad to emit these events for screenface buttons */
	input_set_capability(input_dev, EV_KEY, KEY_F14);
	input_set_capability(input_dev, EV_KEY, KEY_F15);
	input_set_capability(input_dev, EV_KEY, KEY_F16);
	input_set_capability(input_dev, EV_KEY, KEY_F17);
	input_set_capability(input_dev, EV_KEY, KEY_F18);
	input_set_capability(input_dev, EV_KEY, KEY_F19);

	input_set_capability(input_dev, EV_KEY, BTN_TRIGGER_HAPPY1);
	input_set_capability(input_dev, EV_KEY, BTN_TRIGGER_HAPPY2);
	input_set_capability(input_dev, EV_KEY, BTN_TRIGGER_HAPPY3);
	input_set_capability(input_dev, EV_KEY, BTN_TRIGGER_HAPPY4);
	input_set_capability(input_dev, EV_KEY, BTN_TRIGGER_HAPPY5);
	input_set_capability(input_dev, EV_KEY, BTN_TRIGGER_HAPPY6);

	pipe = usb_rcvintpipe(udev, gamepad->ep_in->bEndpointAddress);
	if (!(maxp = usb_maxpacket(udev, pipe))) {
		ret = -EINVAL;
		goto err_free_input;
	}

	interval = gamepad->ep_in->bInterval ? gamepad->ep_in->bInterval :
					       ZOTAC_GAMEPAD_URB_INTERVAL;

	for (i = 0; i < ZOTAC_NUM_URBS; i++) {
		if (!(gamepad->urb_buf[i] =
			      kzalloc(ZOTAC_GAMEPAD_REPORT_SIZE, GFP_KERNEL))) {
			ret = -ENOMEM;
			goto err_free_urbs;
		}
		if (!(gamepad->urbs[i] = usb_alloc_urb(0, GFP_KERNEL))) {
			ret = -ENOMEM;
			goto err_free_urbs;
		}
		usb_fill_int_urb(gamepad->urbs[i], udev, pipe,
				 gamepad->urb_buf[i], ZOTAC_GAMEPAD_REPORT_SIZE,
				 zotac_gamepad_urb_irq, zotac, interval);
	}

	INIT_DELAYED_WORK(&gamepad->button_work, zotac_button_work_func);

	/* Initialize atomic variables */
	atomic_set(&gamepad->button_press_in_progress, 0);

	if (gamepad->ep_out) {
		input_set_capability(input_dev, EV_FF, FF_RUMBLE);

		for (i = 0; i < ZOTAC_NUM_FF_URBS; i++) {
			/* Initialize atomic ff_active */
			atomic_set(&gamepad->ff_active[i], 0);

			if (!(gamepad->ff_data[i] = usb_alloc_coherent(
				      udev, ZOTAC_FF_REPORT_LEN, GFP_KERNEL,
				      &gamepad->ff_dma[i]))) {
				ret = -ENOMEM;
				goto err_free_ff_data;
			}
			if (!(gamepad->ff_urbs[i] =
				      usb_alloc_urb(0, GFP_KERNEL))) {
				ret = -ENOMEM;
				goto err_free_ff_urbs;
			}
			usb_fill_int_urb(
				gamepad->ff_urbs[i], udev,
				usb_sndintpipe(
					udev,
					gamepad->ep_out->bEndpointAddress),
				gamepad->ff_data[i], ZOTAC_FF_REPORT_LEN,
				zotac_gamepad_ff_urb_complete, zotac,
				gamepad->ep_out->bInterval);
			gamepad->ff_urbs[i]->transfer_dma = gamepad->ff_dma[i];
			gamepad->ff_urbs[i]->transfer_flags |=
				URB_NO_TRANSFER_DMA_MAP;
		}

		if ((ret = input_ff_create_memless(
			     input_dev, NULL, zotac_gamepad_play_effect))) {
			dev_err(&zotac->hdev->dev,
				"Failed to create FF device: %d\n", ret);
			goto err_free_ff_urbs;
		}
	}

	if ((ret = input_register_device(input_dev))) {
		dev_err(&zotac->hdev->dev,
			"Failed to register input device: %d\n", ret);
		goto err_free_ff_urbs;
	}

	for (i = 0; i < ZOTAC_NUM_URBS; i++) {
		if ((ret = usb_submit_urb(gamepad->urbs[i], GFP_KERNEL))) {
			dev_err(&zotac->hdev->dev,
				"Failed to submit URB %d: %d\n", i, ret);
			while (--i >= 0)
				usb_kill_urb(gamepad->urbs[i]);
			input_unregister_device(input_dev);
			gamepad->dev = NULL;
			goto err_free_ff_urbs;
		}
	}
	return 0;

err_free_ff_urbs:
	for (i = 0; i < ZOTAC_NUM_FF_URBS; i++) {
		if (gamepad->ff_urbs[i]) {
			usb_free_urb(gamepad->ff_urbs[i]);
			gamepad->ff_urbs[i] = NULL;
		}
	}

err_free_ff_data:
	for (i = 0; i < ZOTAC_NUM_FF_URBS; i++) {
		if (gamepad->ff_data[i]) {
			usb_free_coherent(udev, ZOTAC_FF_REPORT_LEN,
					  gamepad->ff_data[i],
					  gamepad->ff_dma[i]);
			gamepad->ff_data[i] = NULL;
		}
	}

err_free_urbs:
	for (i = 0; i < ZOTAC_NUM_URBS; i++) {
		if (gamepad->urbs[i]) {
			usb_free_urb(gamepad->urbs[i]);
			gamepad->urbs[i] = NULL;
		}
		if (gamepad->urb_buf[i]) {
			kfree(gamepad->urb_buf[i]);
			gamepad->urb_buf[i] = NULL;
		}
	}

err_free_input:
	if (gamepad->dev) {
		input_free_device(gamepad->dev);
		gamepad->dev = NULL;
	}

err_free_gamepad:
	zotac->gamepad = NULL;
	kfree(gamepad);
	return ret;
}

void zotac_cleanup_gamepad(struct zotac_device *zotac)
{
	struct zotac_gamepad *gamepad;
	int i;

	if (!zotac || !zotac->gamepad)
		return;

	gamepad = zotac->gamepad;

	/* Set disconnect first, use WRITE_ONCE and memory barrier to ensure visibility */
	WRITE_ONCE(gamepad->disconnect, true);
	smp_wmb();

	cancel_delayed_work_sync(&gamepad->button_work);

	for (i = 0; i < ZOTAC_NUM_URBS; i++) {
		if (gamepad->urbs[i]) {
			usb_kill_urb(gamepad->urbs[i]);
			usb_free_urb(gamepad->urbs[i]);
			gamepad->urbs[i] = NULL;
		}
	}

	for (i = 0; i < ZOTAC_NUM_FF_URBS; i++) {
		if (gamepad->ff_urbs[i]) {
			usb_kill_urb(gamepad->ff_urbs[i]);
			usb_free_urb(gamepad->ff_urbs[i]);
			gamepad->ff_urbs[i] = NULL;
		}
	}

	if (gamepad->dev) {
		input_unregister_device(gamepad->dev);
		gamepad->dev = NULL;
	}

	zotac->gamepad = NULL;
}
