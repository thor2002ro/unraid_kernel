// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * HID driver for ZOTAC Gaming Zone Controller - RGB LED control
 *
 * Copyright (c) 2025 Luke D. Jones <luke@ljones.dev>
 */

#include <linux/device.h>
#include <linux/hid.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/usb.h>

#include "zotac-zone.h"

#define ZOTAC_VENDOR_ID 0x1ee9
#define ZOTAC_ALT_VENDOR_ID 0x1e19
#define ZOTAC_PRODUCT_ID 0x1590

#define ZOTAC_DIAL_INTERFACE 1
#define ZOTAC_REPORT_INTERFACE 2
#define ZOTAC_COMMAND_INTERFACE 3

#define ZOTAC_DIAL_REPORT_ID 0x03
#define ZOTAC_KBD_REPORT_ID 0x02
#define ZOTAC_MOUSE_REPORT_ID 0x04
#define ZOTAC_STATUS_REPORT_ID 0x07
#define ZOTAC_STATUS2_REPORT_ID 0x08
#define ZOTAC_STATUS3_REPORT_ID 0x09

#define ZOTAC_RIGHT_DIAL_CW_BIT 0
#define ZOTAC_RIGHT_DIAL_CCW_BIT 1
#define ZOTAC_LEFT_DIAL_CW_BIT 3
#define ZOTAC_LEFT_DIAL_CCW_BIT 4

#define HID_USAGE_F16 0x6B
#define HID_USAGE_F17 0x6C
#define HID_USAGE_F18 0x6D
#define HID_USAGE_F19 0x6E
#define HID_USAGE_F20 0x6F

struct zotac_device zotac;

typedef void (*zotac_report_handler)(struct zotac_device *zotac, u8 *data,
				     int size);

struct zotac_report_handler {
	u8 report_id;
	zotac_report_handler handler;
	const char *name;
};

/**
	* zotac_get_usb_interface - Get the USB interface from a HID device
	* @hdev: The HID device
	*
	* Returns the USB interface if the device is a USB device, NULL otherwise
	*/
struct usb_interface *zotac_get_usb_interface(struct hid_device *hdev)
{
	struct usb_interface *intf = NULL;

	if (hid_is_usb(hdev))
		intf = to_usb_interface(hdev->dev.parent);

	return intf;
}

static int get_interface_num(struct hid_device *hdev)
{
	struct usb_interface *intf = zotac_get_usb_interface(hdev);

	if (intf && intf->cur_altsetting)
		return intf->cur_altsetting->desc.bInterfaceNumber;

	return -1;
}

static void process_dial_wheel_report(struct zotac_device *zotac, u8 *data,
				      int size)
{
	u8 value;

	if (size < 4 || !zotac->wheel_input)
		return;

	value = data[3];
	if (value == 0)
		return;

	if (value & BIT(ZOTAC_RIGHT_DIAL_CW_BIT))
		input_report_rel(zotac->wheel_input, REL_WHEEL, 1);
	if (value & BIT(ZOTAC_RIGHT_DIAL_CCW_BIT))
		input_report_rel(zotac->wheel_input, REL_WHEEL, -1);

	if (value & BIT(ZOTAC_LEFT_DIAL_CW_BIT))
		input_report_rel(zotac->wheel_input, REL_HWHEEL, 1);
	if (value & BIT(ZOTAC_LEFT_DIAL_CCW_BIT))
		input_report_rel(zotac->wheel_input, REL_HWHEEL, -1);

	input_sync(zotac->wheel_input);
}

static int process_keyboard_report(struct zotac_device *zotac, u8 *data,
				   int size)
{
	u32 pattern;
	enum qam_mode qam_mode;

	if (zotac->gamepad)
		qam_mode = zotac->gamepad->qam_mode;

	if (size < 5)
		return 0;

	pattern = (data[1] << 16) | (data[2] << 8) | data[3];

	if (pattern == 0x09006c || pattern == 0x09006d || pattern == 0x080007 || pattern == 0x050063) {
		switch (data[3]) {
		case 0x63:
			switch (qam_mode) {
			case QAM_MODE_KEYBOARD:
				data[3] = HID_USAGE_F19;
				break;
			case QAM_MODE_CUSTOM:
				zotac_gamepad_send_button(zotac, (int[]){ BTN_TRIGGER_HAPPY6 }, 1);
				break;
			default:
				zotac_gamepad_send_button(zotac, (int[]){ BTN_MODE, BTN_X }, 2);
				break;
			}
			break;
		case 0x6C:
			switch (qam_mode) {
			case QAM_MODE_KEYBOARD:
				data[3] = HID_USAGE_F16;
				break;
			default:
				zotac_gamepad_send_button(zotac, (int[]){ BTN_MODE }, 1);
				break;
			}
			break;
		case 0x6D:
			switch (qam_mode) {
			case QAM_MODE_KEYBOARD:
				data[3] = HID_USAGE_F17;
				break;
			default:
				zotac_gamepad_send_button(zotac, (int[]){ BTN_MODE, BTN_A }, 2);
				break;
			}
			break;
		case 0x07:
			switch (qam_mode) {
			case QAM_MODE_KEYBOARD:
				data[3] = HID_USAGE_F18;
				break;
			case QAM_MODE_CUSTOM:
				zotac_gamepad_send_button(zotac, (int[]){ BTN_TRIGGER_HAPPY5 }, 1);
				break;
			default:
				zotac_gamepad_send_button(zotac, (int[]){ BTN_MODE, BTN_B }, 2);
				break;
			}
			break;
		}
		if (qam_mode) {
			memset(data, 0, size);
			return 1;
		} else {
			data[1] = 0;
			return 0;
		}
	}
	return 0;
}

static void process_mouse_report(struct zotac_device *zotac, u8 *data, int size)
{
	s8 x_movement = 0, y_movement = 0, wheel_movement = 0;
	int bit, i;

	if (size < 5 || !zotac->mouse_input)
		return;

	x_movement = (s8)data[2];
	y_movement = (s8)data[3];

	if (size >= 5)
		wheel_movement = (s8)data[4];

	for (i = 0; i < 8; i++) {
		bit = 1 << i;
		input_report_key(zotac->mouse_input, BTN_LEFT + i,
				 (data[1] & bit) ? 1 : 0);
	}

	input_report_rel(zotac->mouse_input, REL_X, x_movement);
	input_report_rel(zotac->mouse_input, REL_Y, y_movement);

	if (wheel_movement)
		input_report_rel(zotac->mouse_input, REL_WHEEL, wheel_movement);

	input_sync(zotac->mouse_input);
}

static const struct zotac_report_handler dial_interface_handlers[] = {
	{ .report_id = ZOTAC_DIAL_REPORT_ID,
	  .handler = process_dial_wheel_report,
	  .name = "dial wheel" },
	{ .report_id = ZOTAC_MOUSE_REPORT_ID,
	  .handler = process_mouse_report,
	  .name = "mouse" },
	{ 0 }
};

static int zotac_process_report(struct zotac_device *zotac,
				const struct zotac_report_handler *handlers,
				u8 *data, int size)
{
	const struct zotac_report_handler *handler;
	u8 report_id;

	if (size < 1)
		return 0;

	report_id = data[0];

	for (handler = handlers; handler->handler; handler++) {
		if (handler->report_id == report_id) {
			handler->handler(zotac, data, size);
			return 1;
		}
	}

	return 0;
}

static int zotac_raw_event(struct hid_device *hdev, struct hid_report *report,
			   u8 *data, int size)
{
	int intf_num = get_interface_num(hdev);
	int handled = 0;

	if (size < 2)
		return 0;

	switch (intf_num) {
	case ZOTAC_GAMEPAD_INTERFACE:
		if (zotac.gamepad) {
			zotac_process_gamepad_report(&zotac, data, size);
			handled = 1;
		}
		break;
	case ZOTAC_DIAL_INTERFACE:
		if (data[0] == ZOTAC_KBD_REPORT_ID)
			return process_keyboard_report(&zotac, data, size);

		handled = zotac_process_report(&zotac, dial_interface_handlers,
					       data, size);
		break;
	case ZOTAC_REPORT_INTERFACE:
		if (data[0] >= ZOTAC_STATUS_REPORT_ID &&
		    data[0] <= ZOTAC_STATUS3_REPORT_ID)
			handled = 1;
		break;
	}

	return handled;
}

static int zotac_input_mapping(struct hid_device *hdev, struct hid_input *hi,
			       struct hid_field *field, struct hid_usage *usage,
			       unsigned long **bit, int *max)
{
	int intf_num = get_interface_num(hdev);

	if (intf_num == ZOTAC_REPORT_INTERFACE ||
	    intf_num == ZOTAC_COMMAND_INTERFACE)
		return -1;

	if (intf_num == ZOTAC_DIAL_INTERFACE) {
		if (field->report &&
		    (field->report->id == ZOTAC_MOUSE_REPORT_ID ||
		     field->report->id == ZOTAC_DIAL_REPORT_ID))
			return -1;

		if (field->report && field->report->id == ZOTAC_KBD_REPORT_ID)
			return 0;
	}

	return 0;
}

/**
	* zotac_init_input_device - Initialize common input device properties
	* @input_dev: The input device to initialize
	* @hdev: The HID device associated with this input device
	* @name: The name to assign to the input device
	*
	* Sets up common properties for an input device based on the HID device
	*/
void zotac_init_input_device(struct input_dev *input_dev,
			     struct hid_device *hdev, const char *name)
{
	input_dev->name = name;
	input_dev->phys = hdev->phys;
	input_dev->uniq = hdev->uniq;
	input_dev->id.bustype = hdev->bus;
	input_dev->id.vendor = hdev->vendor;
	input_dev->id.product = hdev->product;
	input_dev->id.version = hdev->version;
	input_dev->dev.parent = &hdev->dev;
}

static int setup_wheel_input_device(struct zotac_device *zotac)
{
	int ret;

	zotac->wheel_input = devm_input_allocate_device(&zotac->hdev->dev);
	if (!zotac->wheel_input) {
		hid_err(zotac->hdev, "Failed to allocate wheel input device\n");
		return -ENOMEM;
	}

	zotac_init_input_device(zotac->wheel_input, zotac->hdev,
				"ZOTAC Gaming Zone Dials");

	__set_bit(EV_REL, zotac->wheel_input->evbit);
	__set_bit(REL_WHEEL, zotac->wheel_input->relbit);
	__set_bit(REL_HWHEEL, zotac->wheel_input->relbit);

	ret = input_register_device(zotac->wheel_input);
	if (ret) {
		hid_err(zotac->hdev, "Failed to register wheel input device\n");
		return ret;
	}

	return 0;
}

static int setup_mouse_input_device(struct zotac_device *zotac)
{
	int ret, i;

	zotac->mouse_input = devm_input_allocate_device(&zotac->hdev->dev);
	if (!zotac->mouse_input) {
		hid_err(zotac->hdev, "Failed to allocate mouse input device\n");
		return -ENOMEM;
	}

	zotac_init_input_device(zotac->mouse_input, zotac->hdev,
				"ZOTAC Gaming Zone Mouse");

	__set_bit(EV_KEY, zotac->mouse_input->evbit);
	__set_bit(EV_REL, zotac->mouse_input->evbit);

	for (i = 0; i < 8; i++)
		__set_bit(BTN_LEFT + i, zotac->mouse_input->keybit);

	__set_bit(REL_X, zotac->mouse_input->relbit);
	__set_bit(REL_Y, zotac->mouse_input->relbit);
	__set_bit(REL_WHEEL, zotac->mouse_input->relbit);

	ret = input_register_device(zotac->mouse_input);
	if (ret) {
		hid_err(zotac->hdev, "Failed to register mouse input device\n");
		return ret;
	}

	return 0;
}

static int zotac_probe(struct hid_device *hdev, const struct hid_device_id *id)
{
	int intf_num, ret;
	bool gamepad_initialized = false;
	bool cfg_initialized = false;

	intf_num = get_interface_num(hdev);

	zotac.hdev = hdev;
	hid_set_drvdata(hdev, &zotac);

	ret = hid_parse(hdev);
	if (ret) {
		hid_err(hdev, "Parse failed\n");
		return ret;
	}

	switch (intf_num) {
	case ZOTAC_DIAL_INTERFACE:
		ret = hid_hw_start(hdev, HID_CONNECT_DEFAULT);
		break;
	case ZOTAC_REPORT_INTERFACE:
	case ZOTAC_COMMAND_INTERFACE:
		ret = hid_hw_start(hdev, HID_CONNECT_HIDRAW);
		break;
	default:
		ret = hid_hw_start(hdev, HID_CONNECT_DEFAULT);
		break;
	}

	if (ret) {
		hid_err(hdev, "HID hw start failed\n");
		goto err;
	}

	if (intf_num == ZOTAC_DIAL_INTERFACE) {
		ret = setup_wheel_input_device(&zotac);
		if (ret) {
			hid_err(hdev, "Wheel input setup failed\n");
			goto err_stop_hw;
		}

		ret = setup_mouse_input_device(&zotac);
		if (ret) {
			hid_err(hdev, "Mouse input setup failed\n");
			/* Unregister wheel input before jumping to err_stop_hw */
			input_unregister_device(zotac.wheel_input);
			zotac.wheel_input = NULL;
			goto err_stop_hw;
		}

		ret = zotac_init_gamepad(&zotac, zotac_get_usb_interface(hdev));
		if (ret) {
			hid_warn(hdev, "Gamepad initialization failed: %d\n",
				 ret);
		} else {
			gamepad_initialized = true;
		}
	}

	if (intf_num == ZOTAC_COMMAND_INTERFACE) {
		ret = zotac_cfg_init(&zotac);
		if (ret) {
			hid_warn(hdev, "Cfg data initialization failed: %d\n",
				 ret);
			goto err_stop_hw;
		} else {
			cfg_initialized = true;
			zotac_register_sysfs(&zotac);
		}
		ret = zotac_rgb_init(&zotac);
		if (ret)
			hid_warn(hdev, "RGB initialization failed: %d\n", ret);
	}

	hid_info(hdev, "Loaded version %s\n", ZOTAC_VERSION);

	return 0;

err_stop_hw:
	if (gamepad_initialized)
		zotac_cleanup_gamepad(&zotac);
	if (cfg_initialized)
		zotac_cfg_cleanup(&zotac);

	hid_hw_stop(hdev);
err:
	return ret;
}

static int zotac_input_configured(struct hid_device *hdev, struct hid_input *hi)
{
	int intf_num = get_interface_num(hdev);

	if (intf_num == ZOTAC_DIAL_INTERFACE)
		hi->input->name = "ZOTAC Gaming Zone Keyboard";

	return 0;
}

static int zotac_resubmit_urbs(struct hid_device *hdev)
{
	int intf_num = get_interface_num(hdev);
	int ret = 0;

	if (zotac.gamepad && zotac.gamepad->urbs[0] &&
	    (intf_num == ZOTAC_GAMEPAD_INTERFACE ||
	     intf_num == ZOTAC_DIAL_INTERFACE)) {
		ret = usb_submit_urb(zotac.gamepad->urbs[0], GFP_NOIO);
		if (ret) {
			hid_err(hdev, "Failed to resubmit gamepad URB: %d\n",
				ret);
			return ret;
		}
		hid_dbg(hdev, "Gamepad URB resubmitted successfully\n");
	}

	return 0;
}

static int zotac_resume(struct hid_device *hdev)
{
	hid_dbg(hdev, "resume called for interface %d\n",
		get_interface_num(hdev));
	return zotac_resubmit_urbs(hdev);
}

static int zotac_reset_resume(struct hid_device *hdev)
{
	int intf_num = get_interface_num(hdev);

	hid_info(hdev, "reset_resume called for interface %d\n", intf_num);

	if (zotac.led_rgb_dev && intf_num == ZOTAC_COMMAND_INTERFACE)
		zotac_rgb_resume(&zotac);

	return zotac_resubmit_urbs(hdev);
}

static int zotac_suspend(struct hid_device *hdev, pm_message_t message)
{
	int intf_num = get_interface_num(hdev);
	int i;

	hid_dbg(hdev, "suspend called for interface %d\n", intf_num);

	if (zotac.gamepad && (intf_num == ZOTAC_GAMEPAD_INTERFACE ||
			intf_num == ZOTAC_DIAL_INTERFACE)) {
		/* Kill all input URBs */
		for (i = 0; i < ZOTAC_NUM_URBS; i++) {
			if (zotac.gamepad->urbs[i]) {
				usb_kill_urb(zotac.gamepad->urbs[i]);
				hid_dbg(hdev,
					"Gamepad URB %d killed for suspend\n",
					i);
			}
		}

		/* Kill all force feedback URBs */
		for (i = 0; i < ZOTAC_NUM_FF_URBS; i++) {
			if (zotac.gamepad->ff_urbs[i]) {
				usb_kill_urb(zotac.gamepad->ff_urbs[i]);
				hid_dbg(hdev,
					"Force feedback URB %d killed for suspend\n",
					i);
			}
		}
	}

	if (zotac.led_rgb_dev && intf_num == ZOTAC_COMMAND_INTERFACE)
		zotac_rgb_suspend(&zotac);

	return 0;
}

static void zotac_remove(struct hid_device *hdev)
{
	int intf_num = get_interface_num(hdev);

	dev_info(&hdev->dev, "Removing driver for interface %d", intf_num);

	if (intf_num == ZOTAC_COMMAND_INTERFACE) {
		dev_info(&hdev->dev, "Unregistering sysfs entries");
		zotac_unregister_sysfs(&zotac);
	}

	if (zotac.gamepad)
		zotac_cleanup_gamepad(&zotac);

	if (zotac.cfg_data)
		zotac_cfg_cleanup(&zotac);

	if (zotac.led_rgb_dev)
		zotac_rgb_cleanup(&zotac);

	hid_hw_stop(hdev);
}

static const struct hid_device_id zotac_devices[] = {
	{ HID_USB_DEVICE(ZOTAC_VENDOR_ID, ZOTAC_PRODUCT_ID) },
	{ HID_USB_DEVICE(ZOTAC_ALT_VENDOR_ID, ZOTAC_PRODUCT_ID) },
	{}
};

MODULE_DEVICE_TABLE(hid, zotac_devices);

static struct hid_driver zotac_driver = {
	.name = "zotac_zone_hid",
	.id_table = zotac_devices,
	.probe = zotac_probe,
	.remove = zotac_remove,
	.raw_event = zotac_raw_event,
	.input_mapping = zotac_input_mapping,
	.input_configured = zotac_input_configured,
	.reset_resume = zotac_reset_resume,
	.suspend = zotac_suspend,
	.resume = zotac_resume,
};

module_hid_driver(zotac_driver);

MODULE_AUTHOR("Luke D. Jones");
MODULE_DESCRIPTION("HID driver for ZOTAC Gaming Zone Controller");
MODULE_LICENSE("GPL");
