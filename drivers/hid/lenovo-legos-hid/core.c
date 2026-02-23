// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  HID driver for Lenovo Legion Go S series gamepad.
 *
 *  Copyright (c) 2025 Derek J. Clark <derekjohn.clark@gmail.com>
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/hid.h>
#include <linux/types.h>
#include <linux/usb.h>

#include "core.h"
#include "config.h"
#include "../hid-ids.h"

u8 get_endpoint_address(struct hid_device *hdev)
{
	struct usb_interface *intf = to_usb_interface(hdev->dev.parent);
	struct usb_host_endpoint *ep;

	if (intf) {
		ep = intf->cur_altsetting->endpoint;
		if (ep)
			return ep->desc.bEndpointAddress;
	}

	return -ENODEV;
}

static int lenovo_legos_raw_event(struct hid_device *hdev,
				  struct hid_report *report, u8 *data, int size)
{
	int ep;

	ep = get_endpoint_address(hdev);

	switch (ep) {
	case LEGION_GO_S_CFG_INTF_IN:
		return legos_cfg_raw_event(data, size);
	default:
		break;
	}
	return 0;
}

static int lenovo_legos_hid_probe(struct hid_device *hdev,
				  const struct hid_device_id *id)
{
	int ret, ep;

	ep = get_endpoint_address(hdev);
	if (ep <= 0)
		return ep;

	ret = hid_parse(hdev);
	if (ret) {
		hid_err(hdev, "Parse failed\n");
		return ret;
	}

	ret = hid_hw_start(hdev, HID_CONNECT_HIDRAW);
	if (ret) {
		hid_err(hdev, "Failed to start HID device\n");
		return ret;
	}

	ret = hid_hw_open(hdev);
	if (ret) {
		hid_err(hdev, "Failed to open HID device\n");
		hid_hw_stop(hdev);
		return ret;
	}

	switch (ep) {
	case LEGION_GO_S_CFG_INTF_IN:
		ret = legos_cfg_probe(hdev, id);
		break;
	default:
		break;
	}

	return ret;
}

static void lenovo_legos_hid_remove(struct hid_device *hdev)
{
	int ep = get_endpoint_address(hdev);

	switch (ep) {
	case LEGION_GO_S_CFG_INTF_IN:
		legos_cfg_remove(hdev);
		break;
	default:
		hid_hw_close(hdev);
		hid_hw_stop(hdev);

		break;
	}
}

static const struct hid_device_id lenovo_legos_devices[] = {
	{ HID_USB_DEVICE(USB_VENDOR_ID_QHE,
			 USB_DEVICE_ID_LENOVO_LEGION_GO_S_XINPUT) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_QHE,
			 USB_DEVICE_ID_LENOVO_LEGION_GO_S_DINPUT) },
	{}
};

MODULE_DEVICE_TABLE(hid, lenovo_legos_devices);
static struct hid_driver lenovo_legos_hid = {
	.name = "lenovo-legos-hid",
	.id_table = lenovo_legos_devices,
	.probe = lenovo_legos_hid_probe,
	.remove = lenovo_legos_hid_remove,
	.raw_event = lenovo_legos_raw_event,
};
module_hid_driver(lenovo_legos_hid);

MODULE_AUTHOR("Derek J. Clark");
MODULE_DESCRIPTION("HID Driver for Lenovo Legion Go S Series gamepad.");
MODULE_LICENSE("GPL");
