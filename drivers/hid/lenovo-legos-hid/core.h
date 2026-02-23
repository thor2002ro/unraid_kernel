/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Copyright(C) 2025 Derek J. Clark <derekjohn.clark@gmail.com> */

#ifndef _LENOVO_LEGOS_HID_CORE_
#define _LENOVO_LEGOS_HID_CORE_

#include <linux/types.h>

#define GO_S_PACKET_SIZE 64

struct hid_device;

enum legos_interface {
	LEGION_GO_S_IAP_INTF_IN = 0x81,
	LEGION_GO_S_TP_INTF_IN = 0x83,
	LEGION_GO_S_CFG_INTF_IN,
	LEGION_GO_S_IMU_INTF_IN,
	LEGION_GO_S_GP_INFT_IN,
	LEGION_GO_S_UNK_INTF_IN,
};

u8 get_endpoint_address(struct hid_device *hdev);

#endif /* !_LENOVO_LEGOS_HID_CORE_*/
