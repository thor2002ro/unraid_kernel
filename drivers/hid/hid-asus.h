/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __HID_ASUS_H
#define __HID_ASUS_H

#include <linux/hid.h>

#define ROG_ALLY_CFG_INTF_IN 0x83
#define ROG_ALLY_CFG_INTF_OUT 0x04
#define ROG_ALLY_X_INTF_IN 0x87

void validate_mcu_fw_version(struct hid_device *hdev, int idProduct);

#endif	/* __HID_ASUS_H */
