// SPDX-License-Identifier: GPL-2.0-or-later
/*
* HID driver for ZOTAC Gaming Zone Controller - RGB LED control
*
* Copyright (c) 2025 Luke D. Jones <luke@ljones.dev>
*/

#include "asm-generic/errno-base.h"
#include "linux/kstrtox.h"
#include <linux/device.h>
#include <linux/hid.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/usb.h>

#include "zotac-zone.h"

#define REPORT_SIZE 64

#define HEADER_TAG_POS 0
#define RESERVED_POS 1
#define SEQUENCE_POS 2
#define PAYLOADSIZE_POS 3
#define COMMAND_POS 4
#define SETTING_POS 5
#define VALUE_POS 6
#define CRC_H_POS 0x3E
#define CRC_L_POS 0x3F

#define HEADER_TAG 0xE1
#define PAYLOAD_SIZE 0x3C

/*
 * Button mapping structure indices (relative to data buffer)
 * The data buffer is copied to the correct location in the HID report.
 */
#define HEADER_LEN 5
#define BTN_MAP_SOURCE_IDX (0x05 - HEADER_LEN) /* Source button ID */
#define BTN_MAP_GAMEPAD_START_IDX (0x06 - HEADER_LEN)
#define BTN_MAP_GAMEPAD_SIZE 4
#define BTN_MAP_MODIFIER_IDX (0x0A - HEADER_LEN)
#define BTN_MAP_KEYBOARD_START_IDX (0x0C - HEADER_LEN)
#define BTN_MAP_KEYBOARD_SIZE 6
#define BTN_MAP_MOUSE_IDX (0x12 - HEADER_LEN)
#define BTN_MAP_RESPONSE_MIN_SIZE 14

#define GAMEPAD_DPAD_STICK_IDX 0 /* DPad, Stick buttons */
#define GAMEPAD_FACE_BUMPER_IDX 1 /* Face buttons, Bumpers */
#define GAMEPAD_TRIGGER_IDX 2 /* Triggers */
#define GAMEPAD_RESERVED_IDX 3 /* Reserved/unused */
/*
 * Note: The above indices are relative to our data buffer, not the full protocol packet.
 * In the full protocol packet (as described in documentation), these fields would be
 * at different positions due to the packet header.
 *
 * For example, BTN_MAP_MOUSE_IDX (13 in our buffer) corresponds to offset 0x12-0x13
 * in the full protocol packet.
 */

/* Mouse speed constants */
#define CMD_SET_MOUSE_SPEED 0xA3
#define CMD_GET_MOUSE_SPEED 0xA4
#define MOUSE_SPEED_MIN 0x01 /* Slow */
#define MOUSE_SPEED_MAX 0x0A /* Fast */

#define STICK_SENSITIVITY_NUM_IDX 0
#define STICK_SENSITIVITY_DATA_IDX 1
#define STICK_SENSITIVITY_SIZE 8

#define DZ_LEFT_INNER_IDX 0
#define DZ_LEFT_OUTER_IDX 1
#define DZ_RIGHT_INNER_IDX 2
#define DZ_RIGHT_OUTER_IDX 3
#define DZ_RESPONSE_SIZE 4

#define VIB_LEFT_TRIGGER_IDX 0
#define VIB_RIGHT_TRIGGER_IDX 1
#define VIB_LEFT_RUMBLE_IDX 2
#define VIB_RIGHT_RUMBLE_IDX 3
#define VIB_RESPONSE_SIZE 4

#define CMD_SET_PROFILE 0xB1
#define CMD_GET_PROFILE 0xB2
#define CMD_GET_PROFILE_NUM 0xB3
#define CMD_RESTORE_PROFILE 0xF1
#define CMD_SAVE_CONFIG 0xFB

#define CMD_SET_VIBRATION_STRENGTH 0xA9
#define CMD_GET_VIBRATION_STRENGTH 0xAA
#define CMD_SET_STICK_DEADZONES 0xA5
#define CMD_GET_STICK_DEADZONES 0xA6
#define CMD_SET_TRIGGER_DEADZONES 0xB4
#define CMD_GET_TRIGGER_DEADZONES 0xB5
#define CMD_SET_STICK_SENSITIVITY 0xBA
#define CMD_GET_STICK_SENSITIVITY 0xBB
#define CMD_SET_BUTTON_TURBO 0xB8
#define CMD_GET_BUTTON_TURBO 0xB9
#define CMD_GET_DEVICE_INFO 0xFA
#define CMD_MOTOR_TEST 0xBD

#define MOTOR_TEST_SIZE 4

#define STICK_LEFT 0
#define STICK_RIGHT 1

#define PROFILE_DEFAULT 0x00
#define PROFILE_SECONDARY 0x01

/* Button bit positions within the turbo byte */
#define A_BTN_POS 0
#define B_BTN_POS 1
#define X_BTN_POS 2
#define Y_BTN_POS 3
#define LB_BTN_POS 4
#define RB_BTN_POS 5
#define LT_BTN_POS 6
#define RT_BTN_POS 7

/* Button ID definitions */
#define BUTTON_NONE 0x00
#define BUTTON_M1 0x01
#define BUTTON_M2 0x02
#define BUTTON_L_TOUCH_UP 0x03
#define BUTTON_L_TOUCH_DOWN 0x04
#define BUTTON_L_TOUCH_LEFT 0x05
#define BUTTON_L_TOUCH_RIGHT 0x06
#define BUTTON_R_TOUCH_UP 0x07
#define BUTTON_R_TOUCH_DOWN 0x08
#define BUTTON_R_TOUCH_LEFT 0x09
#define BUTTON_R_TOUCH_RIGHT 0x0A
#define BUTTON_LB 0x0B
#define BUTTON_RB 0x0C
#define BUTTON_LT 0x0D
#define BUTTON_RT 0x0E
#define BUTTON_A 0x0F
#define BUTTON_B 0x10
#define BUTTON_X 0x11
#define BUTTON_Y 0x12
#define BUTTON_DPAD_UP 0x13
#define BUTTON_DPAD_DOWN 0x14
#define BUTTON_DPAD_LEFT 0x15
#define BUTTON_DPAD_RIGHT 0x16
#define BUTTON_LS 0x17
#define BUTTON_RS 0x18

/* Modifier key definitions */
#define MOD_NONE 0x00
#define MOD_LEFT_CTRL 0x01
#define MOD_LEFT_SHIFT 0x02
#define MOD_LEFT_ALT 0x04
#define MOD_LEFT_WIN 0x08
#define MOD_RIGHT_CTRL 0x10
#define MOD_RIGHT_SHIFT 0x20
#define MOD_RIGHT_ALT 0x40
#define MOD_RIGHT_WIN 0x80

int zotac_cfg_refresh(struct zotac_device *zotac);

struct button_directory {
	const char *name; /* Directory name (e.g., "btn_a") */
	u8 button_id; /* Associated button ID */
	bool has_turbo; /* Whether this button supports turbo */
	struct kobject *
		kobj; /* kobject for this directory (filled during registration) */
	struct attribute_group *main_group; /* Main button attributes */
	struct attribute_group *remap_group; /* Remap subdirectory attributes */
};

/* Structure to map button names to their byte and bit positions */
struct button_mapping_entry {
	const char *name;
	u8 byte_index;
	u8 bit_mask;
};

/* Define all supported buttons with their byte index and bit mask */
static const struct button_mapping_entry button_map[] = {
	{ "dpad_up", 0, 0x01 },
	{ "dpad_down", 0, 0x02 },
	{ "dpad_left", 0, 0x04 },
	{ "dpad_right", 0, 0x08 },
	{ "ls", 0, 0x40 },
	{ "rs", 0, 0x80 },
	{ "lb", 1, 0x01 },
	{ "rb", 1, 0x02 },
	{ "a", 1, 0x10 },
	{ "b", 1, 0x20 },
	{ "x", 1, 0x40 },
	{ "y", 1, 0x80 },
	{ "lt", 2, 0x01 },
	{ "rt", 2, 0x02 },
	{ NULL, 0, 0 } /* Terminator */
};

static const struct {
	const char *name;
	u8 id;
} gamepad_button_names[] = {
	{ "none", BUTTON_NONE },
	{ "a", BUTTON_A },
	{ "b", BUTTON_B },
	{ "x", BUTTON_X },
	{ "y", BUTTON_Y },
	{ "lb", BUTTON_LB },
	{ "rb", BUTTON_RB },
	{ "lt", BUTTON_LT },
	{ "rt", BUTTON_RT },
	{ "ls", BUTTON_LS },
	{ "rs", BUTTON_RS },
	{ "dpad_up", BUTTON_DPAD_UP },
	{ "dpad_down", BUTTON_DPAD_DOWN },
	{ "dpad_left", BUTTON_DPAD_LEFT },
	{ "dpad_right", BUTTON_DPAD_RIGHT },
};

static const struct {
	const char *name;
	u8 value;
} modifier_names[] = {
	{ "none", MOD_NONE },
	{ "left_ctrl", MOD_LEFT_CTRL },
	{ "left_shift", MOD_LEFT_SHIFT },
	{ "left_alt", MOD_LEFT_ALT },
	{ "left_win", MOD_LEFT_WIN },
	{ "right_ctrl", MOD_RIGHT_CTRL },
	{ "right_shift", MOD_RIGHT_SHIFT },
	{ "right_alt", MOD_RIGHT_ALT },
	{ "right_win", MOD_RIGHT_WIN },
};

/* Keyboard key definitions */
struct key_name_mapping {
	const char *name;
	u8 keycode;
};

static const struct key_name_mapping keyboard_keys[] = {
	{ "none", 0x00 },	 { "a", 0x04 },		 { "b", 0x05 },
	{ "c", 0x06 },		 { "d", 0x07 },		 { "e", 0x08 },
	{ "f", 0x09 },		 { "g", 0x0a },		 { "h", 0x0b },
	{ "i", 0x0c },		 { "j", 0x0d },		 { "k", 0x0e },
	{ "l", 0x0f },		 { "m", 0x10 },		 { "n", 0x11 },
	{ "o", 0x12 },		 { "p", 0x13 },		 { "q", 0x14 },
	{ "r", 0x15 },		 { "s", 0x16 },		 { "t", 0x17 },
	{ "u", 0x18 },		 { "v", 0x19 },		 { "w", 0x1a },
	{ "x", 0x1b },		 { "y", 0x1c },		 { "z", 0x1d },
	{ "1", 0x1e },		 { "2", 0x1f },		 { "3", 0x20 },
	{ "4", 0x21 },		 { "5", 0x22 },		 { "6", 0x23 },
	{ "7", 0x24 },		 { "8", 0x25 },		 { "9", 0x26 },
	{ "0", 0x27 },		 { "enter", 0x28 },	 { "esc", 0x29 },
	{ "backspace", 0x2a },	 { "tab", 0x2b },	 { "space", 0x2c },
	{ "minus", 0x2d },	 { "equals", 0x2e },	 { "leftbrace", 0x2f },
	{ "rightbrace", 0x30 },	 { "backslash", 0x31 },	 { "semicolon", 0x33 },
	{ "apostrophe", 0x34 },	 { "grave", 0x35 },	 { "comma", 0x36 },
	{ "dot", 0x37 },	 { "slash", 0x38 },	 { "capslock", 0x39 },
	{ "f1", 0x3a },		 { "f2", 0x3b },	 { "f3", 0x3c },
	{ "f4", 0x3d },		 { "f5", 0x3e },	 { "f6", 0x3f },
	{ "f7", 0x40 },		 { "f8", 0x41 },	 { "f9", 0x42 },
	{ "f10", 0x43 },	 { "f11", 0x44 },	 { "f12", 0x45 },
	{ "printscreen", 0x46 }, { "scrolllock", 0x47 }, { "pause", 0x48 },
	{ "insert", 0x49 },	 { "home", 0x4a },	 { "pageup", 0x4b },
	{ "delete", 0x4c },	 { "end", 0x4d },	 { "pagedown", 0x4e },
	{ "right", 0x4f },	 { "left", 0x50 },	 { "down", 0x51 },
	{ "up", 0x52 },		 { "numlock", 0x53 },	 { "kpslash", 0x54 },
	{ "kpasterisk", 0x55 },	 { "kpminus", 0x56 },	 { "kpplus", 0x57 },
	{ "kpenter", 0x58 },	 { "kp1", 0x59 },	 { "kp2", 0x5a },
	{ "kp3", 0x5b },	 { "kp4", 0x5c },	 { "kp5", 0x5d },
	{ "kp6", 0x5e },	 { "kp7", 0x5f },	 { "kp8", 0x60 },
	{ "kp9", 0x61 },	 { "kp0", 0x62 },	 { "kpdot", 0x63 },
	{ "application", 0x65 }
};

/* Mouse button definitions */
#define MOUSE_LEFT 0x01
#define MOUSE_RIGHT 0x02
#define MOUSE_MIDDLE 0x04

static const struct {
	const char *name;
	u8 value;
} mouse_button_names[] = {
	{ "left", MOUSE_LEFT },
	{ "right", MOUSE_RIGHT },
	{ "middle", MOUSE_MIDDLE },
};

struct zotac_device_info {
	u64 device_id;
	u16 vid;
	u16 pid;
	u8 num_led_zones;
	struct {
		u8 major;
		u8 mid;
		u8 minor;
		u16 revision;
	} fw_version;
	struct {
		u8 major;
		u8 mid;
		u8 minor;
	} hw_version;
};

static u16 zotac_calc_crc(u8 *data)
{
	const int payload_end = 0x3D;
	const int payload_start = 4;
	const u16 crc_seed = 0;
	u16 crc = crc_seed;
	u32 h1, h2, h3, h4;
	int i;

	for (i = payload_start; i <= payload_end; i++) {
		h1 = (u32)((crc ^ data[i]) & 0xFF);
		h2 = h1 & 0x0F;
		h3 = (h2 << 4) ^ h1;
		h4 = h3 >> 4;

		crc = (u16)((((((h3 << 1) ^ h4) << 4) ^ h2) << 3) ^ h4 ^
			    (crc >> 8));
	}

	return crc;
}

static int zotac_send_command_and_get_response_usb(struct hid_device *hdev,
						   u8 *send_buf, int send_len,
						   u8 *recv_buf, int recv_len)
{
	struct usb_device *udev =
		interface_to_usbdev(to_usb_interface(hdev->dev.parent));
	struct usb_interface *intf = to_usb_interface(hdev->dev.parent);
	const int polling_interval_ms = 50;
	int actual_length = 0;

	unsigned int pipe_in, pipe_out;
	int ret;

	if (!intf || !udev) {
		hid_err(hdev, "Failed to get USB interface or device\n");
		return -ENODEV;
	}

	pipe_out = usb_sndintpipe(udev, 0x05);
	pipe_in = usb_rcvintpipe(udev, 0x84);

	ret = usb_interrupt_msg(udev, pipe_out, send_buf, send_len,
				&actual_length, 1000);
	if (ret < 0) {
		hid_err(hdev, "Failed to send USB command: %d\n", ret);
		return ret;
	}

	memset(recv_buf, 0, recv_len);
	ret = usb_interrupt_msg(udev, pipe_in, recv_buf, recv_len,
				&actual_length, polling_interval_ms);
	if (ret == 0 && actual_length > 0) {
		return actual_length;
	}

	hid_err(hdev, "Timeout waiting for USB response\n");
	return -ETIMEDOUT;
}

static int zotac_send_command_raw(struct zotac_device *zotac, u8 cmd_code,
				  u8 setting, const u8 *data, size_t data_len,
				  u8 *response_buffer, size_t *response_len)
{
	bool is_cmd = (cmd_code == CMD_SET_RGB || cmd_code == CMD_GET_RGB);
	int reply_len, result = -EIO;

	struct zotac_cfg_data *cfg;
	size_t copy_len;
	u8 *buffer;
	u16 crc;

	if (!zotac->cfg_data || !zotac->hdev)
		return -ENODEV;

	cfg = zotac->cfg_data;

	buffer = kzalloc(REPORT_SIZE, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	if (mutex_lock_interruptible(&cfg->command_mutex)) {
		kfree(buffer);
		return -EINTR;
	}

	memset(buffer, 0, REPORT_SIZE);
	buffer[HEADER_TAG_POS] = HEADER_TAG;
	buffer[RESERVED_POS] = 0x00;
	buffer[SEQUENCE_POS] = cfg->sequence_num;
	buffer[PAYLOADSIZE_POS] = PAYLOAD_SIZE;
	buffer[COMMAND_POS] = cmd_code;

	if (is_cmd) {
		buffer[SETTING_POS] = setting;

		if (data && data_len > 0) {
			copy_len = min_t(size_t, data_len, PAYLOAD_SIZE - 2);
			memcpy(&buffer[VALUE_POS], data, copy_len);
		}
	} else {
		if (data && data_len > 0) {
			copy_len = min_t(size_t, data_len, PAYLOAD_SIZE - 1);
			memcpy(&buffer[SETTING_POS], data, copy_len);
		} else {
			buffer[SETTING_POS] = setting;
		}
	}

	crc = zotac_calc_crc(buffer);
	buffer[CRC_H_POS] = (crc >> 8) & 0xFF;
	buffer[CRC_L_POS] = crc & 0xFF;

	reply_len = zotac_send_command_and_get_response_usb(
		zotac->hdev, buffer, REPORT_SIZE, response_buffer, REPORT_SIZE);

	if (reply_len > 0) {
		if (response_buffer[COMMAND_POS] == cmd_code) {
			*response_len = reply_len;
			cfg->sequence_num = (cfg->sequence_num + 1) & 0xFF;
			result = 0;
		} else {
			hid_err(zotac->hdev,
				"Command mismatch in response: expected 0x%02x, got 0x%02x\n",
				cmd_code, response_buffer[COMMAND_POS]);
			result = -EIO;
		}
	} else {
		hid_err(zotac->hdev,
			"No response received for command 0x%02x: %d\n",
			cmd_code, reply_len);
		result = reply_len < 0 ? reply_len : -EIO;
	}

	mutex_unlock(&cfg->command_mutex);
	kfree(buffer);

	return result;
}

int zotac_send_get_command(struct zotac_device *zotac, u8 cmd_code, u8 setting,
			   const u8 *req_data, size_t req_data_len,
			   u8 *output_data, size_t *output_len)
{
	bool is_status_offset =
		(cmd_code == CMD_SET_RGB || cmd_code == CMD_SET_BUTTON_MAPPING);
	size_t response_size = REPORT_SIZE, available, to_copy;
	int data_offset, ret;
	u8 *response_buffer;

	response_buffer = kzalloc(REPORT_SIZE, GFP_KERNEL);
	if (!response_buffer)
		return -ENOMEM;

	ret = zotac_send_command_raw(zotac, cmd_code, setting, req_data,
				     req_data_len, response_buffer,
				     &response_size);
	if (ret < 0) {
		kfree(response_buffer);
		return ret;
	}

	if (response_size <= COMMAND_POS ||
	    response_buffer[COMMAND_POS] != cmd_code) {
		kfree(response_buffer);
		return -EIO;
	}

	data_offset = is_status_offset ? 7 : 5;

	if (output_data && output_len && *output_len > 0 &&
	    response_size > data_offset) {
		available = response_size - data_offset;
		to_copy = min_t(size_t, available, *output_len);

		memcpy(output_data, &response_buffer[data_offset], to_copy);
		*output_len = to_copy;
	}

	kfree(response_buffer);
	return 0;
}

int zotac_send_set_command(struct zotac_device *zotac, u8 cmd_code, u8 setting,
			   const u8 *data, size_t data_len)
{
	bool is_status_offset =
		(cmd_code == CMD_SET_RGB || cmd_code == CMD_SET_BUTTON_MAPPING);
	size_t response_size = REPORT_SIZE;

	int ret, status_offset;
	u8 *response_buffer;

	response_buffer = kzalloc(REPORT_SIZE, GFP_KERNEL);
	if (!response_buffer) {
		hid_err(zotac->hdev,
			"SET_COMMAND: Failed to allocate response buffer");
		return -ENOMEM;
	}

	ret = zotac_send_command_raw(zotac, cmd_code, setting, data, data_len,
				     response_buffer, &response_size);

	if (ret < 0) {
		hid_err(zotac->hdev,
			"SET_COMMAND: Command failed with error %d", ret);
		kfree(response_buffer);
		return ret;
	}

	if (response_size <= COMMAND_POS ||
	    response_buffer[COMMAND_POS] != cmd_code) {
		hid_err(zotac->hdev,
			"SET_COMMAND: Invalid response - size=%zu, cmd=0x%02x",
			response_size, response_buffer[COMMAND_POS]);
		kfree(response_buffer);
		return -EIO;
	}

	status_offset = is_status_offset ? 6 : 5;

	if (response_size > status_offset) {
		if (response_buffer[status_offset] != 0) {
			hid_err(zotac->hdev,
				"SET_COMMAND: Command rejected by device, status=0x%02x",
				response_buffer[status_offset]);
			kfree(response_buffer);
			return -EIO;
		}
	}

	kfree(response_buffer);
	return 0;
}

int zotac_send_get_byte(struct zotac_device *zotac, u8 cmd_code, u8 setting,
			const u8 *req_data, size_t req_data_len)
{
	size_t output_len = 1;
	u8 output_data = 0;
	int ret;

	ret = zotac_send_get_command(zotac, cmd_code, setting, req_data,
				     req_data_len, &output_data, &output_len);
	if (ret < 0)
		return ret;

	if (output_len < 1)
		return -EIO;

	return output_data;
}

static int zotac_get_device_info(struct zotac_device *zotac,
				 struct zotac_device_info *info)
{
	u8 data[21];
	size_t data_len = sizeof(data);
	int ret;

	if (!zotac || !info)
		return -EINVAL;

	ret = zotac_send_get_command(zotac, CMD_GET_DEVICE_INFO, 0, NULL, 0,
				     data, &data_len);
	if (ret < 0)
		return ret;

	if (data_len < 20) {
		dev_err(&zotac->hdev->dev,
			"Incomplete device info received: %zu bytes\n",
			data_len);
		return -EIO;
	}

	info->device_id = ((u64)data[0] | ((u64)data[1] << 8) |
			   ((u64)data[2] << 16) | ((u64)data[3] << 24) |
			   ((u64)data[4] << 32) | ((u64)data[5] << 40) |
			   ((u64)data[6] << 48) | ((u64)data[7] << 56));

	info->vid = data[8] | (data[9] << 8);
	info->pid = data[10] | (data[11] << 8);

	info->num_led_zones = data[12];

	info->fw_version.major = data[13];
	info->fw_version.mid = data[14];
	info->fw_version.minor = data[15];
	info->fw_version.revision = data[19] | (data[20] << 8);

	info->hw_version.major = data[16];
	info->hw_version.mid = data[17];
	info->hw_version.minor = data[18];

	return 0;
}

static void zotac_log_device_info(struct zotac_device *zotac)
{
	struct zotac_device_info info;
	int ret;

	ret = zotac_get_device_info(zotac, &info);
	if (ret < 0) {
		dev_err(&zotac->hdev->dev, "Failed to get device info: %d\n",
			ret);
		return;
	}

	dev_info(&zotac->hdev->dev,
		 "Device Info:\n"
		 "  Device ID: %016llx\n"
		 "  VID/PID: %04x:%04x\n"
		 "  LED Zones: %u\n"
		 "  Firmware: %u.%u.%u (revision %u)\n"
		 "  Hardware: %u.%u.%u\n",
		 info.device_id, info.vid, info.pid, info.num_led_zones,
		 info.fw_version.major, info.fw_version.mid,
		 info.fw_version.minor, info.fw_version.revision,
		 info.hw_version.major, info.hw_version.mid,
		 info.hw_version.minor);
}

static const struct button_mapping_entry *find_button_by_name(const char *name)
{
	int i;
	for (i = 0; button_map[i].name != NULL; i++) {
		if (strcmp(button_map[i].name, name) == 0)
			return &button_map[i];
	}
	return NULL;
}

static bool is_button_in_mapping(u8 *mapping_bytes,
				 const struct button_mapping_entry *button)
{
	return (mapping_bytes[button->byte_index] & button->bit_mask) != 0;
}

static void add_button_to_mapping(u8 *mapping_bytes,
				  const struct button_mapping_entry *button)
{
	mapping_bytes[button->byte_index] |= button->bit_mask;
}

static int zotac_get_button_mapping(struct zotac_device *zotac, u8 button_id)
{
	if (!zotac || !zotac->cfg_data || button_id > BUTTON_MAX ||
	    button_id == 0)
		return -EINVAL;
	return 0;
}

static int zotac_set_button_mapping(struct zotac_device *zotac, u8 button_id)
{
	struct button_mapping *mapping =
		&zotac->cfg_data->button_mappings[button_id];
	u8 data[BTN_MAP_RESPONSE_MIN_SIZE] = { 0 };
	u8 *gamepad_bytes = (u8 *)&mapping->target_gamepad_buttons;

	/* Source button goes at offset 0 */
	data[BTN_MAP_SOURCE_IDX] = button_id;

	/* Controller button mappings */
	data[BTN_MAP_GAMEPAD_START_IDX + GAMEPAD_DPAD_STICK_IDX] =
		gamepad_bytes[GAMEPAD_DPAD_STICK_IDX];
	data[BTN_MAP_GAMEPAD_START_IDX + GAMEPAD_FACE_BUMPER_IDX] =
		gamepad_bytes[GAMEPAD_FACE_BUMPER_IDX];
	data[BTN_MAP_GAMEPAD_START_IDX + GAMEPAD_TRIGGER_IDX] =
		gamepad_bytes[GAMEPAD_TRIGGER_IDX];
	data[BTN_MAP_GAMEPAD_START_IDX + GAMEPAD_RESERVED_IDX] =
		gamepad_bytes[GAMEPAD_RESERVED_IDX];

	data[BTN_MAP_MODIFIER_IDX] = mapping->target_modifier_keys;

	memcpy(&data[BTN_MAP_KEYBOARD_START_IDX], mapping->target_keyboard_keys,
	       BTN_MAP_KEYBOARD_SIZE);

	data[BTN_MAP_MOUSE_IDX] = mapping->target_mouse_buttons;

	return zotac_send_set_command(zotac, CMD_SET_BUTTON_MAPPING, 0, data,
				      BTN_MAP_RESPONSE_MIN_SIZE);
}

static void zotac_modifier_value_to_names(u8 modifiers, char *buf,
					  size_t buf_size)
{
	bool first = true;
	int i, pos = 0;

	if (modifiers == 0) {
		strscpy(buf, "none", buf_size);
		return;
	}

	for (i = 0; i < ARRAY_SIZE(modifier_names); i++) {
		if (modifier_names[i].value != MOD_NONE &&
		    (modifiers & modifier_names[i].value)) {
			if (!first)
				pos += scnprintf(buf + pos, buf_size - pos,
						 " ");
			pos += scnprintf(buf + pos, buf_size - pos, "%s",
					 modifier_names[i].name);
			first = false;

			if (pos >= buf_size - 1)
				break;
		}
	}
}

static ssize_t gamepad_show(struct device *dev, struct device_attribute *attr,
			    char *buf, u8 button_id)
{
	struct button_mapping *mapping =
		&zotac.cfg_data->button_mappings[button_id];
	bool found = false;
	char *p = buf;

	u8 *mapping_bytes;
	int i;

	if (zotac_get_button_mapping(&zotac, button_id) < 0)
		return -EIO;

	mapping_bytes = (u8 *)&mapping->target_gamepad_buttons;

	for (i = 0; button_map[i].name != NULL; i++) {
		if (is_button_in_mapping(mapping_bytes, &button_map[i])) {
			p += sprintf(p, "%s ", button_map[i].name);
			found = true;
		}
	}

	if (found) {
		*(p - 1) = '\n';
	} else {
		p += sprintf(p, "none\n");
	}

	return p - buf;
}

static ssize_t gamepad_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count, u8 button_id)
{
	struct button_mapping *mapping =
		&zotac.cfg_data->button_mappings[button_id];
	u8 *mapping_bytes = (u8 *)&mapping->target_gamepad_buttons;
	char *buffer, *token, *cursor;
	bool any_valid = false;

	/* Make a copy of the input buffer for tokenization */
	buffer = kstrndup(buf, count, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	memset(mapping_bytes, 0, 4);

	cursor = buffer;
	while ((token = strsep(&cursor, " \t\n")) != NULL) {
		if (*token == '\0')
			continue;

		if (strcmp(token, "none") == 0) {
			any_valid = true;
			break;
		}

		const struct button_mapping_entry *button =
			find_button_by_name(token);
		if (button) {
			add_button_to_mapping(mapping_bytes, button);
			any_valid = true;
		}
	}

	kfree(buffer);

	if (!any_valid)
		return -EINVAL;

	return zotac_set_button_mapping(&zotac, button_id) ? -EIO : count;
}

static ssize_t modifier_show(struct device *dev, struct device_attribute *attr,
			     char *buf, u8 button_id)
{
	struct button_mapping *mapping =
		&zotac.cfg_data->button_mappings[button_id];
	u8 modifiers;

	modifiers = mapping->target_modifier_keys;
	/* Leave room for newline and null */
	zotac_modifier_value_to_names(modifiers, buf, PAGE_SIZE - 2);
	strcat(buf, "\n");
	return strlen(buf);
}

static ssize_t modifier_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count, u8 button_id)
{
	struct button_mapping *mapping =
		&zotac.cfg_data->button_mappings[button_id];
	char *buffer, *token, *cursor;
	u8 new_modifiers = 0;
	bool any_valid = false;

	buffer = kstrndup(buf, count, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	cursor = buffer;
	while ((token = strsep(&cursor, " \t\n")) != NULL) {
		if (*token == '\0')
			continue;

		if (strcmp(token, "none") == 0) {
			any_valid = true;
			new_modifiers = 0;
			break;
		}

		int i;
		for (i = 0; i < ARRAY_SIZE(modifier_names); i++) {
			if (strcmp(token, modifier_names[i].name) == 0) {
				new_modifiers |= modifier_names[i].value;
				any_valid = true;
				break;
			}
		}
	}

	kfree(buffer);

	if (!any_valid)
		return -EINVAL;

	mapping->target_modifier_keys = new_modifiers;

	return zotac_set_button_mapping(&zotac, button_id) ? -EIO : count;
}

static u8 find_key_code_by_name(const char *name)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(keyboard_keys); i++) {
		if (strcmp(keyboard_keys[i].name, name) == 0)
			return keyboard_keys[i].keycode;
	}
	return 0; /* Return "none" if not found */
}

static const char *find_key_name_by_code(u8 code)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(keyboard_keys); i++) {
		if (keyboard_keys[i].keycode == code)
			return keyboard_keys[i].name;
	}
	return "none";
}

static ssize_t keyboard_keys_show(struct device *dev,
				  struct device_attribute *attr, char *buf,
				  u8 button_id)
{
	struct button_mapping *mapping =
		&zotac.cfg_data->button_mappings[button_id];
	bool any_key = false;
	char *p = buf;
	int i;

	if (zotac_get_button_mapping(&zotac, button_id) < 0)
		return -EIO;

	/* Check each key code in the mapping */
	for (i = 0; i < BTN_MAP_KEYBOARD_SIZE; i++) {
		u8 keycode = mapping->target_keyboard_keys[i];
		if (keycode != 0) {
			p += sprintf(p, "%s ", find_key_name_by_code(keycode));
			any_key = true;
		}
	}

	if (any_key) {
		*(p - 1) = '\n';
	} else {
		p += sprintf(p, "none\n");
	}

	return p - buf;
}

static ssize_t keyboard_keys_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count, u8 button_id)
{
	struct button_mapping *mapping =
		&zotac.cfg_data->button_mappings[button_id];
	u8 new_keys[BTN_MAP_KEYBOARD_SIZE] = { 0 };
	bool any_valid = false;
	int key_count = 0;

	char *buffer, *token, *cursor;

	buffer = kstrndup(buf, count, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	cursor = buffer;
	while ((token = strsep(&cursor, " \t\n")) != NULL) {
		if (*token == '\0')
			continue;

		if (strcmp(token, "none") == 0) {
			any_valid = true;
			key_count = 0; /* Clear all keys */
			break;
		}

		if (key_count < BTN_MAP_KEYBOARD_SIZE) {
			u8 keycode = find_key_code_by_name(token);
			if (keycode != 0) {
				new_keys[key_count++] = keycode;
				any_valid = true;
			}
		}
	}

	kfree(buffer);

	if (!any_valid)
		return -EINVAL;

	memcpy(mapping->target_keyboard_keys, new_keys, BTN_MAP_KEYBOARD_SIZE);

	return zotac_set_button_mapping(&zotac, button_id) ? -EIO : count;
}

static ssize_t keyboard_list_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	char *p = buf;
	int i;

	for (i = 0; i < ARRAY_SIZE(keyboard_keys); i++) {
		if (keyboard_keys[i].keycode != 0x00) {
			int len = sprintf(p, "%s ", keyboard_keys[i].name);
			p += len;

			if (p - buf > PAGE_SIZE - 32) {
				/* Add an indication that the list was truncated */
				p += sprintf(p, "...");
				break;
			}
		}
	}

	if (p > buf)
		*(p - 1) = '\n';
	else
		*p++ = '\n';

	return p - buf;
}
static DEVICE_ATTR_RO_NAMED(keyboard_list, "keyboard_list");

static ssize_t mouse_buttons_show(struct device *dev,
				  struct device_attribute *attr, char *buf,
				  u8 button_id)
{
	struct button_mapping *mapping =
		&zotac.cfg_data->button_mappings[button_id];
	u8 mouse_buttons = mapping->target_mouse_buttons;
	bool found = false;
	char *p = buf;
	int i;

	if (zotac_get_button_mapping(&zotac, button_id) < 0)
		return -EIO;

	for (i = 0; i < ARRAY_SIZE(mouse_button_names); i++) {
		if (mouse_buttons & mouse_button_names[i].value) {
			p += sprintf(p, "%s ", mouse_button_names[i].name);
			found = true;
		}
	}

	if (found) {
		*(p - 1) = '\n';
	} else {
		p += sprintf(p, "none\n");
	}

	return p - buf;
}

static ssize_t mouse_buttons_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count, u8 button_id)
{
	struct button_mapping *mapping =
		&zotac.cfg_data->button_mappings[button_id];
	char *buffer, *token, *cursor;
	u8 new_mouse_buttons = 0;
	bool any_valid = false;

	buffer = kstrndup(buf, count, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	cursor = buffer;
	while ((token = strsep(&cursor, " \t\n")) != NULL) {
		if (*token == '\0')
			continue;

		if (strcmp(token, "none") == 0) {
			any_valid = true;
			new_mouse_buttons = 0;
			break;
		}

		/* Find the button value */
		int i;
		for (i = 0; i < ARRAY_SIZE(mouse_button_names); i++) {
			if (strcmp(token, mouse_button_names[i].name) == 0) {
				new_mouse_buttons |=
					mouse_button_names[i].value;
				any_valid = true;
				break;
			}
		}
	}

	kfree(buffer);

	if (!any_valid)
		return -EINVAL;

	mapping->target_mouse_buttons = new_mouse_buttons;

	return zotac_set_button_mapping(&zotac, button_id) ? -EIO : count;
}

static ssize_t mouse_list_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	char *p = buf;
	int i;

	for (i = 0; i < ARRAY_SIZE(mouse_button_names); i++) {
		p += sprintf(p, "%s ", mouse_button_names[i].name);
	}

	if (p > buf)
		*(p - 1) = '\n';
	else
		*p++ = '\n';

	return p - buf;
}
static DEVICE_ATTR_RO_NAMED(mouse_list, "mouse_list");

static ssize_t modifier_list_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	char *p = buf;
	int i;

	for (i = 0; i < ARRAY_SIZE(modifier_names); i++) {
		p += sprintf(p, "%s ", modifier_names[i].name);
	}

	if (p > buf)
		*(p - 1) = '\n';
	else
		*p++ = '\n';

	return p - buf;
}
static DEVICE_ATTR_RO_NAMED(modifier_list, "modifier_list");

/* List attributes for showing available options */
static ssize_t gamepad_list_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	char *p = buf;
	int i;

	for (i = 0; i < ARRAY_SIZE(gamepad_button_names); i++) {
		if (gamepad_button_names[i].id != BUTTON_NONE)
			p += sprintf(p, "%s ", gamepad_button_names[i].name);
	}

	if (p > buf)
		*(p - 1) = '\n';
	else
		*p++ = '\n';

	return p - buf;
}

static ssize_t gamepad_max_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", MAX_GAMEPAD_BUTTONS);
}

static ssize_t keyboard_max_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", MAX_KEYBOARD_KEYS);
}

static ssize_t mouse_max_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	return sprintf(buf, "%d\n", MAX_MOUSE_BUTTONS);
}

static DEVICE_ATTR_RO_NAMED(gamepad_list, "gamepad_list");
static DEVICE_ATTR_RO_NAMED(gamepad_max, "gamepad_max");
static DEVICE_ATTR_RO_NAMED(keyboard_max, "keyboard_max");
static DEVICE_ATTR_RO_NAMED(mouse_max, "mouse_max");

#define DEFINE_BUTTON_REMAP_ATTRS(btn_name, btn_id)                            \
	static ssize_t btn_name##_gamepad_show(                                \
		struct device *dev, struct device_attribute *attr, char *buf)  \
	{                                                                      \
		return gamepad_show(dev, attr, buf, btn_id);                   \
	}                                                                      \
                                                                               \
	static ssize_t btn_name##_gamepad_store(struct device *dev,            \
						struct device_attribute *attr, \
						const char *buf, size_t count) \
	{                                                                      \
		return gamepad_store(dev, attr, buf, count, btn_id);           \
	}                                                                      \
                                                                               \
	static ssize_t btn_name##_modifier_show(                               \
		struct device *dev, struct device_attribute *attr, char *buf)  \
	{                                                                      \
		return modifier_show(dev, attr, buf, btn_id);                  \
	}                                                                      \
                                                                               \
	static ssize_t btn_name##_modifier_store(                              \
		struct device *dev, struct device_attribute *attr,             \
		const char *buf, size_t count)                                 \
	{                                                                      \
		return modifier_store(dev, attr, buf, count, btn_id);          \
	}                                                                      \
                                                                               \
	static ssize_t btn_name##_keyboard_keys_show(                          \
		struct device *dev, struct device_attribute *attr, char *buf)  \
	{                                                                      \
		return keyboard_keys_show(dev, attr, buf, btn_id);             \
	}                                                                      \
                                                                               \
	static ssize_t btn_name##_keyboard_keys_store(                         \
		struct device *dev, struct device_attribute *attr,             \
		const char *buf, size_t count)                                 \
	{                                                                      \
		return keyboard_keys_store(dev, attr, buf, count, btn_id);     \
	}                                                                      \
                                                                               \
	static ssize_t btn_name##_mouse_buttons_show(                          \
		struct device *dev, struct device_attribute *attr, char *buf)  \
	{                                                                      \
		return mouse_buttons_show(dev, attr, buf, btn_id);             \
	}                                                                      \
                                                                               \
	static ssize_t btn_name##_mouse_buttons_store(                         \
		struct device *dev, struct device_attribute *attr,             \
		const char *buf, size_t count)                                 \
	{                                                                      \
		return mouse_buttons_store(dev, attr, buf, count, btn_id);     \
	}                                                                      \
                                                                               \
	static DEVICE_ATTR_RW_NAMED(btn_name##_gamepad, "gamepad");            \
	static DEVICE_ATTR_RW_NAMED(btn_name##_modifier, "modifier");          \
	static DEVICE_ATTR_RW_NAMED(btn_name##_keyboard_keys, "keyboard");     \
	static DEVICE_ATTR_RW_NAMED(btn_name##_mouse_buttons, "mouse");

/* Create all button attribute groups */
DEFINE_BUTTON_REMAP_ATTRS(btn_a, BUTTON_A);
DEFINE_BUTTON_REMAP_ATTRS(btn_b, BUTTON_B);
DEFINE_BUTTON_REMAP_ATTRS(btn_x, BUTTON_X);
DEFINE_BUTTON_REMAP_ATTRS(btn_y, BUTTON_Y);
DEFINE_BUTTON_REMAP_ATTRS(btn_lb, BUTTON_LB);
DEFINE_BUTTON_REMAP_ATTRS(btn_rb, BUTTON_RB);
DEFINE_BUTTON_REMAP_ATTRS(btn_lt, BUTTON_LT);
DEFINE_BUTTON_REMAP_ATTRS(btn_rt, BUTTON_RT);
DEFINE_BUTTON_REMAP_ATTRS(btn_ls, BUTTON_LS);
DEFINE_BUTTON_REMAP_ATTRS(btn_rs, BUTTON_RS);
DEFINE_BUTTON_REMAP_ATTRS(dpad_up, BUTTON_DPAD_UP);
DEFINE_BUTTON_REMAP_ATTRS(dpad_down, BUTTON_DPAD_DOWN);
DEFINE_BUTTON_REMAP_ATTRS(dpad_left, BUTTON_DPAD_LEFT);
DEFINE_BUTTON_REMAP_ATTRS(dpad_right, BUTTON_DPAD_RIGHT);
DEFINE_BUTTON_REMAP_ATTRS(btn_m1, BUTTON_M1);
DEFINE_BUTTON_REMAP_ATTRS(btn_m2, BUTTON_M2);

static int zotac_get_button_turbo(struct zotac_device *zotac)
{
	size_t data_len = 1;
	u8 turbo_byte;
	int ret;

	ret = zotac_send_get_command(zotac, CMD_GET_BUTTON_TURBO, 0, NULL, 0,
				     &turbo_byte, &data_len);
	if (ret < 0)
		return ret;

	if (data_len < 1)
		return -EIO;

	zotac->cfg_data->button_turbo = turbo_byte;
	return 0;
}

static int zotac_set_button_turbo(struct zotac_device *zotac, u8 turbo_byte)
{
	int ret;

	ret = zotac_send_set_command(zotac, CMD_SET_BUTTON_TURBO, 0,
				     &turbo_byte, 1);
	if (ret < 0)
		return ret;

	zotac->cfg_data->button_turbo = turbo_byte;
	return 0;
}

static ssize_t button_turbo_show(struct device *dev,
				 struct device_attribute *attr, char *buf,
				 int btn_pos)
{
	u8 turbo_val;
	int ret;

	ret = zotac_get_button_turbo(&zotac);
	if (ret < 0)
		return ret;

	turbo_val = (zotac.cfg_data->button_turbo >> btn_pos) & 0x01;
	return sprintf(buf, "%d\n", turbo_val);
}

static ssize_t button_turbo_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count, int btn_pos)
{
	u8 turbo_byte;
	int val, ret;

	ret = kstrtoint(buf, 10, &val);
	if (ret)
		return ret;

	if (val != 0 && val != 1)
		return -EINVAL;

	ret = zotac_get_button_turbo(&zotac);
	if (ret < 0)
		return ret;

	turbo_byte = zotac.cfg_data->button_turbo;

	if (val)
		turbo_byte |= (1 << btn_pos);
	else
		turbo_byte &= ~(1 << btn_pos);

	ret = zotac_set_button_turbo(&zotac, turbo_byte);
	if (ret < 0)
		return ret;

	return count;
}

#define DEFINE_BUTTON_TURBO_ATTRS(btn_name, btn_pos)                          \
	static ssize_t btn_##btn_name##_turbo_show(                           \
		struct device *dev, struct device_attribute *attr, char *buf) \
	{                                                                     \
		return button_turbo_show(dev, attr, buf, btn_pos);            \
	}                                                                     \
                                                                              \
	static ssize_t btn_##btn_name##_turbo_store(                          \
		struct device *dev, struct device_attribute *attr,            \
		const char *buf, size_t count)                                \
	{                                                                     \
		return button_turbo_store(dev, attr, buf, count, btn_pos);    \
	}                                                                     \
	static DEVICE_ATTR_RW_NAMED(btn_##btn_name##_turbo, "turbo");

DEFINE_BUTTON_TURBO_ATTRS(a, A_BTN_POS);
DEFINE_BUTTON_TURBO_ATTRS(b, B_BTN_POS);
DEFINE_BUTTON_TURBO_ATTRS(x, X_BTN_POS);
DEFINE_BUTTON_TURBO_ATTRS(y, Y_BTN_POS);
DEFINE_BUTTON_TURBO_ATTRS(lb, LB_BTN_POS);
DEFINE_BUTTON_TURBO_ATTRS(rb, RB_BTN_POS);
DEFINE_BUTTON_TURBO_ATTRS(lt, LT_BTN_POS);
DEFINE_BUTTON_TURBO_ATTRS(rt, RT_BTN_POS);

/* Create attribute groups for buttons with/without turbo */
#define DEFINE_BUTTON_TURBO_GROUP(btn_name, btn_id)                   \
	static struct attribute *btn_name##_main_attrs[] = {          \
		&dev_attr_##btn_name##_turbo.attr, NULL               \
	};                                                            \
	static const struct attribute_group btn_name##_main_group = { \
		.attrs = btn_name##_main_attrs,                       \
	};

#define DEFINE_BUTTON_NO_TURBO_GROUP(btn_name, btn_id)                \
	static struct attribute *btn_name##_main_attrs[] = { NULL };  \
	static const struct attribute_group btn_name##_main_group = { \
		.attrs = btn_name##_main_attrs,                       \
	};

/* Define remap subgroups */
#define DEFINE_BUTTON_REMAP_GROUP(btn_name, btn_id)                    \
	static struct attribute *btn_name##_remap_attrs[] = {          \
		&dev_attr_##btn_name##_gamepad.attr,                   \
		&dev_attr_##btn_name##_modifier.attr,                  \
		&dev_attr_##btn_name##_keyboard_keys.attr,             \
		&dev_attr_##btn_name##_mouse_buttons.attr,             \
		&dev_attr_gamepad_list.attr,                           \
		&dev_attr_gamepad_max.attr,                            \
		&dev_attr_modifier_list.attr,                          \
		&dev_attr_keyboard_list.attr,                          \
		&dev_attr_keyboard_max.attr,                           \
		&dev_attr_mouse_list.attr,                             \
		&dev_attr_mouse_max.attr,                              \
		NULL                                                   \
	};                                                             \
	static const struct attribute_group btn_name##_remap_group = { \
		.name = "remap",                                       \
		.attrs = btn_name##_remap_attrs,                       \
	};

/* Define button directory */
#define DEFINE_BUTTON_GROUP_WITH_TURBO(btn_name, btn_id) \
	DEFINE_BUTTON_TURBO_GROUP(btn_name, btn_id)      \
	DEFINE_BUTTON_REMAP_GROUP(btn_name, btn_id)

#define DEFINE_BUTTON_DIR_WITH_TURBO(btn_name, btn_id)                     \
	{                                                                  \
		.name = #btn_name,                                         \
		.button_id = btn_id,                                       \
		.has_turbo = true,                                         \
		.kobj = NULL,                                              \
		.main_group =                                              \
			(struct attribute_group *)&btn_name##_main_group,  \
		.remap_group =                                             \
			(struct attribute_group *)&btn_name##_remap_group, \
	}

#define DEFINE_BUTTON_GROUP_NO_TURBO(btn_name, btn_id) \
	DEFINE_BUTTON_NO_TURBO_GROUP(btn_name, btn_id) \
	DEFINE_BUTTON_REMAP_GROUP(btn_name, btn_id)

#define DEFINE_BUTTON_DIR_NO_TURBO(btn_name, btn_id)                       \
	{                                                                  \
		.name = #btn_name,                                         \
		.button_id = btn_id,                                       \
		.has_turbo = false,                                        \
		.kobj = NULL,                                              \
		.main_group =                                              \
			(struct attribute_group *)&btn_name##_main_group,  \
		.remap_group =                                             \
			(struct attribute_group *)&btn_name##_remap_group, \
	}

DEFINE_BUTTON_GROUP_WITH_TURBO(btn_a, BUTTON_A);
DEFINE_BUTTON_GROUP_WITH_TURBO(btn_b, BUTTON_B);
DEFINE_BUTTON_GROUP_WITH_TURBO(btn_x, BUTTON_X);
DEFINE_BUTTON_GROUP_WITH_TURBO(btn_y, BUTTON_Y);
DEFINE_BUTTON_GROUP_WITH_TURBO(btn_lb, BUTTON_LB);
DEFINE_BUTTON_GROUP_WITH_TURBO(btn_rb, BUTTON_RB);
DEFINE_BUTTON_GROUP_WITH_TURBO(btn_lt, BUTTON_LT);
DEFINE_BUTTON_GROUP_WITH_TURBO(btn_rt, BUTTON_RT);
DEFINE_BUTTON_GROUP_NO_TURBO(btn_ls, BUTTON_LS);
DEFINE_BUTTON_GROUP_NO_TURBO(btn_rs, BUTTON_RS);
DEFINE_BUTTON_GROUP_NO_TURBO(dpad_up, BUTTON_DPAD_UP);
DEFINE_BUTTON_GROUP_NO_TURBO(dpad_down, BUTTON_DPAD_DOWN);
DEFINE_BUTTON_GROUP_NO_TURBO(dpad_left, BUTTON_DPAD_LEFT);
DEFINE_BUTTON_GROUP_NO_TURBO(dpad_right, BUTTON_DPAD_RIGHT);
DEFINE_BUTTON_GROUP_NO_TURBO(btn_m1, BUTTON_M1);
DEFINE_BUTTON_GROUP_NO_TURBO(btn_m2, BUTTON_M2);

/* Define all button directories */
static struct button_directory button_dirs[] = {
	DEFINE_BUTTON_DIR_WITH_TURBO(btn_a, BUTTON_A),
	DEFINE_BUTTON_DIR_WITH_TURBO(btn_b, BUTTON_B),
	DEFINE_BUTTON_DIR_WITH_TURBO(btn_x, BUTTON_X),
	DEFINE_BUTTON_DIR_WITH_TURBO(btn_y, BUTTON_Y),
	DEFINE_BUTTON_DIR_WITH_TURBO(btn_lb, BUTTON_LB),
	DEFINE_BUTTON_DIR_WITH_TURBO(btn_rb, BUTTON_RB),
	DEFINE_BUTTON_DIR_WITH_TURBO(btn_lt, BUTTON_LT),
	DEFINE_BUTTON_DIR_WITH_TURBO(btn_rt, BUTTON_RT),
	DEFINE_BUTTON_DIR_NO_TURBO(btn_ls, BUTTON_LS),
	DEFINE_BUTTON_DIR_NO_TURBO(btn_rs, BUTTON_RS),
	DEFINE_BUTTON_DIR_NO_TURBO(dpad_up, BUTTON_DPAD_UP),
	DEFINE_BUTTON_DIR_NO_TURBO(dpad_down, BUTTON_DPAD_DOWN),
	DEFINE_BUTTON_DIR_NO_TURBO(dpad_left, BUTTON_DPAD_LEFT),
	DEFINE_BUTTON_DIR_NO_TURBO(dpad_right, BUTTON_DPAD_RIGHT),
	DEFINE_BUTTON_DIR_NO_TURBO(btn_m1, BUTTON_M1),
	DEFINE_BUTTON_DIR_NO_TURBO(btn_m2, BUTTON_M2),
	{ NULL, 0, false, NULL, NULL, NULL } /* Terminator */
};

static int zotac_get_stick_sensitivity(struct zotac_device *zotac,
				       int stick_num, u8 *output_values)
{
	u8 request_data = stick_num;
	u8 temp_values[STICK_SENSITIVITY_SIZE];
	size_t output_len = STICK_SENSITIVITY_SIZE;
	int i, ret;

	ret = zotac_send_get_command(zotac, CMD_GET_STICK_SENSITIVITY, 0,
				     &request_data, 1, temp_values,
				     &output_len);

	if (ret == 0 && output_len == STICK_SENSITIVITY_SIZE) {
		/* Scale from percentage (0-100) to device values (0-255) */
		for (i = 0; i < STICK_SENSITIVITY_SIZE; i++) {
			output_values[i] = temp_values[i] * 255 / 100;
		}
	}

	return ret;
}

static struct stick_sensitivity *
get_sensitivity_for_stick(struct zotac_device *zotac, int stick_num)
{
	if (stick_num == STICK_LEFT)
		return &zotac->cfg_data->left_stick_sensitivity;
	else
		return &zotac->cfg_data->right_stick_sensitivity;
}

static ssize_t curve_response_show(struct device *dev,
				   struct device_attribute *attr, char *buf,
				   int stick_num, int point_index)
{
	struct stick_sensitivity *sensitivity =
		get_sensitivity_for_stick(&zotac, stick_num);
	int base_idx = point_index * 2;

	// Dev input is 0-255, but it outputs 0-100. So we store as 0-255
	int x_pct = sensitivity->values[base_idx] * 100 / 255;
	int y_pct = sensitivity->values[base_idx + 1] * 100 / 255;

	return sprintf(buf, "%d %d\n", x_pct, y_pct);
}

static ssize_t curve_response_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count,
				    int stick_num, int point_index)
{
	struct stick_sensitivity *sensitivity =
		get_sensitivity_for_stick(&zotac, stick_num);
	u8 data[STICK_SENSITIVITY_SIZE + 1]; // +1 for stick ID
	int base_idx = point_index * 2;

	int x_pct, y_pct;
	int ret;

	ret = sscanf(buf, "%d %d", &x_pct, &y_pct);
	if (ret != 2)
		return -EINVAL;

	x_pct = clamp_val(x_pct, 0, 100);
	y_pct = clamp_val(y_pct, 0, 100);

	sensitivity->values[base_idx] = x_pct * 255 / 100;
	sensitivity->values[base_idx + 1] = y_pct * 255 / 100;

	data[STICK_SENSITIVITY_NUM_IDX] = stick_num;

	memcpy(&data[STICK_SENSITIVITY_DATA_IDX], sensitivity->values,
	       STICK_SENSITIVITY_SIZE);

	ret = zotac_send_set_command(&zotac, CMD_SET_STICK_SENSITIVITY, 0, data,
				     sizeof(data));
	if (ret < 0)
		return ret;

	return count;
}

#define DEFINE_CURVE_RESPONSE_ATTRS(stick_name, stick_num, point_num)           \
	static ssize_t stick_##stick_name##_curve_response_##point_num##_show(  \
		struct device *dev, struct device_attribute *attr, char *buf)   \
	{                                                                       \
		return curve_response_show(dev, attr, buf, stick_num,           \
					   point_num - 1);                      \
	}                                                                       \
                                                                                \
	static ssize_t stick_##stick_name##_curve_response_##point_num##_store( \
		struct device *dev, struct device_attribute *attr,              \
		const char *buf, size_t count)                                  \
	{                                                                       \
		return curve_response_store(dev, attr, buf, count, stick_num,   \
					    point_num - 1);                     \
	}                                                                       \
	static DEVICE_ATTR_RW_NAMED(                                            \
		stick_##stick_name##_curve_response_##point_num,                \
		"curve_response_pct_" #point_num);

DEFINE_CURVE_RESPONSE_ATTRS(xy_left, STICK_LEFT, 1)
DEFINE_CURVE_RESPONSE_ATTRS(xy_left, STICK_LEFT, 2)
DEFINE_CURVE_RESPONSE_ATTRS(xy_left, STICK_LEFT, 3)
DEFINE_CURVE_RESPONSE_ATTRS(xy_left, STICK_LEFT, 4)

DEFINE_CURVE_RESPONSE_ATTRS(xy_right, STICK_RIGHT, 1)
DEFINE_CURVE_RESPONSE_ATTRS(xy_right, STICK_RIGHT, 2)
DEFINE_CURVE_RESPONSE_ATTRS(xy_right, STICK_RIGHT, 3)
DEFINE_CURVE_RESPONSE_ATTRS(xy_right, STICK_RIGHT, 4)

static ssize_t axis_xyz_deadzone_index_show(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	return sprintf(buf, "inner outer\n");
}
static DEVICE_ATTR_RO_NAMED(axis_xyz_deadzone_index, "deadzone_index");

static ssize_t axis_xyz_deadzone_show(struct device *dev,
				      struct device_attribute *attr, char *buf,
				      struct deadzone *dz)
{
	return sprintf(buf, "%d %d\n", dz->inner, dz->outer);
}

static int zotac_apply_deadzones(struct zotac_device *zotac,
				 struct deadzone *left_dz,
				 struct deadzone *right_dz, u8 cmd_code)
{
	u8 data[DZ_RESPONSE_SIZE];
	int ret;

	data[DZ_LEFT_INNER_IDX] = left_dz->inner;
	data[DZ_LEFT_OUTER_IDX] = left_dz->outer;
	data[DZ_RIGHT_INNER_IDX] = right_dz->inner;
	data[DZ_RIGHT_OUTER_IDX] = right_dz->outer;

	ret = zotac_send_set_command(zotac, cmd_code, 0, data, sizeof(data));

	return ret;
}

static ssize_t axis_xyz_deadzone_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count,
				       struct deadzone *dz)
{
	struct zotac_cfg_data *cfg = zotac.cfg_data;
	int inner, outer;
	u8 cmd_code;
	int ret;

	ret = sscanf(buf, "%d %d", &inner, &outer);
	if (ret != 2)
		return -EINVAL;

	if (inner < 0 || inner > 100 || outer < 0 || outer > 100)
		return -EINVAL;

	dz->inner = inner;
	dz->outer = outer;

	/* Determine which command to use based on which deadzone is being modified */
	if (dz == &cfg->ls_dz || dz == &cfg->rs_dz) {
		cmd_code = CMD_SET_STICK_DEADZONES;
		ret = zotac_apply_deadzones(&zotac, &cfg->ls_dz, &cfg->rs_dz,
					    cmd_code);
	} else {
		cmd_code = CMD_SET_TRIGGER_DEADZONES;
		ret = zotac_apply_deadzones(&zotac, &cfg->lt_dz, &cfg->rt_dz,
					    cmd_code);
	}

	if (ret < 0)
		return ret;

	return count;
}

#define DEFINE_DEADZONE_HANDLERS(axis_name, dz_field)                         \
	static ssize_t axis_##axis_name##_deadzone_show(                      \
		struct device *dev, struct device_attribute *attr, char *buf) \
	{                                                                     \
		return axis_xyz_deadzone_show(dev, attr, buf,                 \
					      &zotac.cfg_data->dz_field);    \
	}                                                                     \
                                                                              \
	static ssize_t axis_##axis_name##_deadzone_store(                     \
		struct device *dev, struct device_attribute *attr,            \
		const char *buf, size_t count)                                \
	{                                                                     \
		return axis_xyz_deadzone_store(dev, attr, buf, count,         \
					       &zotac.cfg_data->dz_field);   \
	}                                                                     \
	static DEVICE_ATTR_RW_NAMED(axis_##axis_name##_deadzone, "deadzone");

#define DEFINE_XY_AXIS_ATTR_GROUP(axis_name)                                  \
	static struct attribute *axis_##axis_name##_attrs[] = {               \
		&dev_attr_axis_##axis_name##_deadzone.attr,                   \
		&dev_attr_stick_##axis_name##_curve_response_1.attr,          \
		&dev_attr_stick_##axis_name##_curve_response_2.attr,          \
		&dev_attr_stick_##axis_name##_curve_response_3.attr,          \
		&dev_attr_stick_##axis_name##_curve_response_4.attr,          \
		&dev_attr_axis_xyz_deadzone_index.attr,                       \
		NULL                                                          \
	};                                                                    \
                                                                              \
	static const struct attribute_group axis_##axis_name##_attr_group = { \
		.name = "axis_" #axis_name,                                   \
		.attrs = axis_##axis_name##_attrs,                            \
	};

#define DEFINE_Z_AXIS_ATTR_GROUP(axis_name)                                   \
	static struct attribute *axis_##axis_name##_attrs[] = {               \
		&dev_attr_axis_##axis_name##_deadzone.attr,                   \
		&dev_attr_axis_xyz_deadzone_index.attr, NULL                  \
	};                                                                    \
                                                                              \
	static const struct attribute_group axis_##axis_name##_attr_group = { \
		.name = "axis_" #axis_name,                                   \
		.attrs = axis_##axis_name##_attrs,                            \
	};

DEFINE_DEADZONE_HANDLERS(xy_left, ls_dz);
DEFINE_DEADZONE_HANDLERS(xy_right, rs_dz);
DEFINE_DEADZONE_HANDLERS(z_left, lt_dz);
DEFINE_DEADZONE_HANDLERS(z_right, rt_dz);

DEFINE_XY_AXIS_ATTR_GROUP(xy_left);
DEFINE_XY_AXIS_ATTR_GROUP(xy_right);
DEFINE_Z_AXIS_ATTR_GROUP(z_left);
DEFINE_Z_AXIS_ATTR_GROUP(z_right);

static ssize_t vibration_intensity_index_show(struct device *dev,
					      struct device_attribute *attr,
					      char *buf)
{
	return sprintf(buf,
		       "trigger_left trigger_right rumble_left rumble_right\n");
}
static DEVICE_ATTR_RO_NAMED(vibration_intensity_index,
			    "vibration_intensity_index");

static ssize_t vibration_intensity_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	u8 data[VIB_RESPONSE_SIZE];
	size_t data_len = sizeof(data);
	int ret;

	ret = zotac_send_get_command(&zotac, CMD_GET_VIBRATION_STRENGTH, 0, NULL,
				     0, data, &data_len);
	if (ret < 0)
		return ret;

	if (data_len < VIB_RESPONSE_SIZE) {
		dev_err(&zotac.hdev->dev,
			"Incomplete vibration data received: %zu bytes\n",
			data_len);
		return -EIO;
	}

	return sprintf(buf, "%d %d %d %d\n", data[VIB_LEFT_TRIGGER_IDX],
		       data[VIB_RIGHT_TRIGGER_IDX], data[VIB_LEFT_RUMBLE_IDX],
		       data[VIB_RIGHT_RUMBLE_IDX]);
}

static ssize_t vibration_intensity_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	u8 data[VIB_RESPONSE_SIZE];
	int lt, rt, lr, rr;
	int ret;

	ret = sscanf(buf, "%d %d %d %d", &lt, &rt, &lr, &rr);
	if (ret != 4)
		return -EINVAL;

	data[VIB_LEFT_TRIGGER_IDX] = clamp_val(lt, 0, 100);
	data[VIB_RIGHT_TRIGGER_IDX] = clamp_val(rt, 0, 100);
	data[VIB_LEFT_RUMBLE_IDX] = clamp_val(lr, 0, 100);
	data[VIB_RIGHT_RUMBLE_IDX] = clamp_val(rr, 0, 100);

	ret = zotac_send_set_command(&zotac, CMD_SET_VIBRATION_STRENGTH, 0, data,
				     sizeof(data));
	if (ret < 0)
		return ret;

	return count;
}
static DEVICE_ATTR_RW(vibration_intensity);

static ssize_t mouse_speed_max_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", MOUSE_SPEED_MAX);
}
static DEVICE_ATTR_RO_NAMED(mouse_speed_max, "mouse_speed_max");

static ssize_t mouse_speed_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	int speed;

	speed = zotac_send_get_byte(&zotac, CMD_GET_MOUSE_SPEED, 0, NULL, 0);
	if (speed < 0)
		return speed;

	return sprintf(buf, "%d\n", speed);
}

static ssize_t mouse_speed_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	int speed_val;
	u8 speed;
	int ret;

	ret = kstrtoint(buf, 10, &speed_val);
	if (ret)
		return ret;

	if (speed_val < MOUSE_SPEED_MIN || speed_val > MOUSE_SPEED_MAX)
		return -EINVAL;

	speed = (u8)speed_val;
	ret = zotac_send_set_command(&zotac, CMD_SET_MOUSE_SPEED, 0, &speed, 1);
	if (ret < 0)
		return ret;

	return count;
}
static DEVICE_ATTR_RW(mouse_speed);

static ssize_t motor_test_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t count)
{
	u8 data[MOTOR_TEST_SIZE] = { 0 };

	int left_trigger, right_trigger, left_rumble, right_rumble;
	int ret;

	ret = sscanf(buf, "%d %d %d %d", &left_trigger, &right_trigger,
		     &left_rumble, &right_rumble);
	if (ret != 4)
		return -EINVAL;

	left_trigger = clamp_val(left_trigger, 0, 100);
	right_trigger = clamp_val(right_trigger, 0, 100);
	left_rumble = clamp_val(left_rumble, 0, 100);
	right_rumble = clamp_val(right_rumble, 0, 100);

	data[0] = (u8)left_trigger; /* Left Trigger Motor */
	data[1] = (u8)right_trigger; /* Right Trigger Motor */
	data[2] = (u8)left_rumble; /* Left Rumble Motor */
	data[3] = (u8)right_rumble; /* Right Rumble Motor */

	ret = zotac_send_set_command(&zotac, CMD_MOTOR_TEST, 0, data,
				     MOTOR_TEST_SIZE);
	if (ret < 0)
		return ret;

	return count;
}
static DEVICE_ATTR_WO(motor_test);

static ssize_t motor_test_index_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	return sprintf(buf,
		       "left_trigger right_trigger left_rumble right_rumble\n");
}
static DEVICE_ATTR_RO_NAMED(motor_test_index, "motor_test_index");

static ssize_t profile_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	int profile;

	profile = zotac_send_get_byte(&zotac, CMD_GET_PROFILE, 0, NULL, 0);
	if (profile < 0)
		return profile;

	return sprintf(buf, "%d\n", profile);
}

static ssize_t profile_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	int profile_id, ret;
	u8 profile;

	ret = kstrtoint(buf, 10, &profile_id);
	if (ret)
		return ret;

	if (profile_id > PROFILE_SECONDARY)
		return -EINVAL;

	profile = (u8)profile_id;
	ret = zotac_send_set_command(&zotac, CMD_SET_PROFILE, 0, &profile, 1);
	if (ret)
		return ret;

	ret = zotac_cfg_refresh(&zotac);
	if (ret)
		return ret;

	return count;
}
static DEVICE_ATTR_RW_NAMED(profile, "current");

static ssize_t profile_count_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{

	return sprintf(buf, "%d\n",
		       zotac_send_get_byte(&zotac, CMD_GET_PROFILE_NUM, 0, NULL,
					   0));
}
static DEVICE_ATTR_RO_NAMED(profile_count, "count");

/* The device resets and reconnects */
static ssize_t restore_profile_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	int val, ret;

	ret = kstrtoint(buf, 10, &val);
	if (ret)
		return ret;

	if (val != 1)
		return -EINVAL;

	dev_warn(dev, "Restoring profile, the device will reset and reconnect");
	ret = zotac_send_set_command(&zotac, CMD_RESTORE_PROFILE, 0, NULL, 0);
	if (ret)
		return ret;

	return count;
}
static DEVICE_ATTR_WO_NAMED(restore_profile, "restore");

static struct attribute *zotac_profile_attrs[] = {
	&dev_attr_profile.attr, &dev_attr_profile_count.attr,
	&dev_attr_restore_profile.attr, NULL
};

static const struct attribute_group zotac_profile_attr_group = {
	.name = "profile",
	.attrs = zotac_profile_attrs,
};

static ssize_t save_config_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	int val, ret;

	ret = kstrtoint(buf, 10, &val);
	if (ret)
		return ret;

	if (val != 1)
		return -EINVAL;

	ret = zotac_send_set_command(&zotac, CMD_SAVE_CONFIG, 0, NULL, 0);
	if (ret)
		return ret;

	return count;
}
static DEVICE_ATTR_WO(save_config);

static ssize_t qam_mode_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	if (!zotac.gamepad)
		return -ENODEV;

	return sprintf(buf, "%i\n", zotac.gamepad->qam_mode);
}

static ssize_t qam_mode_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	u8 value;
	int ret;

	if (!zotac.gamepad)
		return -ENODEV;

	ret = kstrtou8(buf, 10, &value);
	if (ret)
		return ret;

	if (value >= QAM_MODE_LENGTH)
		return -EINVAL;

	zotac.gamepad->qam_mode = value;

	return count;
}
DEVICE_ATTR_RW(qam_mode);

static struct attribute *zotac_root_attrs[] = {
	&dev_attr_save_config.attr,
	&dev_attr_qam_mode.attr,
	&dev_attr_vibration_intensity.attr,
	&dev_attr_vibration_intensity_index.attr,
	&dev_attr_mouse_speed.attr,
	&dev_attr_mouse_speed_max.attr,
	&dev_attr_motor_test.attr,
	&dev_attr_motor_test_index.attr,
	NULL
};

static const struct attribute_group zotac_root_attr_group = {
	.attrs = zotac_root_attrs,
};

static const struct attribute_group *zotac_top_level_attr_groups[] = {
	&zotac_profile_attr_group,
	&zotac_root_attr_group,
	&axis_xy_left_attr_group,
	&axis_xy_right_attr_group,
	&axis_z_left_attr_group,
	&axis_z_right_attr_group,
	NULL
};

int zotac_register_sysfs(struct zotac_device *zotac)
{
	struct device *dev;
	int ret, i;

	if (!zotac || !zotac->hdev)
		return -ENODEV;

	dev = &zotac->hdev->dev;

	ret = sysfs_create_groups(&dev->kobj, zotac_top_level_attr_groups);
	if (ret) {
		dev_err(dev, "Failed to create top-level sysfs groups: %d\n",
			ret);
		return ret;
	}

	for (i = 0; button_dirs[i].name != NULL; i++) {
		struct button_directory *btn_dir = &button_dirs[i];

		/* Create the button directory kobject */
		btn_dir->kobj =
			kobject_create_and_add(btn_dir->name, &dev->kobj);
		if (!btn_dir->kobj) {
			dev_err(dev, "Failed to create kobject for %s\n",
				btn_dir->name);
			ret = -ENOMEM;
			goto cleanup;
		}

		/* Add the main attributes to the button directory */
		ret = sysfs_create_group(btn_dir->kobj, btn_dir->main_group);
		if (ret) {
			dev_err(dev, "Failed to create main group for %s: %d\n",
				btn_dir->name, ret);
			goto cleanup;
		}

		/* Add the remap subgroup to the button directory */
		ret = sysfs_create_group(btn_dir->kobj, btn_dir->remap_group);
		if (ret) {
			dev_err(dev,
				"Failed to create remap group for %s: %d\n",
				btn_dir->name, ret);
			goto cleanup;
		}
	}

	return 0;

cleanup:
	/* Clean up on error */
	for (i = 0; button_dirs[i].name != NULL; i++) {
		if (button_dirs[i].kobj) {
			kobject_put(button_dirs[i].kobj);
			button_dirs[i].kobj = NULL;
		}
	}
	sysfs_remove_groups(&dev->kobj, zotac_top_level_attr_groups);
	return ret;
}

void zotac_unregister_sysfs(struct zotac_device *zotac)
{
	int i;
	struct device *dev;

	if (!zotac || !zotac->hdev) {
		pr_err("Invalid zotac device in unregister_sysfs\n");
		return;
	}

	dev = &zotac->hdev->dev;

	/* Remove button directories and their attributes */
	for (i = 0; button_dirs[i].name != NULL; i++) {
		if (button_dirs[i].kobj) {
			kobject_put(button_dirs[i].kobj);
			button_dirs[i].kobj = NULL;
		}
	}

	sysfs_remove_groups(&dev->kobj, zotac_top_level_attr_groups);
}

/**
 * zotac_cfg_refresh - Refresh all configuration data from the device
 * @zotac: The zotac device to refresh
 *
 * This function queries the device for all current configuration and
 * updates the driver's cached values. It should be called during
 * initialization and after profile changes or restores.
 */
int zotac_cfg_refresh(struct zotac_device *zotac)
{
	struct zotac_cfg_data *cfg;
	u8 data[DZ_RESPONSE_SIZE];
	size_t data_len = sizeof(data);
	int ret, i;

	if (!zotac->cfg_data)
		return -EINVAL;

	cfg = zotac->cfg_data;

	ret = zotac_send_get_command(zotac, CMD_GET_STICK_DEADZONES, 0, NULL, 0,
				     data, &data_len);
	if (ret == 0 && data_len >= DZ_RESPONSE_SIZE) {
		cfg->ls_dz.inner = data[DZ_LEFT_INNER_IDX];
		cfg->ls_dz.outer = data[DZ_LEFT_OUTER_IDX];
		cfg->rs_dz.inner = data[DZ_RIGHT_INNER_IDX];
		cfg->rs_dz.outer = data[DZ_RIGHT_OUTER_IDX];
	} else {
		dev_info(
			&zotac->hdev->dev,
			"Could not retrieve stick deadzone settings, using defaults\n");
		cfg->ls_dz.inner = 0;
		cfg->ls_dz.outer = 100;
		cfg->rs_dz.inner = 0;
		cfg->rs_dz.outer = 100;
	}

	ret = zotac_send_get_command(zotac, CMD_GET_TRIGGER_DEADZONES, 0, NULL,
				     0, data, &data_len);
	if (ret == 0 && data_len >= DZ_RESPONSE_SIZE) {
		cfg->lt_dz.inner = data[DZ_LEFT_INNER_IDX];
		cfg->lt_dz.outer = data[DZ_LEFT_OUTER_IDX];
		cfg->rt_dz.inner = data[DZ_RIGHT_INNER_IDX];
		cfg->rt_dz.outer = data[DZ_RIGHT_OUTER_IDX];
	} else {
		dev_info(
			&zotac->hdev->dev,
			"Could not retrieve trigger deadzone settings, using defaults\n");
		cfg->lt_dz.inner = 0;
		cfg->lt_dz.outer = 100;
		cfg->rt_dz.inner = 0;
		cfg->rt_dz.outer = 100;
	}

	ret = zotac_get_stick_sensitivity(zotac, STICK_LEFT,
					  cfg->left_stick_sensitivity.values);
	if (ret < 0) {
		dev_info(
			&zotac->hdev->dev,
			"Could not retrieve left stick sensitivity, using defaults\n");
		/* Initialize with linear response: 25%, 50%, 75%, 100% */
		cfg->left_stick_sensitivity.values[0] = 64; /* X1 = 25% */
		cfg->left_stick_sensitivity.values[1] = 64; /* Y1 = 25% */
		cfg->left_stick_sensitivity.values[2] = 128; /* X2 = 50% */
		cfg->left_stick_sensitivity.values[3] = 128; /* Y2 = 50% */
		cfg->left_stick_sensitivity.values[4] = 192; /* X3 = 75% */
		cfg->left_stick_sensitivity.values[5] = 192; /* Y3 = 75% */
		cfg->left_stick_sensitivity.values[6] = 255; /* X4 = 100% */
		cfg->left_stick_sensitivity.values[7] = 255; /* Y4 = 100% */
	}

	ret = zotac_get_stick_sensitivity(zotac, STICK_RIGHT,
					  cfg->right_stick_sensitivity.values);
	if (ret < 0) {
		dev_info(
			&zotac->hdev->dev,
			"Could not retrieve right stick sensitivity, using defaults\n");
		/* Copy the left stick values which may be initialized or linear defaults */
		memcpy(cfg->right_stick_sensitivity.values,
		       cfg->left_stick_sensitivity.values,
		       sizeof(cfg->right_stick_sensitivity.values));
	}

	ret = zotac_get_button_turbo(zotac);
	if (ret < 0) {
		dev_info(
			&zotac->hdev->dev,
			"Could not retrieve button turbo settings, using defaults\n");
		cfg->button_turbo = 0; /* Default: no turbo buttons */
	}

	for (i = 1; i <= BUTTON_MAX; i++) {
		u8 request_data = i;
		u8 response_data[BTN_MAP_RESPONSE_MIN_SIZE];
		size_t response_len = sizeof(response_data);

		/* Set default values first */
		cfg->button_mappings[i].target_gamepad_buttons = 0;
		cfg->button_mappings[i].target_modifier_keys = 0;
		memset(cfg->button_mappings[i].target_keyboard_keys, 0,
		       MAX_KEYBOARD_KEYS);
		cfg->button_mappings[i].target_mouse_buttons = 0;

		ret = zotac_send_get_command(zotac, CMD_GET_BUTTON_MAPPING, 0,
					     &request_data, 1, response_data,
					     &response_len);
		if (ret == 0 && response_len >= BTN_MAP_RESPONSE_MIN_SIZE) {
			memcpy(&cfg->button_mappings[i].target_gamepad_buttons,
			       &response_data[BTN_MAP_GAMEPAD_START_IDX],
			       BTN_MAP_GAMEPAD_SIZE);

			cfg->button_mappings[i].target_modifier_keys =
				response_data[BTN_MAP_MODIFIER_IDX];

			memcpy(cfg->button_mappings[i].target_keyboard_keys,
			       &response_data[BTN_MAP_KEYBOARD_START_IDX],
			       BTN_MAP_KEYBOARD_SIZE);

			cfg->button_mappings[i].target_mouse_buttons =
				response_data[BTN_MAP_MOUSE_IDX];
		} else {
			dev_info(
				&zotac->hdev->dev,
				"Could not retrieve button %d mapping, using defaults\n",
				i);
		}
	}

	return 0;
}

/**
 * zotac_cfg_setup - Allocate and initialize config data structure
 * @zotac: The zotac device to set up
 *
 * This function allocates the config data structure and initializes
 * the mutex and sequence number. It should be called once during
 * driver initialization.
 */
static int zotac_cfg_setup(struct zotac_device *zotac)
{
	struct zotac_cfg_data *cfg;

	if (!zotac)
		return -EINVAL;

	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!cfg)
		return -ENOMEM;

	mutex_init(&cfg->command_mutex);
	cfg->sequence_num = 0;
	zotac->cfg_data = cfg;

	zotac_log_device_info(zotac);

	return 0;
}

/**
 * zotac_cfg_init - Initialize the device configuration system
 * @zotac: The zotac device to initialize
 *
 * This function sets up the configuration system and loads the initial
 * configuration from the device.
 */
int zotac_cfg_init(struct zotac_device *zotac)
{
	int ret;

	ret = zotac_cfg_setup(zotac);
	if (ret < 0)
		return ret;

	ret = zotac_cfg_refresh(zotac);
	if (ret < 0) {
		/* If refresh fails, still keep the structure but log an error */
		dev_err(&zotac->hdev->dev,
			"Failed to load initial configuration: %d\n", ret);
	}

	return 0;
}

void zotac_cfg_cleanup(struct zotac_device *zotac)
{
	if (!zotac || !zotac->cfg_data)
		return;

	kfree(zotac->cfg_data);
	zotac->cfg_data = NULL;
}
