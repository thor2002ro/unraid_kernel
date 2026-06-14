// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  HID driver for Asus ROG laptops and Ally
 *
 *  Copyright (c) 2023 Luke Jones <luke@ljones.dev>
 */

#include "linux/compiler_attributes.h"
#include "linux/device.h"
#include <linux/platform_data/x86/asus-wmi.h>
#include <linux/platform_device.h>
#include "linux/pm.h"
#include "linux/printk.h"
#include "linux/slab.h"
#include <linux/hid.h>
#include <linux/types.h>
#include <linux/usb.h>
#include <linux/leds.h>
#include <linux/led-class-multicolor.h>

#include "hid-ids.h"
#include "hid-asus.h"
#include "hid-asus-ally.h"

#define DEBUG

#define READY_MAX_TRIES 3
#define FEATURE_REPORT_ID 0x0d
#define FEATURE_ROG_ALLY_REPORT_ID 0x5a
#define FEATURE_ROG_ALLY_CODE_PAGE 0xD1
#define FEATURE_ROG_ALLY_REPORT_SIZE 64
#define ALLY_X_INPUT_REPORT_USB 0x0B
#define ALLY_X_INPUT_REPORT_USB_SIZE 16

#define ROG_ALLY_REPORT_SIZE 64
#define ROG_ALLY_X_MIN_MCU 313
#define ROG_ALLY_MIN_MCU 319

#define FEATURE_KBD_LED_REPORT_ID1 0x5d
#define FEATURE_KBD_LED_REPORT_ID2 0x5e

#define BTN_DATA_LEN 11;
#define BTN_CODE_BYTES_LEN 8

static const u8 EC_INIT_STRING[] = { 0x5A, 'A', 'S', 'U', 'S', ' ', 'T', 'e','c', 'h', '.', 'I', 'n', 'c', '.', '\0' };
static const u8 EC_MODE_LED_APPLY[] = { 0x5A, 0xB4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
static const u8 EC_MODE_LED_SET[] = { 0x5A, 0xB5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
static const u8 FORCE_FEEDBACK_OFF[] = { 0x0D, 0x0F, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0xEB };

static const struct hid_device_id rog_ally_devices[] = {
	{ HID_USB_DEVICE(USB_VENDOR_ID_ASUSTEK, USB_DEVICE_ID_ASUSTEK_ROG_NKEY_ALLY) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ASUSTEK, USB_DEVICE_ID_ASUSTEK_ROG_NKEY_ALLY_X) },
	{}
};

struct btn_code_map {
	u64 code;
	const char *name;
};

static const struct btn_code_map ally_btn_codes[] = {
	{ 0, "NONE" },
	/* Gamepad button codes */
	{ BTN_PAD_A, "PAD_A" },
	{ BTN_PAD_B, "PAD_B" },
	{ BTN_PAD_X, "PAD_X" },
	{ BTN_PAD_Y, "PAD_Y" },
	{ BTN_PAD_LB, "PAD_LB" },
	{ BTN_PAD_RB, "PAD_RB" },
	{ BTN_PAD_LS, "PAD_LS" },
	{ BTN_PAD_RS, "PAD_RS" },
	{ BTN_PAD_DPAD_UP, "PAD_DPAD_UP" },
	{ BTN_PAD_DPAD_DOWN, "PAD_DPAD_DOWN" },
	{ BTN_PAD_DPAD_LEFT, "PAD_DPAD_LEFT" },
	{ BTN_PAD_DPAD_RIGHT, "PAD_DPAD_RIGHT" },
	{ BTN_PAD_VIEW, "PAD_VIEW" },
	{ BTN_PAD_MENU, "PAD_MENU" },
	{ BTN_PAD_XBOX, "PAD_XBOX" },

	/* Triggers mapped to keyboard codes */
	{ BTN_KB_M2, "KB_M2" },
	{ BTN_KB_M1, "KB_M1" },
	{ BTN_KB_ESC, "KB_ESC" },
	{ BTN_KB_F1, "KB_F1" },
	{ BTN_KB_F2, "KB_F2" },
	{ BTN_KB_F3, "KB_F3" },
	{ BTN_KB_F4, "KB_F4" },
	{ BTN_KB_F5, "KB_F5" },
	{ BTN_KB_F6, "KB_F6" },
	{ BTN_KB_F7, "KB_F7" },
	{ BTN_KB_F8, "KB_F8" },
	{ BTN_KB_F9, "KB_F9" },
	{ BTN_KB_F10, "KB_F10" },
	{ BTN_KB_F11, "KB_F11" },
	{ BTN_KB_F12, "KB_F12" },
	{ BTN_KB_F14, "KB_F14" },
	{ BTN_KB_F15, "KB_F15" },
	{ BTN_KB_BACKTICK, "KB_BACKTICK" },
	{ BTN_KB_1, "KB_1" },
	{ BTN_KB_2, "KB_2" },
	{ BTN_KB_3, "KB_3" },
	{ BTN_KB_4, "KB_4" },
	{ BTN_KB_5, "KB_5" },
	{ BTN_KB_6, "KB_6" },
	{ BTN_KB_7, "KB_7" },
	{ BTN_KB_8, "KB_8" },
	{ BTN_KB_9, "KB_9" },
	{ BTN_KB_0, "KB_0" },
	{ BTN_KB_HYPHEN, "KB_HYPHEN" },
	{ BTN_KB_EQUALS, "KB_EQUALS" },
	{ BTN_KB_BACKSPACE, "KB_BACKSPACE" },
	{ BTN_KB_TAB, "KB_TAB" },
	{ BTN_KB_Q, "KB_Q" },
	{ BTN_KB_W, "KB_W" },
	{ BTN_KB_E, "KB_E" },
	{ BTN_KB_R, "KB_R" },
	{ BTN_KB_T, "KB_T" },
	{ BTN_KB_Y, "KB_Y" },
	{ BTN_KB_U, "KB_U" },
	{ BTN_KB_O, "KB_O" },
	{ BTN_KB_P, "KB_P" },
	{ BTN_KB_LBRACKET, "KB_LBRACKET" },
	{ BTN_KB_RBRACKET, "KB_RBRACKET" },
	{ BTN_KB_BACKSLASH, "KB_BACKSLASH" },
	{ BTN_KB_CAPS, "KB_CAPS" },
	{ BTN_KB_A, "KB_A" },
	{ BTN_KB_S, "KB_S" },
	{ BTN_KB_D, "KB_D" },
	{ BTN_KB_F, "KB_F" },
	{ BTN_KB_G, "KB_G" },
	{ BTN_KB_H, "KB_H" },
	{ BTN_KB_J, "KB_J" },
	{ BTN_KB_K, "KB_K" },
	{ BTN_KB_L, "KB_L" },
	{ BTN_KB_SEMI, "KB_SEMI" },
	{ BTN_KB_QUOTE, "KB_QUOTE" },
	{ BTN_KB_RET, "KB_RET" },
	{ BTN_KB_LSHIFT, "KB_LSHIFT" },
	{ BTN_KB_Z, "KB_Z" },
	{ BTN_KB_X, "KB_X" },
	{ BTN_KB_C, "KB_C" },
	{ BTN_KB_V, "KB_V" },
	{ BTN_KB_B, "KB_B" },
	{ BTN_KB_N, "KB_N" },
	{ BTN_KB_M, "KB_M" },
	{ BTN_KB_COMMA, "KB_COMMA" },
	{ BTN_KB_PERIOD, "KB_PERIOD" },
	{ BTN_KB_RSHIFT, "KB_RSHIFT" },
	{ BTN_KB_LCTL, "KB_LCTL" },
	{ BTN_KB_META, "KB_META" },
	{ BTN_KB_LALT, "KB_LALT" },
	{ BTN_KB_SPACE, "KB_SPACE" },
	{ BTN_KB_RALT, "KB_RALT" },
	{ BTN_KB_MENU, "KB_MENU" },
	{ BTN_KB_RCTL, "KB_RCTL" },
	{ BTN_KB_PRNTSCN, "KB_PRNTSCN" },
	{ BTN_KB_SCRLCK, "KB_SCRLCK" },
	{ BTN_KB_PAUSE, "KB_PAUSE" },
	{ BTN_KB_INS, "KB_INS" },
	{ BTN_KB_HOME, "KB_HOME" },
	{ BTN_KB_PGUP, "KB_PGUP" },
	{ BTN_KB_DEL, "KB_DEL" },
	{ BTN_KB_END, "KB_END" },
	{ BTN_KB_PGDWN, "KB_PGDWN" },
	{ BTN_KB_UP_ARROW, "KB_UP_ARROW" },
	{ BTN_KB_DOWN_ARROW, "KB_DOWN_ARROW" },
	{ BTN_KB_LEFT_ARROW, "KB_LEFT_ARROW" },
	{ BTN_KB_RIGHT_ARROW, "KB_RIGHT_ARROW" },

	/* Numpad mappings */
	{ BTN_NUMPAD_LOCK, "NUMPAD_LOCK" },
	{ BTN_NUMPAD_FWDSLASH, "NUMPAD_FWDSLASH" },
	{ BTN_NUMPAD_ASTERISK, "NUMPAD_ASTERISK" },
	{ BTN_NUMPAD_HYPHEN, "NUMPAD_HYPHEN" },
	{ BTN_NUMPAD_0, "NUMPAD_0" },
	{ BTN_NUMPAD_1, "NUMPAD_1" },
	{ BTN_NUMPAD_2, "NUMPAD_2" },
	{ BTN_NUMPAD_3, "NUMPAD_3" },
	{ BTN_NUMPAD_4, "NUMPAD_4" },
	{ BTN_NUMPAD_5, "NUMPAD_5" },
	{ BTN_NUMPAD_6, "NUMPAD_6" },
	{ BTN_NUMPAD_7, "NUMPAD_7" },
	{ BTN_NUMPAD_8, "NUMPAD_8" },
	{ BTN_NUMPAD_9, "NUMPAD_9" },
	{ BTN_NUMPAD_PLUS, "NUMPAD_PLUS" },
	{ BTN_NUMPAD_ENTER, "NUMPAD_ENTER" },
	{ BTN_NUMPAD_PERIOD, "NUMPAD_PERIOD" },

	/* Mouse mappings */
	{ BTN_MOUSE_LCLICK, "MOUSE_LCLICK" },
	{ BTN_MOUSE_RCLICK, "MOUSE_RCLICK" },
	{ BTN_MOUSE_MCLICK, "MOUSE_MCLICK" },
	{ BTN_MOUSE_WHEEL_UP, "MOUSE_WHEEL_UP" },
	{ BTN_MOUSE_WHEEL_DOWN, "MOUSE_WHEEL_DOWN" },

	/* Media mappings */
	{ BTN_MEDIA_SCREENSHOT, "MEDIA_SCREENSHOT" },
	{ BTN_MEDIA_SHOW_KEYBOARD, "MEDIA_SHOW_KEYBOARD" },
	{ BTN_MEDIA_SHOW_DESKTOP, "MEDIA_SHOW_DESKTOP" },
	{ BTN_MEDIA_START_RECORDING, "MEDIA_START_RECORDING" },
	{ BTN_MEDIA_MIC_OFF, "MEDIA_MIC_OFF" },
	{ BTN_MEDIA_VOL_DOWN, "MEDIA_VOL_DOWN" },
	{ BTN_MEDIA_VOL_UP, "MEDIA_VOL_UP" },
};
static const size_t keymap_len = ARRAY_SIZE(ally_btn_codes);

/* byte_array must be >= 8 in length */
static void btn_code_to_byte_array(u64 keycode, u8 *byte_array)
{
	/* Convert the u64 to bytes[8] */
	for (int i = 0; i < 8; ++i) {
		byte_array[i] = (keycode >> (56 - 8 * i)) & 0xFF;
	}
}

static u64 name_to_btn(const char *name)
{
	int len = strcspn(name, "\n");
	for (size_t i = 0; i < keymap_len; ++i) {
		if (strncmp(ally_btn_codes[i].name, name, len) == 0) {
			return ally_btn_codes[i].code;
		}
	}
	return -EINVAL;
}

static const char* btn_to_name(u64 key)
{
	for (size_t i = 0; i < keymap_len; ++i) {
		if (ally_btn_codes[i].code == key) {
			return ally_btn_codes[i].name;
		}
	}
	return NULL;
}

struct btn_data {
	u64 button;
	u64 macro;
	bool turbo;
};

struct btn_mapping {
	struct btn_data btn_a;
	struct btn_data btn_b;
	struct btn_data btn_x;
	struct btn_data btn_y;
	struct btn_data btn_lb;
	struct btn_data btn_rb;
	struct btn_data btn_ls;
	struct btn_data btn_rs;
	struct btn_data btn_lt;
	struct btn_data btn_rt;
	struct btn_data dpad_up;
	struct btn_data dpad_down;
	struct btn_data dpad_left;
	struct btn_data dpad_right;
	struct btn_data btn_view;
	struct btn_data btn_menu;
	struct btn_data btn_m1;
	struct btn_data btn_m2;
};

struct deadzone {
	u8 inner;
	u8 outer;
};

struct response_curve {
	uint8_t move_pct_1;
	uint8_t response_pct_1;
	uint8_t move_pct_2;
	uint8_t response_pct_2;
	uint8_t move_pct_3;
	uint8_t response_pct_3;
	uint8_t move_pct_4;
	uint8_t response_pct_4;
} __packed;

struct js_axis_calibrations {
	uint16_t left_y_stable;
	uint16_t left_y_min;
	uint16_t left_y_max;
	uint16_t left_x_stable;
	uint16_t left_x_min;
	uint16_t left_x_max;
	uint16_t right_y_stable;
	uint16_t right_y_min;
	uint16_t right_y_max;
	uint16_t right_x_stable;
	uint16_t right_x_min;
	uint16_t right_x_max;
} __packed;

struct tr_axis_calibrations {
	uint16_t left_stable;
	uint16_t left_max;
	uint16_t right_stable;
	uint16_t right_max;
} __packed;

/* ROG Ally has many settings related to the gamepad, all using the same n-key endpoint */
struct ally_gamepad_cfg {
	struct hid_device *hdev;
	struct input_dev *input;

	enum xpad_mode mode;
	/*
	 * index: [mode]
	 */
	struct btn_mapping key_mapping[xpad_mode_mouse];
	/*
	 * index: left, right
	 * max: 64
	 */
	u8 vibration_intensity[2];

	/* deadzones */
	struct deadzone ls_dz; // left stick
	struct deadzone rs_dz; // right stick
	struct deadzone lt_dz; // left trigger
	struct deadzone rt_dz; // right trigger
	/* anti-deadzones */
	u8 ls_adz; // left stick
	u8 rs_adz; // right stick
	/* joystick response curves */
	struct response_curve ls_rc;
	struct response_curve rs_rc;

	struct js_axis_calibrations js_cal;
	struct tr_axis_calibrations tr_cal;
};

/* The hatswitch outputs integers, we use them to index this X|Y pair */
static const int hat_values[][2] = {
	{ 0, 0 }, { 0, -1 }, { 1, -1 }, { 1, 0 },   { 1, 1 },
	{ 0, 1 }, { -1, 1 }, { -1, 0 }, { -1, -1 },
};

/* rumble packet structure */
struct ff_data {
	u8 enable;
	u8 magnitude_left;
	u8 magnitude_right;
	u8 magnitude_strong;
	u8 magnitude_weak;
	u8 pulse_sustain_10ms;
	u8 pulse_release_10ms;
	u8 loop_count;
} __packed;

struct ff_report {
	u8 report_id;
	struct ff_data ff;
} __packed;

struct ally_x_input_report {
	uint16_t x, y;
	uint16_t rx, ry;
	uint16_t z, rz;
	uint8_t buttons[4];
} __packed;

struct ally_x_device {
	struct input_dev *input;
	struct hid_device *hdev;
	spinlock_t lock;

	struct ff_report *ff_packet;
	struct work_struct output_worker;
	bool output_worker_initialized;
	/* Prevent multiple queued event due to the enforced delay in worker */
	bool update_qam_btn;
	/* Set if the QAM and AC buttons emit Xbox and Xbox+A */
	bool qam_btns_steam_mode;
	bool update_ff;
};

struct ally_rgb_dev {
	struct hid_device *hdev;
	struct led_classdev_mc led_rgb_dev;
	struct work_struct work;
	bool output_worker_initialized;
	spinlock_t lock;

	bool removed;
	bool update_rgb;
	uint8_t red[4];
	uint8_t green[4];
	uint8_t blue[4];
};

struct ally_rgb_data {
	uint8_t brightness;
	uint8_t red[4];
	uint8_t green[4];
	uint8_t blue[4];
	bool initialized;
};

static struct ally_drvdata {
	struct hid_device *hdev;
	struct ally_x_device *ally_x;
	struct ally_gamepad_cfg *gamepad_cfg;
	struct ally_rgb_dev *led_rgb_dev;
	struct ally_rgb_data led_rgb_data;
	uint mcu_version;
} drvdata;

static void reverse_bytes_in_pairs(u8 *buf, size_t size) {
	uint16_t *word_ptr;
	size_t i;

	for (i = 0; i < size; i += 2) {
		if (i + 1 < size) {
			word_ptr = (uint16_t *)&buf[i];
			*word_ptr = cpu_to_be16(*word_ptr);
		}
	}
}

/**
 * asus_dev_set_report - send set report request to device.
 *
 * @hdev: hid device
 * @buf: in/out data to transfer
 * @len: length of buf
 *
 * Return: count of data transferred, negative if error
 *
 * Same behavior as hid_hw_raw_request. Note that the input buffer is duplicated.
 */
static int asus_dev_set_report(struct hid_device *hdev, const u8 *buf, size_t len)
{
	unsigned char *dmabuf;
	int ret;

	dmabuf = kmemdup(buf, len, GFP_KERNEL);
	if (!dmabuf)
		return -ENOMEM;

	ret = hid_hw_raw_request(hdev, buf[0], dmabuf, len, HID_FEATURE_REPORT,
				 HID_REQ_SET_REPORT);
	kfree(dmabuf);

	return ret;
}

/**
 * asus_dev_get_report - send get report request to device.
 *
 * @hdev: hid device
 * @out: buffer to write output data in to
 * @len: length the output buffer provided
 *
 * Return: count of data transferred, negative if error
 *
 * Same behavior as hid_hw_raw_request.
 */
static int asus_dev_get_report(struct hid_device *hdev, u8 *out, size_t len)
{
	return hid_hw_raw_request(hdev, FEATURE_REPORT_ID, out, len,
		HID_FEATURE_REPORT, HID_REQ_GET_REPORT);
}

static u8 get_endpoint_address(struct hid_device *hdev)
{
	struct usb_interface *intf;
	struct usb_host_endpoint *ep;

	intf = to_usb_interface(hdev->dev.parent);

	if (intf) {
		ep = intf->cur_altsetting->endpoint;
		if (ep) {
			return ep->desc.bEndpointAddress;
		}
	}

	return -ENODEV;
}

/**************************************************************************************************/
/* ROG Ally gamepad configuration                                                                 */
/**************************************************************************************************/

/* This should be called before any attempts to set device functions */
static int ally_gamepad_check_ready(struct hid_device *hdev)
{
	int ret, count;
	u8 *hidbuf;

	hidbuf = kzalloc(FEATURE_ROG_ALLY_REPORT_SIZE, GFP_KERNEL);
	if (!hidbuf)
		return -ENOMEM;

	ret = 0;
	for (count = 0; count < READY_MAX_TRIES; count++) {
		hidbuf[0] = FEATURE_ROG_ALLY_REPORT_ID;
		hidbuf[1] = FEATURE_ROG_ALLY_CODE_PAGE;
		hidbuf[2] = xpad_cmd_check_ready;
		hidbuf[3] = 01;
		ret = asus_dev_set_report(hdev, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);
		if (ret < 0)
			hid_dbg(hdev, "ROG Ally check failed set report: %d\n", ret);

		hidbuf[0] = hidbuf[1] = hidbuf[2] = hidbuf[3] = 0;
		ret = asus_dev_get_report(hdev, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);
		if (ret < 0)
			hid_dbg(hdev, "ROG Ally check failed get report: %d\n", ret);

		ret = hidbuf[2] == xpad_cmd_check_ready;
		if (ret)
			break;
		usleep_range(
			1000,
			2000); /* don't spam the entire loop in less than USB response time */
	}

	if (count == READY_MAX_TRIES)
		hid_warn(hdev, "ROG Ally never responded with a ready\n");

	kfree(hidbuf);
	return ret;
}

/* VIBRATION INTENSITY ****************************************************************************/
static ssize_t gamepad_vibration_intensity_index_show(struct device *dev,
						      struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "left right\n");
}

ALLY_DEVICE_ATTR_RO(gamepad_vibration_intensity_index, vibration_intensity_index);

static ssize_t _gamepad_apply_intensity(struct hid_device *hdev,
					struct ally_gamepad_cfg *ally_cfg)
{
	u8 *hidbuf;
	int ret;

	hidbuf = kzalloc(FEATURE_ROG_ALLY_REPORT_SIZE, GFP_KERNEL);
	if (!hidbuf)
		return -ENOMEM;

	hidbuf[0] = FEATURE_ROG_ALLY_REPORT_ID;
	hidbuf[1] = FEATURE_ROG_ALLY_CODE_PAGE;
	hidbuf[2] = xpad_cmd_set_vibe_intensity;
	hidbuf[3] = xpad_cmd_len_vibe_intensity;
	hidbuf[4] = ally_cfg->vibration_intensity[0];
	hidbuf[5] = ally_cfg->vibration_intensity[1];

	ret = ally_gamepad_check_ready(hdev);
	if (ret < 0)
		goto report_fail;

	ret = asus_dev_set_report(hdev, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);
	if (ret < 0)
		goto report_fail;

report_fail:
	kfree(hidbuf);
	return ret;
}

static ssize_t gamepad_vibration_intensity_show(struct device *dev,
						struct device_attribute *attr, char *buf)
{
	struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;

	if (!drvdata.gamepad_cfg)
		return -ENODEV;

	return sysfs_emit(
		buf, "%d %d\n",
		ally_cfg->vibration_intensity[0],
		ally_cfg->vibration_intensity[1]);
}

static ssize_t gamepad_vibration_intensity_store(struct device *dev,
						 struct device_attribute *attr, const char *buf,
						 size_t count)
{
	struct hid_device *hdev = to_hid_device(dev);
	struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;
	u32 left, right;
	int ret;

	if (!drvdata.gamepad_cfg)
		return -ENODEV;

	if (sscanf(buf, "%d %d", &left, &right) != 2)
		return -EINVAL;

	if (left > 64 || right > 64)
		return -EINVAL;

	ally_cfg->vibration_intensity[0] = left;
	ally_cfg->vibration_intensity[1] = right;

	ret = _gamepad_apply_intensity(hdev, ally_cfg);
	if (ret < 0)
		return ret;

	return count;
}

ALLY_DEVICE_ATTR_RW(gamepad_vibration_intensity, vibration_intensity);

/* ANALOGUE DEADZONES *****************************************************************************/
static ssize_t _gamepad_apply_deadzones(struct hid_device *hdev,
				       struct ally_gamepad_cfg *ally_cfg)
{
	u8 *hidbuf;
	int ret;

	ret = ally_gamepad_check_ready(hdev);
	if (ret < 0)
		return ret;

	hidbuf = kzalloc(FEATURE_ROG_ALLY_REPORT_SIZE, GFP_KERNEL);
	if (!hidbuf)
		return -ENOMEM;

	hidbuf[0] = FEATURE_ROG_ALLY_REPORT_ID;
	hidbuf[1] = FEATURE_ROG_ALLY_CODE_PAGE;
	hidbuf[2] = xpad_cmd_set_js_dz;
	hidbuf[3] = xpad_cmd_len_deadzone;
	hidbuf[4] = ally_cfg->ls_dz.inner;
	hidbuf[5] = ally_cfg->ls_dz.outer;
	hidbuf[6] = ally_cfg->rs_dz.inner;
	hidbuf[7] = ally_cfg->rs_dz.outer;

	ret = asus_dev_set_report(hdev, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);
	if (ret < 0)
		goto end;

	hidbuf[2] = xpad_cmd_set_tr_dz;
	hidbuf[4] = ally_cfg->lt_dz.inner;
	hidbuf[5] = ally_cfg->lt_dz.outer;
	hidbuf[6] = ally_cfg->rt_dz.inner;
	hidbuf[7] = ally_cfg->rt_dz.outer;

	ret = asus_dev_set_report(hdev, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);
	if (ret < 0)
		goto end;

end:
	kfree(hidbuf);
	return ret;
}

static void _gamepad_set_deadzones_default(struct ally_gamepad_cfg *ally_cfg)
{
	ally_cfg->ls_dz.inner = 0x00;
	ally_cfg->ls_dz.outer = 0x64;
	ally_cfg->rs_dz.inner = 0x00;
	ally_cfg->rs_dz.outer = 0x64;
	ally_cfg->lt_dz.inner = 0x00;
	ally_cfg->lt_dz.outer = 0x64;
	ally_cfg->rt_dz.inner = 0x00;
	ally_cfg->rt_dz.outer = 0x64;
}

static ssize_t axis_xyz_deadzone_index_show(struct device *dev, struct device_attribute *attr,
					    char *buf)
{
	return sysfs_emit(buf, "inner outer\n");
}

ALLY_DEVICE_ATTR_RO(axis_xyz_deadzone_index, deadzone_index);

ALLY_DEADZONES(axis_xy_left, ls_dz);
ALLY_DEADZONES(axis_xy_right, rs_dz);
ALLY_DEADZONES(axis_z_left, lt_dz);
ALLY_DEADZONES(axis_z_right, rt_dz);

/* ANTI-DEADZONES *********************************************************************************/
static ssize_t _gamepad_apply_js_ADZ(struct hid_device *hdev,
					     struct ally_gamepad_cfg *ally_cfg)
{
	u8 *hidbuf;
	int ret;

	hidbuf = kzalloc(FEATURE_ROG_ALLY_REPORT_SIZE, GFP_KERNEL);
	if (!hidbuf)
		return -ENOMEM;

	hidbuf[0] = FEATURE_ROG_ALLY_REPORT_ID;
	hidbuf[1] = FEATURE_ROG_ALLY_CODE_PAGE;
	hidbuf[2] = xpad_cmd_set_adz;
	hidbuf[3] = xpad_cmd_len_adz;
	hidbuf[4] = ally_cfg->ls_adz;
	hidbuf[5] = ally_cfg->rs_adz;

	ret = ally_gamepad_check_ready(hdev);
	if (ret < 0)
		goto report_fail;

	ret = asus_dev_set_report(hdev, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);
	if (ret < 0)
		goto report_fail;

report_fail:
	kfree(hidbuf);
	return ret;
}

static void _gamepad_set_anti_deadzones_default(struct ally_gamepad_cfg *ally_cfg)
{
	ally_cfg->ls_adz = 0x00;
	ally_cfg->rs_adz = 0x00;
}

static ssize_t _gamepad_js_ADZ_store(struct device *dev, const char *buf, u8 *adz)
{
	int ret, val;

	ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;

	if (val < 0 || val > 32)
		return -EINVAL;

	*adz = val;

	return ret;
}

static ssize_t axis_xy_left_anti_deadzone_show(struct device *dev,
						struct device_attribute *attr,
						char *buf)
{
	struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;

	return sysfs_emit(buf, "%d\n", ally_cfg->ls_adz);
}

static ssize_t axis_xy_left_anti_deadzone_store(struct device *dev,
						struct device_attribute *attr,
						const char *buf, size_t count)
{
	struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;
	int ret;

	ret = _gamepad_js_ADZ_store(dev, buf, &ally_cfg->ls_adz);
	if (ret)
		return ret;

	return count;
}
ALLY_DEVICE_ATTR_RW(axis_xy_left_anti_deadzone, anti_deadzone);

static ssize_t axis_xy_right_anti_deadzone_show(struct device *dev,
						struct device_attribute *attr,
						char *buf)
{
	struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;

	return sysfs_emit(buf, "%d\n", ally_cfg->rs_adz);
}

static ssize_t axis_xy_right_anti_deadzone_store(struct device *dev,
						struct device_attribute *attr,
						const char *buf, size_t count)
{
	struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;
	int ret;

	ret = _gamepad_js_ADZ_store(dev, buf, &ally_cfg->rs_adz);
	if (ret)
		return ret;

	return count;
}
ALLY_DEVICE_ATTR_RW(axis_xy_right_anti_deadzone, anti_deadzone);

/* JS RESPONSE CURVES *****************************************************************************/
static void _gamepad_set_js_response_curves_default(struct ally_gamepad_cfg *ally_cfg)
{
	struct response_curve *js1_rc = &ally_cfg->ls_rc;
	struct response_curve *js2_rc = &ally_cfg->rs_rc;
	js1_rc->move_pct_1 = js2_rc->move_pct_1 = 0x16; // 25%
	js1_rc->move_pct_2 = js2_rc->move_pct_2 = 0x32; // 50%
	js1_rc->move_pct_3 = js2_rc->move_pct_3 = 0x48; // 75%
	js1_rc->move_pct_4 = js2_rc->move_pct_4 = 0x64; // 100%
	js1_rc->response_pct_1 = js2_rc->response_pct_1 = 0x16;
	js1_rc->response_pct_2 = js2_rc->response_pct_2 = 0x32;
	js1_rc->response_pct_3 = js2_rc->response_pct_3 = 0x48;
	js1_rc->response_pct_4 = js2_rc->response_pct_4 = 0x64;
}

static ssize_t _gamepad_apply_response_curves(struct hid_device *hdev,
					      struct ally_gamepad_cfg *ally_cfg)
{
	u8 *hidbuf;
	int ret;

	hidbuf = kzalloc(FEATURE_ROG_ALLY_REPORT_SIZE, GFP_KERNEL);
	if (!hidbuf)
		return -ENOMEM;

	hidbuf[0] = FEATURE_ROG_ALLY_REPORT_ID;
	hidbuf[1] = FEATURE_ROG_ALLY_CODE_PAGE;
	memcpy(&hidbuf[2], &ally_cfg->ls_rc, sizeof(ally_cfg->ls_rc));

	ret = ally_gamepad_check_ready(hdev);
	if (ret < 0)
		goto report_fail;

	hidbuf[4] = 0x02;
	memcpy(&hidbuf[5], &ally_cfg->rs_rc, sizeof(ally_cfg->rs_rc));

	ret = ally_gamepad_check_ready(hdev);
	if (ret < 0)
		goto report_fail;

	ret = asus_dev_set_report(hdev, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);
	if (ret < 0)
		goto report_fail;

report_fail:
	kfree(hidbuf);
	return ret;
}

ALLY_JS_RC_POINT(axis_xy_left, move, 1);
ALLY_JS_RC_POINT(axis_xy_left, move, 2);
ALLY_JS_RC_POINT(axis_xy_left, move, 3);
ALLY_JS_RC_POINT(axis_xy_left, move, 4);
ALLY_JS_RC_POINT(axis_xy_left, response, 1);
ALLY_JS_RC_POINT(axis_xy_left, response, 2);
ALLY_JS_RC_POINT(axis_xy_left, response, 3);
ALLY_JS_RC_POINT(axis_xy_left, response, 4);

ALLY_JS_RC_POINT(axis_xy_right, move, 1);
ALLY_JS_RC_POINT(axis_xy_right, move, 2);
ALLY_JS_RC_POINT(axis_xy_right, move, 3);
ALLY_JS_RC_POINT(axis_xy_right, move, 4);
ALLY_JS_RC_POINT(axis_xy_right, response, 1);
ALLY_JS_RC_POINT(axis_xy_right, response, 2);
ALLY_JS_RC_POINT(axis_xy_right, response, 3);
ALLY_JS_RC_POINT(axis_xy_right, response, 4);

/* CALIBRATIONS ***********************************************************************************/
static int gamepad_get_calibration(struct hid_device *hdev)
{
	struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;
	u8 *hidbuf;
	int ret, i;

	if (!drvdata.gamepad_cfg)
		return -ENODEV;

	hidbuf = kzalloc(FEATURE_ROG_ALLY_REPORT_SIZE, GFP_KERNEL);
	if (!hidbuf)
		return -ENOMEM;

	for (i = 0; i < 2; i++) {
		hidbuf[0] = FEATURE_ROG_ALLY_REPORT_ID;
		hidbuf[1] = 0xD0;
		hidbuf[2] = 0x03;
		hidbuf[3] = i + 1; // 0x01 JS, 0x02 TR
		hidbuf[4] = 0x20;

		ret = asus_dev_set_report(hdev, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);
		if (ret < 0) {
			hid_warn(hdev, "ROG Ally check failed set report: %d\n", ret);
			goto cleanup;
		}

		memset(hidbuf, 0, FEATURE_ROG_ALLY_REPORT_SIZE);
		ret = asus_dev_get_report(hdev, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);
		if (ret < 0 || hidbuf[5] != 1) {
			hid_warn(hdev, "ROG Ally check failed get report: %d\n", ret);
			goto cleanup;
		}

		if (i == 0) {
			/* Joystick calibration */
			reverse_bytes_in_pairs(&hidbuf[6], sizeof(struct js_axis_calibrations));
			ally_cfg->js_cal = *(struct js_axis_calibrations *)&hidbuf[6];
			print_hex_dump(KERN_INFO, "HID Buffer JS: ", DUMP_PREFIX_OFFSET, 16, 1, hidbuf, 32, true);
			struct js_axis_calibrations *cal = &drvdata.gamepad_cfg->js_cal;
			pr_err("LS_CAL: X: %d, Min: %d, Max: %d", cal->left_x_stable, cal->left_x_min, cal->left_x_max);
			pr_err("LS_CAL: Y: %d, Min: %d, Max: %d", cal->left_y_stable, cal->left_y_min, cal->left_y_max);
			pr_err("RS_CAL: X: %d, Min: %d, Max: %d", cal->right_x_stable, cal->right_x_min, cal->right_x_max);
			pr_err("RS_CAL: Y: %d, Min: %d, Max: %d", cal->right_y_stable, cal->right_y_min, cal->right_y_max);
		} else {
			/* Trigger calibration */
			reverse_bytes_in_pairs(&hidbuf[6], sizeof(struct tr_axis_calibrations));
			ally_cfg->tr_cal = *(struct tr_axis_calibrations *)&hidbuf[6];
			print_hex_dump(KERN_INFO, "HID Buffer TR: ", DUMP_PREFIX_OFFSET, 16, 1, hidbuf, 32, true);
		}
	}

cleanup:
	kfree(hidbuf);
	return ret;
}

static struct attribute *axis_xy_left_attrs[] = {
	&dev_attr_axis_xy_left_anti_deadzone.attr,
	&dev_attr_axis_xy_left_deadzone.attr,
	&dev_attr_axis_xyz_deadzone_index.attr,
	&dev_attr_axis_xy_left_move_1.attr,
	&dev_attr_axis_xy_left_move_2.attr,
	&dev_attr_axis_xy_left_move_3.attr,
	&dev_attr_axis_xy_left_move_4.attr,
	&dev_attr_axis_xy_left_response_1.attr,
	&dev_attr_axis_xy_left_response_2.attr,
	&dev_attr_axis_xy_left_response_3.attr,
	&dev_attr_axis_xy_left_response_4.attr,
	NULL
};
static const struct attribute_group axis_xy_left_attr_group = {
	.name = "axis_xy_left",
	.attrs = axis_xy_left_attrs,
};

static struct attribute *axis_xy_right_attrs[] = {
	&dev_attr_axis_xy_right_anti_deadzone.attr,
	&dev_attr_axis_xy_right_deadzone.attr,
	&dev_attr_axis_xyz_deadzone_index.attr,
	&dev_attr_axis_xy_right_move_1.attr,
	&dev_attr_axis_xy_right_move_2.attr,
	&dev_attr_axis_xy_right_move_3.attr,
	&dev_attr_axis_xy_right_move_4.attr,
	&dev_attr_axis_xy_right_response_1.attr,
	&dev_attr_axis_xy_right_response_2.attr,
	&dev_attr_axis_xy_right_response_3.attr,
	&dev_attr_axis_xy_right_response_4.attr,
	NULL
};
static const struct attribute_group axis_xy_right_attr_group = {
	.name = "axis_xy_right",
	.attrs = axis_xy_right_attrs,
};

static struct attribute *axis_z_left_attrs[] = {
	&dev_attr_axis_z_left_deadzone.attr,
	&dev_attr_axis_xyz_deadzone_index.attr,
	NULL,
};
static const struct attribute_group axis_z_left_attr_group = {
	.name = "axis_z_left",
	.attrs = axis_z_left_attrs,
};

static struct attribute *axis_z_right_attrs[] = {
	&dev_attr_axis_z_right_deadzone.attr,
	&dev_attr_axis_xyz_deadzone_index.attr,
	NULL,
};
static const struct attribute_group axis_z_right_attr_group = {
	.name = "axis_z_right",
	.attrs = axis_z_right_attrs,
};

/* A HID packet conatins mappings for two buttons: btn1, btn1_macro, btn2, btn2_macro */
static void _btn_pair_to_hid_pkt(struct ally_gamepad_cfg *ally_cfg,
				enum btn_pair_index pair,
				struct btn_data *btn1, struct btn_data *btn2,
				u8 *out, int out_len)
{
	int start = 5;

	out[0] = FEATURE_ROG_ALLY_REPORT_ID;
	out[1] = FEATURE_ROG_ALLY_CODE_PAGE;
	out[2] = xpad_cmd_set_mapping;
	out[3] = pair;
	out[4] = xpad_cmd_len_mapping;

	btn_code_to_byte_array(btn1->button, &out[start]);
	start += BTN_DATA_LEN;
	btn_code_to_byte_array(btn1->macro, &out[start]);
	start += BTN_DATA_LEN;
	btn_code_to_byte_array(btn2->button, &out[start]);
	start += BTN_DATA_LEN;
	btn_code_to_byte_array(btn2->macro, &out[start]);
	//print_hex_dump(KERN_DEBUG, "byte_array: ", DUMP_PREFIX_OFFSET, 64, 1, out, 64, false);
}

/* Apply the mapping pair to the device */
static int _gamepad_apply_btn_pair(struct hid_device *hdev, struct ally_gamepad_cfg *ally_cfg,
				 enum btn_pair_index btn_pair)
{
	u8 mode = ally_cfg->mode - 1;
	struct btn_data *btn1, *btn2;
	u8 *hidbuf;
	int ret;

	ret = ally_gamepad_check_ready(hdev);
	if (ret < 0)
		return ret;

	hidbuf = kzalloc(FEATURE_ROG_ALLY_REPORT_SIZE, GFP_KERNEL);
	if (!hidbuf)
		return -ENOMEM;

	switch (btn_pair) {
	case btn_pair_dpad_u_d:
		btn1 = &ally_cfg->key_mapping[mode].dpad_up;
		btn2 = &ally_cfg->key_mapping[mode].dpad_down;
		break;
	case btn_pair_dpad_l_r:
		btn1 = &ally_cfg->key_mapping[mode].dpad_left;
		btn2 = &ally_cfg->key_mapping[mode].dpad_right;
		break;
	case btn_pair_ls_rs:
		btn1 = &ally_cfg->key_mapping[mode].btn_ls;
		btn2 = &ally_cfg->key_mapping[mode].btn_rs;
		break;
	case btn_pair_lb_rb:
		btn1 = &ally_cfg->key_mapping[mode].btn_lb;
		btn2 = &ally_cfg->key_mapping[mode].btn_rb;
		break;
	case btn_pair_lt_rt:
		btn1 = &ally_cfg->key_mapping[mode].btn_lt;
		btn2 = &ally_cfg->key_mapping[mode].btn_rt;
		break;
	case btn_pair_a_b:
		btn1 = &ally_cfg->key_mapping[mode].btn_a;
		btn2 = &ally_cfg->key_mapping[mode].btn_b;
		break;
	case btn_pair_x_y:
		btn1 = &ally_cfg->key_mapping[mode].btn_x;
		btn2 = &ally_cfg->key_mapping[mode].btn_y;
		break;
	case btn_pair_view_menu:
		btn1 = &ally_cfg->key_mapping[mode].btn_view;
		btn2 = &ally_cfg->key_mapping[mode].btn_menu;
		break;
	case btn_pair_m1_m2:
		btn1 = &ally_cfg->key_mapping[mode].btn_m1;
		btn2 = &ally_cfg->key_mapping[mode].btn_m2;
		break;
	default:
		break;
	}

	_btn_pair_to_hid_pkt(ally_cfg, btn_pair, btn1, btn2, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);
	ret = asus_dev_set_report(hdev, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);

	kfree(hidbuf);

	return ret;
}

static int _gamepad_apply_turbo(struct hid_device *hdev, struct ally_gamepad_cfg *ally_cfg)
{
	struct btn_mapping *map = &ally_cfg->key_mapping[ally_cfg->mode - 1];
	u8 *hidbuf;
	int ret;

	/* set turbo */
	hidbuf = kzalloc(FEATURE_ROG_ALLY_REPORT_SIZE, GFP_KERNEL);
	if (!hidbuf)
		return -ENOMEM;
	hidbuf[0] = FEATURE_ROG_ALLY_REPORT_ID;
	hidbuf[1] = FEATURE_ROG_ALLY_CODE_PAGE;
	hidbuf[2] = xpad_cmd_set_turbo;
	hidbuf[3] = xpad_cmd_len_turbo;

	hidbuf[4] = map->dpad_up.turbo;
	hidbuf[6] = map->dpad_down.turbo;
	hidbuf[8] = map->dpad_left.turbo;
	hidbuf[10] = map->dpad_right.turbo;

	hidbuf[12] = map->btn_ls.turbo;
	hidbuf[14] = map->btn_rs.turbo;
	hidbuf[16] = map->btn_lb.turbo;
	hidbuf[18] = map->btn_rb.turbo;

	hidbuf[20] = map->btn_a.turbo;
	hidbuf[22] = map->btn_b.turbo;
	hidbuf[24] = map->btn_x.turbo;
	hidbuf[26] = map->btn_y.turbo;

	hidbuf[28] = map->btn_lt.turbo;
	hidbuf[30] = map->btn_rt.turbo;

	ret = asus_dev_set_report(hdev, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);

	kfree(hidbuf);

	return ret;
}

static ssize_t _gamepad_apply_all(struct hid_device *hdev, struct ally_gamepad_cfg *ally_cfg)
{
	int ret;

	ret = _gamepad_apply_btn_pair(hdev, ally_cfg, btn_pair_dpad_u_d);
	if (ret < 0)
		return ret;
	ret = _gamepad_apply_btn_pair(hdev, ally_cfg, btn_pair_dpad_l_r);
	if (ret < 0)
		return ret;
	ret = _gamepad_apply_btn_pair(hdev, ally_cfg, btn_pair_ls_rs);
	if (ret < 0)
		return ret;
	ret = _gamepad_apply_btn_pair(hdev, ally_cfg, btn_pair_lb_rb);
	if (ret < 0)
		return ret;
	ret = _gamepad_apply_btn_pair(hdev, ally_cfg, btn_pair_a_b);
	if (ret < 0)
		return ret;
	ret = _gamepad_apply_btn_pair(hdev, ally_cfg, btn_pair_x_y);
	if (ret < 0)
		return ret;
	ret = _gamepad_apply_btn_pair(hdev, ally_cfg, btn_pair_view_menu);
	if (ret < 0)
		return ret;
	ret = _gamepad_apply_btn_pair(hdev, ally_cfg, btn_pair_m1_m2);
	if (ret < 0)
		return ret;
	ret = _gamepad_apply_btn_pair(hdev, ally_cfg, btn_pair_lt_rt);
	if (ret < 0)
		return ret;
	ret = _gamepad_apply_turbo(hdev, ally_cfg);
	if (ret < 0)
		return ret;
	ret = _gamepad_apply_deadzones(hdev, ally_cfg);
	if (ret < 0)
		return ret;
	ret = _gamepad_apply_js_ADZ(hdev, ally_cfg);
	if (ret < 0)
		return ret;
	ret =_gamepad_apply_response_curves(hdev, ally_cfg);
	if (ret < 0)
		return ret;

	return 0;
}

static ssize_t gamepad_apply_all_store(struct device *dev, struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;
	struct hid_device *hdev = to_hid_device(dev);
	int ret;

	if (!drvdata.gamepad_cfg)
		return -ENODEV;

	ret = _gamepad_apply_all(hdev, ally_cfg);
	if (ret < 0)
		return ret;

	return count;
}
ALLY_DEVICE_ATTR_WO(gamepad_apply_all, apply_all);

/* button map attributes, regular and macro*/
ALLY_BTN_MAPPING(m1, btn_m1);
ALLY_BTN_MAPPING(m2, btn_m2);
ALLY_BTN_MAPPING(view, btn_view);
ALLY_BTN_MAPPING(menu, btn_menu);
ALLY_TURBO_BTN_MAPPING(a, btn_a);
ALLY_TURBO_BTN_MAPPING(b, btn_b);
ALLY_TURBO_BTN_MAPPING(x, btn_x);
ALLY_TURBO_BTN_MAPPING(y, btn_y);
ALLY_TURBO_BTN_MAPPING(lb, btn_lb);
ALLY_TURBO_BTN_MAPPING(rb, btn_rb);
ALLY_TURBO_BTN_MAPPING(ls, btn_ls);
ALLY_TURBO_BTN_MAPPING(rs, btn_rs);
ALLY_TURBO_BTN_MAPPING(lt, btn_lt);
ALLY_TURBO_BTN_MAPPING(rt, btn_rt);
ALLY_TURBO_BTN_MAPPING(dpad_u, dpad_up);
ALLY_TURBO_BTN_MAPPING(dpad_d, dpad_down);
ALLY_TURBO_BTN_MAPPING(dpad_l, dpad_left);
ALLY_TURBO_BTN_MAPPING(dpad_r, dpad_right);

static void _gamepad_set_xpad_default(struct ally_gamepad_cfg *ally_cfg)
{
	struct btn_mapping *map = &ally_cfg->key_mapping[ally_cfg->mode - 1];
	map->btn_m1.button = BTN_KB_M1;
	map->btn_m2.button = BTN_KB_M2;
	map->btn_a.button = BTN_PAD_A;
	map->btn_b.button = BTN_PAD_B;
	map->btn_x.button = BTN_PAD_X;
	map->btn_y.button = BTN_PAD_Y;
	map->btn_lb.button = BTN_PAD_LB;
	map->btn_rb.button = BTN_PAD_RB;
	map->btn_lt.button = BTN_PAD_LT;
	map->btn_rt.button = BTN_PAD_RT;
	map->btn_ls.button = BTN_PAD_LS;
	map->btn_rs.button = BTN_PAD_RS;
	map->dpad_up.button = BTN_PAD_DPAD_UP;
	map->dpad_down.button = BTN_PAD_DPAD_DOWN;
	map->dpad_left.button = BTN_PAD_DPAD_LEFT;
	map->dpad_right.button = BTN_PAD_DPAD_RIGHT;
	map->btn_view.button = BTN_PAD_VIEW;
	map->btn_menu.button = BTN_PAD_MENU;
}

static ssize_t btn_mapping_reset_store(struct device *dev, struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;

	if (!drvdata.gamepad_cfg)
		return -ENODEV;

	switch (ally_cfg->mode) {
	case xpad_mode_game:
		_gamepad_set_xpad_default(ally_cfg);
		break;
	default:
		_gamepad_set_xpad_default(ally_cfg);
		break;
	}

	return count;
}
ALLY_DEVICE_ATTR_WO(btn_mapping_reset, reset_btn_mapping);

/* GAMEPAD MODE */
static ssize_t _gamepad_set_mode(struct hid_device *hdev, struct ally_gamepad_cfg *ally_cfg,
				  int val)
{
	u8 *hidbuf;
	int ret;

	hidbuf = kzalloc(FEATURE_ROG_ALLY_REPORT_SIZE, GFP_KERNEL);
	if (!hidbuf)
		return -ENOMEM;

	hidbuf[0] = FEATURE_ROG_ALLY_REPORT_ID;
	hidbuf[1] = FEATURE_ROG_ALLY_CODE_PAGE;
	hidbuf[2] = xpad_cmd_set_mode;
	hidbuf[3] = xpad_cmd_len_mode;
	hidbuf[4] = val;

	ret = ally_gamepad_check_ready(hdev);
	if (ret < 0)
		goto report_fail;

	ret = asus_dev_set_report(hdev, hidbuf, FEATURE_ROG_ALLY_REPORT_SIZE);
	if (ret < 0)
		goto report_fail;

	ret = _gamepad_apply_all(hdev, ally_cfg);
	if (ret < 0)
		goto report_fail;

report_fail:
	kfree(hidbuf);
	return ret;
}

static ssize_t gamepad_mode_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;

	if (!drvdata.gamepad_cfg)
		return -ENODEV;

	return sysfs_emit(buf, "%d\n", ally_cfg->mode);
}

static ssize_t gamepad_mode_store(struct device *dev, struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct hid_device *hdev = to_hid_device(dev);
	struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;
	int ret, val;

	if (!drvdata.gamepad_cfg)
		return -ENODEV;

	ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;

	if (val < xpad_mode_game || val > xpad_mode_mouse)
		return -EINVAL;

	ally_cfg->mode = val;

	ret = _gamepad_set_mode(hdev, ally_cfg, val);
	if (ret < 0)
		return ret;

	return count;
}

DEVICE_ATTR_RW(gamepad_mode);

static ssize_t mcu_version_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", drvdata.mcu_version);
}

DEVICE_ATTR_RO(mcu_version);

/* ROOT LEVEL ATTRS *******************************************************************************/
static struct attribute *gamepad_device_attrs[] = {
	&dev_attr_btn_mapping_reset.attr,
	&dev_attr_gamepad_mode.attr,
	&dev_attr_gamepad_apply_all.attr,
	&dev_attr_gamepad_vibration_intensity.attr,
	&dev_attr_gamepad_vibration_intensity_index.attr,
	&dev_attr_mcu_version.attr,
	NULL
};

static const struct attribute_group ally_controller_attr_group = {
	.attrs = gamepad_device_attrs,
};

static const struct attribute_group *gamepad_device_attr_groups[] = {
	&ally_controller_attr_group,
	&axis_xy_left_attr_group,
	&axis_xy_right_attr_group,
	&axis_z_left_attr_group,
	&axis_z_right_attr_group,
	&btn_mapping_m1_attr_group,
	&btn_mapping_m2_attr_group,
	&btn_mapping_a_attr_group,
	&btn_mapping_b_attr_group,
	&btn_mapping_x_attr_group,
	&btn_mapping_y_attr_group,
	&btn_mapping_lb_attr_group,
	&btn_mapping_rb_attr_group,
	&btn_mapping_ls_attr_group,
	&btn_mapping_rs_attr_group,
	&btn_mapping_lt_attr_group,
	&btn_mapping_rt_attr_group,
	&btn_mapping_dpad_u_attr_group,
	&btn_mapping_dpad_d_attr_group,
	&btn_mapping_dpad_l_attr_group,
	&btn_mapping_dpad_r_attr_group,
	&btn_mapping_view_attr_group,
	&btn_mapping_menu_attr_group,
	NULL,
};

static struct ally_gamepad_cfg *ally_gamepad_cfg_create(struct hid_device *hdev)
{
	struct ally_gamepad_cfg *ally_cfg;
	struct input_dev *input_dev;
	int err;

	ally_cfg = devm_kzalloc(&hdev->dev, sizeof(*ally_cfg), GFP_KERNEL);
	if (!ally_cfg)
		return ERR_PTR(-ENOMEM);
	ally_cfg->hdev = hdev;
	// Allocate memory for each mode's `btn_mapping`
	ally_cfg->mode = xpad_mode_game;

	input_dev = devm_input_allocate_device(&hdev->dev);
	if (!input_dev) {
		err = -ENOMEM;
		goto free_ally_cfg;
	}

	input_dev->id.bustype = hdev->bus;
	input_dev->id.vendor = hdev->vendor;
	input_dev->id.product = hdev->product;
	input_dev->id.version = hdev->version;
	input_dev->uniq = hdev->uniq;
	input_dev->name = "ASUS ROG Ally Config";
	input_set_capability(input_dev, EV_KEY, KEY_PROG1);
	input_set_capability(input_dev, EV_KEY, KEY_F16);
	input_set_capability(input_dev, EV_KEY, KEY_F17);
	input_set_capability(input_dev, EV_KEY, KEY_F18);
	input_set_drvdata(input_dev, hdev);

	err = input_register_device(input_dev);
	if (err)
		goto free_input_dev;
	ally_cfg->input = input_dev;

	/* ignore all errors for this as they are related to USB HID I/O */
	_gamepad_set_xpad_default(ally_cfg);
	ally_cfg->key_mapping[ally_cfg->mode - 1].btn_m1.button = BTN_KB_M1;
	ally_cfg->key_mapping[ally_cfg->mode - 1].btn_m2.button = BTN_KB_M2;
	_gamepad_apply_btn_pair(hdev, ally_cfg, btn_pair_m1_m2);
	gamepad_get_calibration(hdev);

	ally_cfg->vibration_intensity[0] = 0x64;
	ally_cfg->vibration_intensity[1] = 0x64;
	_gamepad_set_deadzones_default(ally_cfg);
	_gamepad_set_anti_deadzones_default(ally_cfg);
	_gamepad_set_js_response_curves_default(ally_cfg);

	drvdata.gamepad_cfg = ally_cfg; // Must asign before attr group setup
	if (sysfs_create_groups(&hdev->dev.kobj, gamepad_device_attr_groups)) {
		err = -ENODEV;
		goto unregister_input_dev;
	}

	return ally_cfg;

unregister_input_dev:
	input_unregister_device(input_dev);
	ally_cfg->input = NULL; // Prevent double free when kfree(ally_cfg) happens

free_input_dev:
	devm_kfree(&hdev->dev, input_dev);

free_ally_cfg:
	devm_kfree(&hdev->dev, ally_cfg);
	return ERR_PTR(err);
}

static void ally_cfg_remove(struct hid_device *hdev)
{
	// __gamepad_set_mode(hdev, drvdata.gamepad_cfg, xpad_mode_mouse);
	sysfs_remove_groups(&hdev->dev.kobj, gamepad_device_attr_groups);
}

/**************************************************************************************************/
/* ROG Ally gamepad i/o and force-feedback                                                        */
/**************************************************************************************************/
static int ally_x_raw_event(struct ally_x_device *ally_x, struct hid_report *report, u8 *data,
			    int size)
{
	struct ally_x_input_report *in_report;
	unsigned long flags;
	u8 byte;

	if (data[0] == 0x0B) {
		in_report = (struct ally_x_input_report *)&data[1];

		input_report_abs(ally_x->input, ABS_X, in_report->x);
		input_report_abs(ally_x->input, ABS_Y, in_report->y);
		input_report_abs(ally_x->input, ABS_RX, in_report->rx);
		input_report_abs(ally_x->input, ABS_RY, in_report->ry);
		input_report_abs(ally_x->input, ABS_Z, in_report->z);
		input_report_abs(ally_x->input, ABS_RZ, in_report->rz);

		byte = in_report->buttons[0];
		input_report_key(ally_x->input, BTN_A, byte & BIT(0));
		input_report_key(ally_x->input, BTN_B, byte & BIT(1));
		input_report_key(ally_x->input, BTN_X, byte & BIT(2));
		input_report_key(ally_x->input, BTN_Y, byte & BIT(3));
		input_report_key(ally_x->input, BTN_TL, byte & BIT(4));
		input_report_key(ally_x->input, BTN_TR, byte & BIT(5));
		input_report_key(ally_x->input, BTN_SELECT, byte & BIT(6));
		input_report_key(ally_x->input, BTN_START, byte & BIT(7));

		byte = in_report->buttons[1];
		input_report_key(ally_x->input, BTN_THUMBL, byte & BIT(0));
		input_report_key(ally_x->input, BTN_THUMBR, byte & BIT(1));
		input_report_key(ally_x->input, BTN_MODE, byte & BIT(2));

		byte = in_report->buttons[2];
		input_report_abs(ally_x->input, ABS_HAT0X, hat_values[byte][0]);
		input_report_abs(ally_x->input, ABS_HAT0Y, hat_values[byte][1]);
	}
	/*
	 * The MCU used on Ally provides many devices: gamepad, keyboord, mouse, other.
	 * The AC and QAM buttons route through another interface making it difficult to
	 * use the events unless we grab those and use them here. Only works for Ally X.
	 */
	else if (data[0] == 0x5A) {
		if (ally_x->qam_btns_steam_mode) {
			spin_lock_irqsave(&ally_x->lock, flags);
			if ((data[1] == 0x38 || data[1] == 0x93) && !ally_x->update_qam_btn) {
				ally_x->update_qam_btn = true;
				if (ally_x->output_worker_initialized)
					schedule_work(&ally_x->output_worker);
			}
			spin_unlock_irqrestore(&ally_x->lock, flags);
			/* Left/XBox button. Long press does ctrl+alt+del which we can't catch */
			input_report_key(ally_x->input, BTN_MODE, data[1] == 0xA6);
		} else {
			input_report_key(ally_x->input, KEY_F16, data[1] == 0xA6);
			input_report_key(ally_x->input, KEY_PROG1, data[1] == 0x38 || data[1] == 0x93);
		}
		/* QAM long press */
		input_report_key(ally_x->input, KEY_F17, data[1] == 0xA7);
		/* QAM long press released */
		input_report_key(ally_x->input, KEY_F18, data[1] == 0xA8);
	}

	input_sync(ally_x->input);

	return 0;
}

static struct input_dev *ally_x_alloc_input_dev(struct hid_device *hdev,
						const char *name_suffix)
{
	struct input_dev *input_dev;

	input_dev = devm_input_allocate_device(&hdev->dev);
	if (!input_dev)
		return ERR_PTR(-ENOMEM);

	input_dev->id.bustype = hdev->bus;
	input_dev->id.vendor = hdev->vendor;
	input_dev->id.product = hdev->product;
	input_dev->id.version = hdev->version;
	input_dev->uniq = hdev->uniq;
	input_dev->name = "ASUS ROG Ally X Gamepad";

	input_set_drvdata(input_dev, hdev);

	return input_dev;
}

static int ally_x_play_effect(struct input_dev *idev, void *data, struct ff_effect *effect)
{
	struct ally_x_device *ally_x = drvdata.ally_x;
	unsigned long flags;

	if (effect->type != FF_RUMBLE)
		return 0;

	spin_lock_irqsave(&ally_x->lock, flags);
	ally_x->ff_packet->ff.magnitude_strong = effect->u.rumble.strong_magnitude / 512;
	ally_x->ff_packet->ff.magnitude_weak = effect->u.rumble.weak_magnitude / 512;
	ally_x->update_ff = true;
	spin_unlock_irqrestore(&ally_x->lock, flags);

	if (ally_x->output_worker_initialized)
		schedule_work(&ally_x->output_worker);

	return 0;
}

static void ally_x_work(struct work_struct *work)
{
	struct ally_x_device *ally_x = container_of(work, struct ally_x_device, output_worker);
	struct ff_report *ff_report = NULL;
	bool update_qam = false;
	bool update_ff = false;
	unsigned long flags;

	spin_lock_irqsave(&ally_x->lock, flags);
	update_ff = ally_x->update_ff;
	if (ally_x->update_ff) {
		ff_report = kmemdup(ally_x->ff_packet, sizeof(*ally_x->ff_packet), GFP_KERNEL);
		ally_x->update_ff = false;
	}
	update_qam = ally_x->update_qam_btn;
	spin_unlock_irqrestore(&ally_x->lock, flags);

	if (update_ff && ff_report) {
		ff_report->ff.magnitude_left = ff_report->ff.magnitude_strong;
		ff_report->ff.magnitude_right = ff_report->ff.magnitude_weak;
		asus_dev_set_report(ally_x->hdev, (u8 *)ff_report, sizeof(*ff_report));
	}
	kfree(ff_report);

	if (update_qam) {
		/*
		 * The sleeps here are required to allow steam to register the button combo.
		 */
		usleep_range(1000, 2000);
		input_report_key(ally_x->input, BTN_MODE, 1);
		input_sync(ally_x->input);

		msleep(80);
		input_report_key(ally_x->input, BTN_A, 1);
		input_sync(ally_x->input);

		msleep(80);
		input_report_key(ally_x->input, BTN_A, 0);
		input_sync(ally_x->input);

		msleep(80);
		input_report_key(ally_x->input, BTN_MODE, 0);
		input_sync(ally_x->input);

		spin_lock_irqsave(&ally_x->lock, flags);
		ally_x->update_qam_btn = false;
		spin_unlock_irqrestore(&ally_x->lock, flags);
	}
}

static struct input_dev *ally_x_setup_input(struct hid_device *hdev)
{
	int ret, abs_min = 0, js_abs_max = 65535, tr_abs_max = 1023;
	struct input_dev *input;

	input = ally_x_alloc_input_dev(hdev, NULL);
	if (IS_ERR(input))
		return ERR_CAST(input);

	input_set_abs_params(input, ABS_X, abs_min, js_abs_max, 0, 0);
	input_set_abs_params(input, ABS_Y, abs_min, js_abs_max, 0, 0);
	input_set_abs_params(input, ABS_RX, abs_min, js_abs_max, 0, 0);
	input_set_abs_params(input, ABS_RY, abs_min, js_abs_max, 0, 0);
	input_set_abs_params(input, ABS_Z, abs_min, tr_abs_max, 0, 0);
	input_set_abs_params(input, ABS_RZ, abs_min, tr_abs_max, 0, 0);
	input_set_abs_params(input, ABS_HAT0X, -1, 1, 0, 0);
	input_set_abs_params(input, ABS_HAT0Y, -1, 1, 0, 0);
	input_set_capability(input, EV_KEY, BTN_A);
	input_set_capability(input, EV_KEY, BTN_B);
	input_set_capability(input, EV_KEY, BTN_X);
	input_set_capability(input, EV_KEY, BTN_Y);
	input_set_capability(input, EV_KEY, BTN_TL);
	input_set_capability(input, EV_KEY, BTN_TR);
	input_set_capability(input, EV_KEY, BTN_SELECT);
	input_set_capability(input, EV_KEY, BTN_START);
	input_set_capability(input, EV_KEY, BTN_MODE);
	input_set_capability(input, EV_KEY, BTN_THUMBL);
	input_set_capability(input, EV_KEY, BTN_THUMBR);

	input_set_capability(input, EV_KEY, KEY_PROG1);
	input_set_capability(input, EV_KEY, KEY_F16);
	input_set_capability(input, EV_KEY, KEY_F17);
	input_set_capability(input, EV_KEY, KEY_F18);

	input_set_capability(input, EV_FF, FF_RUMBLE);
	input_ff_create_memless(input, NULL, ally_x_play_effect);

	ret = input_register_device(input);
	if (ret)
		return ERR_PTR(ret);

	return input;
}

static ssize_t ally_x_qam_mode_show(struct device *dev, struct device_attribute *attr,
				    char *buf)
{
	struct ally_x_device *ally_x = drvdata.ally_x;

	return sysfs_emit(buf, "%d\n", ally_x->qam_btns_steam_mode);
}

static ssize_t ally_x_qam_mode_store(struct device *dev, struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct ally_x_device *ally_x = drvdata.ally_x;
	bool val;
	int ret;

	ret = kstrtobool(buf, &val);
	if (ret < 0)
		return ret;

	ally_x->qam_btns_steam_mode = val;

	return count;
}
ALLY_DEVICE_ATTR_RW(ally_x_qam_mode, qam_mode);

static struct ally_x_device *ally_x_create(struct hid_device *hdev)
{
	uint8_t max_output_report_size;
	struct ally_x_device *ally_x;
	struct ff_report *report;
	int ret;

	ally_x = devm_kzalloc(&hdev->dev, sizeof(*ally_x), GFP_KERNEL);
	if (!ally_x)
		return ERR_PTR(-ENOMEM);

	ally_x->hdev = hdev;
	INIT_WORK(&ally_x->output_worker, ally_x_work);
	spin_lock_init(&ally_x->lock);
	ally_x->output_worker_initialized = true;
	ally_x->qam_btns_steam_mode =
		true; /* Always default to steam mode, it can be changed by userspace attr */

	max_output_report_size = sizeof(struct ally_x_input_report);
	report = devm_kzalloc(&hdev->dev, sizeof(*report), GFP_KERNEL);
	if (!report) {
		ret = -ENOMEM;
		goto free_ally_x;
	}

	/* None of these bytes will change for the FF command for now */
	report->report_id = 0x0D;
	report->ff.enable = 0x0F; /* Enable all by default */
	report->ff.pulse_sustain_10ms = 0xFF; /* Duration */
	report->ff.pulse_release_10ms = 0x00; /* Start Delay */
	report->ff.loop_count = 0xEB; /* Loop Count */
	ally_x->ff_packet = report;

	ally_x->input = ally_x_setup_input(hdev);
	if (IS_ERR(ally_x->input)) {
		ret = PTR_ERR(ally_x->input);
		goto free_ff_packet;
	}

	if (sysfs_create_file(&hdev->dev.kobj, &dev_attr_ally_x_qam_mode.attr)) {
		ret = -ENODEV;
		goto unregister_input;
	}

	ally_x->update_ff = true;
	if (ally_x->output_worker_initialized)
		schedule_work(&ally_x->output_worker);

	hid_info(hdev, "Registered Ally X controller using %s\n",
		 dev_name(&ally_x->input->dev));
	return ally_x;

unregister_input:
	input_unregister_device(ally_x->input);
free_ff_packet:
	kfree(ally_x->ff_packet);
free_ally_x:
	kfree(ally_x);
	return ERR_PTR(ret);
}

static void ally_x_remove(struct hid_device *hdev)
{
	struct ally_x_device *ally_x = drvdata.ally_x;
	unsigned long flags;

	spin_lock_irqsave(&ally_x->lock, flags);
	ally_x->output_worker_initialized = false;
	spin_unlock_irqrestore(&ally_x->lock, flags);
	cancel_work_sync(&ally_x->output_worker);
	sysfs_remove_file(&hdev->dev.kobj, &dev_attr_ally_x_qam_mode.attr);
}

/**************************************************************************************************/
/* ROG Ally LED control                                                                           */
/**************************************************************************************************/
static void ally_rgb_schedule_work(struct ally_rgb_dev *led)
{
	unsigned long flags;

	spin_lock_irqsave(&led->lock, flags);
	if (!led->removed)
		schedule_work(&led->work);
	spin_unlock_irqrestore(&led->lock, flags);
}

/*
 * The RGB still has the basic 0-3 level brightness. Since the multicolour
 * brightness is being used in place, set this to max
 */
static int ally_rgb_set_bright_base_max(struct hid_device *hdev)
{
	u8 buf[] = { FEATURE_KBD_LED_REPORT_ID1, 0xba, 0xc5, 0xc4, 0x02 };

	return asus_dev_set_report(hdev, buf, sizeof(buf));
}

static void ally_rgb_do_work(struct work_struct *work)
{
	struct ally_rgb_dev *led = container_of(work, struct ally_rgb_dev, work);
	int ret;
	unsigned long flags;

	u8 buf[16] = { [0] = FEATURE_ROG_ALLY_REPORT_ID,
		       [1] = FEATURE_ROG_ALLY_CODE_PAGE,
		       [2] = xpad_cmd_set_leds,
		       [3] = xpad_cmd_len_leds };

	spin_lock_irqsave(&led->lock, flags);
	if (!led->update_rgb) {
		spin_unlock_irqrestore(&led->lock, flags);
		return;
	}

	for (int i = 0; i < 4; i++) {
		buf[5 + i * 3] = drvdata.led_rgb_dev->green[i];
		buf[6 + i * 3] = drvdata.led_rgb_dev->blue[i];
		buf[4 + i * 3] = drvdata.led_rgb_dev->red[i];
	}
	led->update_rgb = false;

	spin_unlock_irqrestore(&led->lock, flags);

	ret = asus_dev_set_report(led->hdev, buf, sizeof(buf));
	if (ret < 0)
		hid_err(led->hdev, "Ally failed to set gamepad backlight: %d\n", ret);
}

static void ally_rgb_set(struct led_classdev *cdev, enum led_brightness brightness)
{
	struct led_classdev_mc *mc_cdev = lcdev_to_mccdev(cdev);
	struct ally_rgb_dev *led = container_of(mc_cdev, struct ally_rgb_dev, led_rgb_dev);
	int intensity, bright;
	unsigned long flags;

	led_mc_calc_color_components(mc_cdev, brightness);
	spin_lock_irqsave(&led->lock, flags);
	led->update_rgb = true;
	bright = mc_cdev->led_cdev.brightness;
	for (int i = 0; i < 4; i++) {
		intensity = mc_cdev->subled_info[i].intensity;
		drvdata.led_rgb_dev->red[i] = (((intensity >> 16) & 0xFF) * bright) / 255;
		drvdata.led_rgb_dev->green[i] = (((intensity >> 8) & 0xFF) * bright) / 255;
		drvdata.led_rgb_dev->blue[i] = ((intensity & 0xFF) * bright) / 255;
	}
	spin_unlock_irqrestore(&led->lock, flags);
	drvdata.led_rgb_data.initialized = true;

	ally_rgb_schedule_work(led);
}

static int ally_rgb_set_static_from_multi(struct hid_device *hdev)
{
	u8 buf[17] = {FEATURE_KBD_LED_REPORT_ID1, 0xb3};
	int ret;

	/*
	 * Set single zone single colour based on the first LED of EC software mode.
	 * buf[2] = zone, buf[3] = mode
	 */
	buf[4] = drvdata.led_rgb_data.red[0];
	buf[5] = drvdata.led_rgb_data.green[0];
	buf[6] = drvdata.led_rgb_data.blue[0];

	ret = asus_dev_set_report(hdev, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	ret = asus_dev_set_report(hdev, EC_MODE_LED_APPLY, sizeof(EC_MODE_LED_APPLY));
	if (ret < 0)
		return ret;

	return asus_dev_set_report(hdev, EC_MODE_LED_SET, sizeof(EC_MODE_LED_SET));
}

/*
 * Store the RGB values for restoring on resume, and set the static mode to the first LED colour
*/
static void ally_rgb_store_settings(void)
{
	int arr_size = sizeof(drvdata.led_rgb_data.red);

	struct ally_rgb_dev *led_rgb = drvdata.led_rgb_dev;

	drvdata.led_rgb_data.brightness = led_rgb->led_rgb_dev.led_cdev.brightness;

	memcpy(drvdata.led_rgb_data.red, led_rgb->red, arr_size);
	memcpy(drvdata.led_rgb_data.green, led_rgb->green, arr_size);
	memcpy(drvdata.led_rgb_data.blue, led_rgb->blue, arr_size);

	ally_rgb_set_static_from_multi(led_rgb->hdev);
}

static void ally_rgb_restore_settings(struct ally_rgb_dev *led_rgb, struct led_classdev *led_cdev,
				      struct mc_subled *mc_led_info)
{
	int arr_size = sizeof(drvdata.led_rgb_data.red);

	memcpy(led_rgb->red, drvdata.led_rgb_data.red, arr_size);
	memcpy(led_rgb->green, drvdata.led_rgb_data.green, arr_size);
	memcpy(led_rgb->blue, drvdata.led_rgb_data.blue, arr_size);
	for (int i = 0; i < 4; i++) {
		mc_led_info[i].intensity = (drvdata.led_rgb_data.red[i] << 16) |
					   (drvdata.led_rgb_data.green[i] << 8) |
					   drvdata.led_rgb_data.blue[i];
	}
	led_cdev->brightness = drvdata.led_rgb_data.brightness;
}

/* Set LEDs. Call after any setup. */
static void ally_rgb_resume(void)
{
	struct ally_rgb_dev *led_rgb = drvdata.led_rgb_dev;
	struct led_classdev *led_cdev;
	struct mc_subled *mc_led_info;

	if (!led_rgb)
		return;

	led_cdev = &led_rgb->led_rgb_dev.led_cdev;
	mc_led_info = led_rgb->led_rgb_dev.subled_info;

	if (drvdata.led_rgb_data.initialized) {
		ally_rgb_restore_settings(led_rgb, led_cdev, mc_led_info);
		led_rgb->update_rgb = true;
		ally_rgb_schedule_work(led_rgb);
		ally_rgb_set_bright_base_max(led_rgb->hdev);
	}
}

static int ally_rgb_register(struct hid_device *hdev, struct ally_rgb_dev *led_rgb)
{
	struct mc_subled *mc_led_info;
	struct led_classdev *led_cdev;

	mc_led_info =
		devm_kmalloc_array(&hdev->dev, 12, sizeof(*mc_led_info), GFP_KERNEL | __GFP_ZERO);
	if (!mc_led_info)
		return -ENOMEM;

	mc_led_info[0].color_index = LED_COLOR_ID_RGB;
	mc_led_info[1].color_index = LED_COLOR_ID_RGB;
	mc_led_info[2].color_index = LED_COLOR_ID_RGB;
	mc_led_info[3].color_index = LED_COLOR_ID_RGB;

	led_rgb->led_rgb_dev.subled_info = mc_led_info;
	led_rgb->led_rgb_dev.num_colors = 4;

	led_cdev = &led_rgb->led_rgb_dev.led_cdev;
	led_cdev->brightness = 128;
	led_cdev->name = "ally:rgb:joystick_rings";
	led_cdev->max_brightness = 255;
	led_cdev->brightness_set = ally_rgb_set;

	if (drvdata.led_rgb_data.initialized) {
		ally_rgb_restore_settings(led_rgb, led_cdev, mc_led_info);
	}

	return devm_led_classdev_multicolor_register(&hdev->dev, &led_rgb->led_rgb_dev);
}

static struct ally_rgb_dev *ally_rgb_create(struct hid_device *hdev)
{
	struct ally_rgb_dev *led_rgb;
	int ret;

	led_rgb = devm_kzalloc(&hdev->dev, sizeof(struct ally_rgb_dev), GFP_KERNEL);
	if (!led_rgb)
		return ERR_PTR(-ENOMEM);

	ret = ally_rgb_register(hdev, led_rgb);
	if (ret < 0) {
		cancel_work_sync(&led_rgb->work);
		devm_kfree(&hdev->dev, led_rgb);
		return ERR_PTR(ret);
	}

	led_rgb->hdev = hdev;
	led_rgb->removed = false;

	INIT_WORK(&led_rgb->work, ally_rgb_do_work);
	led_rgb->output_worker_initialized = true;
	spin_lock_init(&led_rgb->lock);

	ally_rgb_set_bright_base_max(hdev);

	/* Not marked as initialized unless ally_rgb_set() is called */
	if (drvdata.led_rgb_data.initialized) {
		msleep(1500);
		led_rgb->update_rgb = true;
		ally_rgb_schedule_work(led_rgb);
	}

	return led_rgb;
}

static void ally_rgb_remove(struct hid_device *hdev)
{
	struct ally_rgb_dev *led_rgb = drvdata.led_rgb_dev;
	unsigned long flags;
	int ep;

	ep = get_endpoint_address(hdev);
	if (ep != ROG_ALLY_CFG_INTF_IN)
		return;

	if (!drvdata.led_rgb_dev || led_rgb->removed)
		return;

	spin_lock_irqsave(&led_rgb->lock, flags);
	led_rgb->removed = true;
	led_rgb->output_worker_initialized = false;
	spin_unlock_irqrestore(&led_rgb->lock, flags);
	cancel_work_sync(&led_rgb->work);
	devm_led_classdev_multicolor_unregister(&hdev->dev, &led_rgb->led_rgb_dev);

	hid_info(hdev, "Removed Ally RGB interface");
}

/**************************************************************************************************/
/* ROG Ally driver init                                                                           */
/**************************************************************************************************/

static int ally_raw_event(struct hid_device *hdev, struct hid_report *report, u8 *data,
			  int size)
{
	struct ally_gamepad_cfg *cfg = drvdata.gamepad_cfg;
	struct ally_x_device *ally_x = drvdata.ally_x;

	if (ally_x) {
		if ((hdev->bus == BUS_USB && report->id == ALLY_X_INPUT_REPORT_USB &&
		     size == ALLY_X_INPUT_REPORT_USB_SIZE) ||
		    (data[0] == 0x5A)) {
			ally_x_raw_event(ally_x, report, data, size);
		} else {
			return -1;
		}
	}

	if (cfg && !ally_x) {
		input_report_key(cfg->input, KEY_PROG1, data[1] == 0x38);
		input_report_key(cfg->input, KEY_F16, data[1] == 0xA6);
		input_report_key(cfg->input, KEY_F17, data[1] == 0xA7);
		input_report_key(cfg->input, KEY_F18, data[1] == 0xA8);
		input_sync(cfg->input);
	}

	return 0;
}

static int ally_hid_init(struct hid_device *hdev)
{
	int ret;

	ret = asus_dev_set_report(hdev, EC_INIT_STRING, sizeof(EC_INIT_STRING));
	if (ret < 0) {
		hid_err(hdev, "Ally failed to send init command: %d\n", ret);
		return ret;
	}

	ret = asus_dev_set_report(hdev, FORCE_FEEDBACK_OFF, sizeof(FORCE_FEEDBACK_OFF));
	if (ret < 0)
		hid_err(hdev, "Ally failed to send init command: %d\n", ret);

	return ret;
}

static void ally_disable_nkey_wakeup(struct hid_device *hdev)
{
	struct usb_interface *intf = to_usb_interface(hdev->dev.parent);
	struct usb_device *udev;

	if (!intf)
		return;

	udev = interface_to_usbdev(intf);
	if (!udev)
		return;

	/* HACK: Mark Ally N-Key as incapable of wakeup */
	device_set_wakeup_enable(&udev->dev, false);
	hid_info(hdev, "Disabled wakeup capability on %s\n", dev_name(&udev->dev));
}

static int ally_hid_probe(struct hid_device *hdev, const struct hid_device_id *_id)
{
	struct usb_interface *intf = to_usb_interface(hdev->dev.parent);
	struct usb_device *udev = interface_to_usbdev(intf);
	u16 idProduct = le16_to_cpu(udev->descriptor.idProduct);
	int ret, ep;

	ep = get_endpoint_address(hdev);
	if (ep < 0)
		return ep;

	if (ep != ROG_ALLY_CFG_INTF_IN &&
	    ep != ROG_ALLY_X_INTF_IN)
		return -ENODEV;

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
		goto err_stop;
	}

	/* Initialize MCU even before alloc */
	ret = ally_hid_init(hdev);
	if (ret < 0)
		return ret;

	drvdata.hdev = hdev;
	hid_set_drvdata(hdev, &drvdata);

	/* This should almost always exist */
	if (ep == ROG_ALLY_CFG_INTF_IN) {
		validate_mcu_fw_version(hdev, idProduct);
		ally_disable_nkey_wakeup(hdev);

		drvdata.led_rgb_dev = ally_rgb_create(hdev);
		if (IS_ERR(drvdata.led_rgb_dev))
			hid_err(hdev, "Failed to create Ally gamepad LEDs.\n");
		else
			hid_info(hdev, "Created Ally RGB LED controls.\n");

		drvdata.gamepad_cfg = ally_gamepad_cfg_create(hdev);
		if (IS_ERR(drvdata.gamepad_cfg))
			hid_err(hdev, "Failed to create Ally gamepad attributes.\n");
		else
			hid_info(hdev, "Created Ally gamepad attributes.\n");

		if (IS_ERR(drvdata.led_rgb_dev) && IS_ERR(drvdata.gamepad_cfg))
			goto err_close;
	}

	/* May or may not exist */
	if (ep == ROG_ALLY_X_INTF_IN) {
		drvdata.ally_x = ally_x_create(hdev);
		if (IS_ERR(drvdata.ally_x)) {
			hid_err(hdev, "Failed to create Ally X gamepad.\n");
			drvdata.ally_x = NULL;
			goto err_close;
		}
		hid_info(hdev, "Created Ally X controller.\n");

		// Not required since we send this inputs ep through the gamepad input dev
		if (drvdata.gamepad_cfg && drvdata.gamepad_cfg->input) {
			input_unregister_device(drvdata.gamepad_cfg->input);
			hid_info(hdev, "Ally X removed unrequired input dev.\n");
		}
	}

	return 0;

err_close:
	hid_hw_close(hdev);
err_stop:
	hid_hw_stop(hdev);
	return ret;
}

static void ally_hid_remove(struct hid_device *hdev)
{
	if (drvdata.led_rgb_dev)
		ally_rgb_remove(hdev);

	if (drvdata.ally_x)
		ally_x_remove(hdev);

	if (drvdata.gamepad_cfg)
		ally_cfg_remove(hdev);

	hid_hw_close(hdev);
	hid_hw_stop(hdev);
}

static int ally_hid_resume(struct hid_device *hdev)
{
	struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;
	int err;

	if (!ally_cfg)
		return 0;

	err = _gamepad_apply_all(hdev, ally_cfg);
	if (err)
		return err;

	return 0;
}

static int ally_hid_reset_resume(struct hid_device *hdev)
{
	int ep = get_endpoint_address(hdev);
	if (ep != ROG_ALLY_CFG_INTF_IN)
		return 0;

	ally_hid_init(hdev);
	ally_rgb_resume();

	return ally_hid_resume(hdev);
}

static int ally_pm_thaw(struct device *dev)
{
	struct hid_device *hdev = to_hid_device(dev);

	return ally_hid_reset_resume(hdev);
}

static int ally_pm_suspend(struct device *dev)
{
	if (drvdata.led_rgb_dev) {
		ally_rgb_store_settings();
	}

	return 0;
}

static const struct dev_pm_ops ally_pm_ops = {
	.thaw = ally_pm_thaw,
	.suspend = ally_pm_suspend,
	.poweroff = ally_pm_suspend,
};

MODULE_DEVICE_TABLE(hid, rog_ally_devices);

static struct hid_driver rog_ally_cfg = { .name = "asus_rog_ally",
		.id_table = rog_ally_devices,
		.probe = ally_hid_probe,
		.remove = ally_hid_remove,
		.raw_event = ally_raw_event,
		/* HID is the better place for resume functions, not pm_ops */
		.resume = ally_hid_resume,
		/* ALLy 1 requires this to reset device state correctly */
		.reset_resume = ally_hid_reset_resume,
		.driver = {
			.pm = &ally_pm_ops,
		}
};

static int __init rog_ally_init(void)
{
	return hid_register_driver(&rog_ally_cfg);
}

static void __exit rog_ally_exit(void)
{
	hid_unregister_driver(&rog_ally_cfg);
}

module_init(rog_ally_init);
module_exit(rog_ally_exit);

MODULE_IMPORT_NS("ASUS_WMI");
MODULE_IMPORT_NS("HID_ASUS");
MODULE_AUTHOR("Luke D. Jones");
MODULE_DESCRIPTION("HID Driver for ASUS ROG Ally gamepad configuration.");
MODULE_LICENSE("GPL");
