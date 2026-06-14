/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 *  HID driver for Asus ROG laptops and Ally
 *
 *  Copyright (c) 2023 Luke Jones <luke@ljones.dev>
 */

#include <linux/hid.h>
#include <linux/types.h>

/*
 * the xpad_mode is used inside the mode setting packet and is used
 * for indexing (xpad_mode - 1)
 */
enum xpad_mode {
	xpad_mode_game = 0x01,
	xpad_mode_wasd = 0x02,
	xpad_mode_mouse = 0x03,
};

/* the xpad_cmd determines which feature is set or queried */
enum xpad_cmd {
	xpad_cmd_set_mode = 0x01,
	xpad_cmd_set_mapping = 0x02,
	xpad_cmd_set_js_dz = 0x04, /* deadzones */
	xpad_cmd_set_tr_dz = 0x05, /* deadzones */
	xpad_cmd_set_vibe_intensity = 0x06,
	xpad_cmd_set_leds = 0x08,
	xpad_cmd_check_ready = 0x0A,
	xpad_cmd_set_turbo = 0x0F,
	xpad_cmd_set_response_curve = 0x13,
	xpad_cmd_set_adz = 0x18,
};

/* the xpad_cmd determines which feature is set or queried */
enum xpad_cmd_len {
	xpad_cmd_len_mode = 0x01,
	xpad_cmd_len_mapping = 0x2c,
	xpad_cmd_len_deadzone = 0x04,
	xpad_cmd_len_vibe_intensity = 0x02,
	xpad_cmd_len_leds = 0x0C,
	xpad_cmd_len_turbo = 0x20,
	xpad_cmd_len_response_curve = 0x09,
	xpad_cmd_len_adz = 0x02,
};

/* Values correspond to the actual HID byte value required */
enum btn_pair_index {
	btn_pair_dpad_u_d = 0x01,
	btn_pair_dpad_l_r = 0x02,
	btn_pair_ls_rs = 0x03,
	btn_pair_lb_rb = 0x04,
	btn_pair_a_b = 0x05,
	btn_pair_x_y = 0x06,
	btn_pair_view_menu = 0x07,
	btn_pair_m1_m2 = 0x08,
	btn_pair_lt_rt = 0x09,
};

#define BTN_PAD_A             0x0101000000000000
#define BTN_PAD_B             0x0102000000000000
#define BTN_PAD_X             0x0103000000000000
#define BTN_PAD_Y             0x0104000000000000
#define BTN_PAD_LB            0x0105000000000000
#define BTN_PAD_RB            0x0106000000000000
#define BTN_PAD_LS            0x0107000000000000
#define BTN_PAD_RS            0x0108000000000000
#define BTN_PAD_DPAD_UP       0x0109000000000000
#define BTN_PAD_DPAD_DOWN     0x010A000000000000
#define BTN_PAD_DPAD_LEFT     0x010B000000000000
#define BTN_PAD_DPAD_RIGHT    0x010C000000000000
#define BTN_PAD_LT            0x010D000000000000
#define BTN_PAD_RT            0x010E000000000000
#define BTN_PAD_VIEW          0x0111000000000000
#define BTN_PAD_MENU          0x0112000000000000
#define BTN_PAD_XBOX          0x0113000000000000

#define BTN_KB_M2             0x02008E0000000000
#define BTN_KB_M1             0x02008F0000000000
#define BTN_KB_ESC            0x0200760000000000
#define BTN_KB_F1             0x0200500000000000
#define BTN_KB_F2             0x0200600000000000
#define BTN_KB_F3             0x0200400000000000
#define BTN_KB_F4             0x02000C0000000000
#define BTN_KB_F5             0x0200030000000000
#define BTN_KB_F6             0x02000B0000000000
#define BTN_KB_F7             0x0200800000000000
#define BTN_KB_F8             0x02000A0000000000
#define BTN_KB_F9             0x0200010000000000
#define BTN_KB_F10            0x0200090000000000
#define BTN_KB_F11            0x0200780000000000
#define BTN_KB_F12            0x0200070000000000
#define BTN_KB_F14            0x0200180000000000
#define BTN_KB_F15            0x0200100000000000
#define BTN_KB_BACKTICK       0x02000E0000000000
#define BTN_KB_1              0x0200160000000000
#define BTN_KB_2              0x02001E0000000000
#define BTN_KB_3              0x0200260000000000
#define BTN_KB_4              0x0200250000000000
#define BTN_KB_5              0x02002E0000000000
#define BTN_KB_6              0x0200360000000000
#define BTN_KB_7              0x02003D0000000000
#define BTN_KB_8              0x02003E0000000000
#define BTN_KB_9              0x0200460000000000
#define BTN_KB_0              0x0200450000000000
#define BTN_KB_HYPHEN         0x02004E0000000000
#define BTN_KB_EQUALS         0x0200550000000000
#define BTN_KB_BACKSPACE      0x0200660000000000
#define BTN_KB_TAB            0x02000D0000000000
#define BTN_KB_Q              0x0200150000000000
#define BTN_KB_W              0x02001D0000000000
#define BTN_KB_E              0x0200240000000000
#define BTN_KB_R              0x02002D0000000000
#define BTN_KB_T              0x02002C0000000000
#define BTN_KB_Y              0x0200350000000000
#define BTN_KB_U              0x02003C0000000000
#define BTN_KB_O              0x0200440000000000
#define BTN_KB_P              0x02004D0000000000
#define BTN_KB_LBRACKET       0x0200540000000000
#define BTN_KB_RBRACKET       0x02005B0000000000
#define BTN_KB_BACKSLASH      0x02005D0000000000
#define BTN_KB_CAPS           0x0200580000000000
#define BTN_KB_A              0x02001C0000000000
#define BTN_KB_S              0x02001B0000000000
#define BTN_KB_D              0x0200230000000000
#define BTN_KB_F              0x02002B0000000000
#define BTN_KB_G              0x0200340000000000
#define BTN_KB_H              0x0200330000000000
#define BTN_KB_J              0x02003B0000000000
#define BTN_KB_K              0x0200420000000000
#define BTN_KB_L              0x02004B0000000000
#define BTN_KB_SEMI           0x02004C0000000000
#define BTN_KB_QUOTE          0x0200520000000000
#define BTN_KB_RET            0x02005A0000000000
#define BTN_KB_LSHIFT         0x0200880000000000
#define BTN_KB_Z              0x02001A0000000000
#define BTN_KB_X              0x0200220000000000
#define BTN_KB_C              0x0200210000000000
#define BTN_KB_V              0x02002A0000000000
#define BTN_KB_B              0x0200320000000000
#define BTN_KB_N              0x0200310000000000
#define BTN_KB_M              0x02003A0000000000
#define BTN_KB_COMMA          0x0200410000000000
#define BTN_KB_PERIOD         0x0200490000000000
#define BTN_KB_RSHIFT         0x0200890000000000
#define BTN_KB_LCTL           0x02008C0000000000
#define BTN_KB_META           0x0200820000000000
#define BTN_KB_LALT           0x02008A0000000000
#define BTN_KB_SPACE          0x0200290000000000
#define BTN_KB_RALT           0x02008B0000000000
#define BTN_KB_MENU           0x0200840000000000
#define BTN_KB_RCTL           0x02008D0000000000
#define BTN_KB_PRNTSCN        0x0200C30000000000
#define BTN_KB_SCRLCK         0x02007E0000000000
#define BTN_KB_PAUSE          0x0200910000000000
#define BTN_KB_INS            0x0200C20000000000
#define BTN_KB_HOME           0x0200940000000000
#define BTN_KB_PGUP           0x0200960000000000
#define BTN_KB_DEL            0x0200C00000000000
#define BTN_KB_END            0x0200950000000000
#define BTN_KB_PGDWN          0x0200970000000000
#define BTN_KB_UP_ARROW       0x0200980000000000
#define BTN_KB_DOWN_ARROW     0x0200990000000000
#define BTN_KB_LEFT_ARROW     0x0200910000000000
#define BTN_KB_RIGHT_ARROW    0x02009B0000000000

#define BTN_NUMPAD_LOCK       0x0200770000000000
#define BTN_NUMPAD_FWDSLASH   0x0200900000000000
#define BTN_NUMPAD_ASTERISK   0x02007C0000000000
#define BTN_NUMPAD_HYPHEN     0x02007B0000000000
#define BTN_NUMPAD_0          0x0200700000000000
#define BTN_NUMPAD_1          0x0200690000000000
#define BTN_NUMPAD_2          0x0200720000000000
#define BTN_NUMPAD_3          0x02007A0000000000
#define BTN_NUMPAD_4          0x02006B0000000000
#define BTN_NUMPAD_5          0x0200730000000000
#define BTN_NUMPAD_6          0x0200740000000000
#define BTN_NUMPAD_7          0x02006C0000000000
#define BTN_NUMPAD_8          0x0200750000000000
#define BTN_NUMPAD_9          0x02007D0000000000
#define BTN_NUMPAD_PLUS       0x0200790000000000
#define BTN_NUMPAD_ENTER      0x0200810000000000
#define BTN_NUMPAD_PERIOD     0x0200710000000000

#define BTN_MOUSE_LCLICK      0x0300000001000000
#define BTN_MOUSE_RCLICK      0x0300000002000000
#define BTN_MOUSE_MCLICK      0x0300000003000000
#define BTN_MOUSE_WHEEL_UP    0x0300000004000000
#define BTN_MOUSE_WHEEL_DOWN  0x0300000005000000

#define BTN_MEDIA_SCREENSHOT      0x0500001600000000
#define BTN_MEDIA_SHOW_KEYBOARD   0x0500001900000000
#define BTN_MEDIA_SHOW_DESKTOP    0x0500001C00000000
#define BTN_MEDIA_START_RECORDING 0x0500001E00000000
#define BTN_MEDIA_MIC_OFF         0x0500000100000000
#define BTN_MEDIA_VOL_DOWN        0x0500000200000000
#define BTN_MEDIA_VOL_UP          0x0500000300000000

#define ALLY_DEVICE_ATTR_WO(_name, _sysfs_name)    \
	struct device_attribute dev_attr_##_name = \
		__ATTR(_sysfs_name, 0200, NULL, _name##_store)

/* required so we can have nested attributes with same name but different functions */
#define ALLY_DEVICE_ATTR_RW(_name, _sysfs_name)    \
	struct device_attribute dev_attr_##_name = \
		__ATTR(_sysfs_name, 0644, _name##_show, _name##_store)

#define ALLY_DEVICE_ATTR_RO(_name, _sysfs_name)    \
	struct device_attribute dev_attr_##_name = \
		__ATTR(_sysfs_name, 0444, _name##_show, NULL)

/* button specific macros */
#define ALLY_BTN_SHOW(_fname, _btn_name, _secondary)                           \
	static ssize_t _fname##_show(struct device *dev,                       \
				     struct device_attribute *attr, char *buf) \
	{                                                                      \
		struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;       \
		struct btn_data *btn;                                          \
		const char* name;                                              \
		if (!drvdata.gamepad_cfg)                                      \
			return -ENODEV;                                        \
		btn = &ally_cfg->key_mapping[ally_cfg->mode - 1]._btn_name;   \
		name = btn_to_name(_secondary ? btn->macro : btn->button);     \
		return sysfs_emit(buf, "%s\n", name);                          \
	}

#define ALLY_BTN_STORE(_fname, _btn_name, _secondary)                          \
	static ssize_t _fname##_store(struct device *dev,                      \
				      struct device_attribute *attr,           \
				      const char *buf, size_t count)           \
	{                                                                      \
		struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;       \
		struct btn_data *btn;                                          \
		u64 code;                                                      \
		if (!drvdata.gamepad_cfg)                                      \
			return -ENODEV;                                        \
		btn = &ally_cfg->key_mapping[ally_cfg->mode - 1]._btn_name;   \
		code = name_to_btn(buf);                                       \
		if (_secondary)                                                \
			btn->macro = code;                                     \
		else                                                           \
			btn->button = code;                                    \
		return count;                                                  \
	}

#define ALLY_TURBO_SHOW(_fname, _btn_name)                                     \
	static ssize_t _fname##_show(struct device *dev,                       \
				     struct device_attribute *attr, char *buf) \
	{                                                                      \
		struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;       \
		struct btn_data *btn;                                          \
		if (!drvdata.gamepad_cfg)                                      \
			return -ENODEV;                                        \
		btn = &ally_cfg->key_mapping[ally_cfg->mode - 1]._btn_name;   \
		return sysfs_emit(buf, "%d\n", btn->turbo);                    \
	}

#define ALLY_TURBO_STORE(_fname, _btn_name)                                    \
	static ssize_t _fname##_store(struct device *dev,                      \
				      struct device_attribute *attr,           \
				      const char *buf, size_t count)           \
	{                                                                      \
		struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;       \
		struct btn_data *btn;                                          \
		bool turbo;                                                    \
		int ret; \
		if (!drvdata.gamepad_cfg)                                      \
			return -ENODEV;                                        \
		btn = &ally_cfg->key_mapping[ally_cfg->mode - 1]._btn_name;   \
		ret = kstrtobool(buf, &turbo);                                 \
		if (ret)                                                       \
			return ret;                                            \
		btn->turbo = turbo;                                            \
		return count;                                                  \
	}

#define ALLY_DEADZONE_SHOW(_fname, _axis_name)                                 \
	static ssize_t _fname##_show(struct device *dev,                       \
				     struct device_attribute *attr, char *buf) \
	{                                                                      \
		struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;       \
		struct deadzone *dz;                                           \
		if (!drvdata.gamepad_cfg)                                      \
			return -ENODEV;                                        \
		dz = &ally_cfg->_axis_name;                                    \
		return sysfs_emit(buf, "%d %d\n", dz->inner, dz->outer);       \
	}

#define ALLY_DEADZONE_STORE(_fname, _axis_name)                                \
	static ssize_t _fname##_store(struct device *dev,                      \
				      struct device_attribute *attr,           \
				      const char *buf, size_t count)           \
	{                                                                      \
		struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg;       \
		struct hid_device *hdev = to_hid_device(dev);                  \
		u32 inner, outer;                                              \
		if (!drvdata.gamepad_cfg)                                      \
			return -ENODEV;                                        \
		if (sscanf(buf, "%d %d", &inner, &outer) != 2)                 \
			return -EINVAL;                                        \
		if (inner > 64 || outer > 64 || inner > outer)                 \
			return -EINVAL;                                        \
		ally_cfg->_axis_name.inner = inner;                            \
		ally_cfg->_axis_name.outer = outer;                            \
		_gamepad_apply_deadzones(hdev, ally_cfg);                      \
		return count;                                                  \
	}

#define ALLY_DEADZONES(_fname, _mname)                                    \
	ALLY_DEADZONE_SHOW(_fname##_deadzone, _mname);                    \
	ALLY_DEADZONE_STORE(_fname##_deadzone, _mname);                   \
	ALLY_DEVICE_ATTR_RW(_fname##_deadzone, deadzone)

/* response curve macros */
#define ALLY_RESP_CURVE_SHOW(_fname, _mname)                             \
static ssize_t _fname##_show(struct device *dev,                         \
			struct device_attribute *attr,                   \
			char *buf)                                       \
	{                                                                \
		struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg; \
		if (!drvdata.gamepad_cfg)                                \
			return -ENODEV;                                  \
		return sysfs_emit(buf, "%d\n", ally_cfg->ls_rc._mname);  \
	}

#define ALLY_RESP_CURVE_STORE(_fname, _mname)                            \
static ssize_t _fname##_store(struct device *dev,                        \
			struct device_attribute *attr,                   \
			const char *buf, size_t count)                   \
	{                                                                \
		struct ally_gamepad_cfg *ally_cfg = drvdata.gamepad_cfg; \
		int ret, val;                                            \
		if (!drvdata.gamepad_cfg)                                \
			return -ENODEV;                                  \
		ret = kstrtoint(buf, 0, &val);                           \
		if (ret)                                                 \
			return ret;                                      \
		if (val < 0 || val > 100)                                \
			return -EINVAL;                                  \
		ally_cfg->ls_rc._mname = val;                            \
		return count;                                            \
	}

/* _point_n must start at 1 */
#define ALLY_JS_RC_POINT(_fname, _mname, _num)                                 \
	ALLY_RESP_CURVE_SHOW(_fname##_##_mname##_##_num, _mname##_pct_##_num); \
	ALLY_RESP_CURVE_STORE(_fname##_##_mname##_##_num, _mname##_pct_##_num); \
	ALLY_DEVICE_ATTR_RW(_fname##_##_mname##_##_num, curve_##_mname##_pct_##_num)

#define ALLY_BTN_ATTRS_GROUP(_name, _fname)                               \
	static struct attribute *_fname##_attrs[] = {                     \
		&dev_attr_##_fname.attr,                                  \
		&dev_attr_##_fname##_macro.attr,                          \
	};                                                                \
	static const struct attribute_group _fname##_attr_group = {       \
		.name = __stringify(_name),                               \
		.attrs = _fname##_attrs,                                  \
	}

#define _ALLY_BTN_REMAP(_fname, _btn_name)                              \
	ALLY_BTN_SHOW(btn_mapping_##_fname##_remap, _btn_name, false);  \
	ALLY_BTN_STORE(btn_mapping_##_fname##_remap, _btn_name, false); \
	ALLY_DEVICE_ATTR_RW(btn_mapping_##_fname##_remap, remap);

#define _ALLY_BTN_MACRO(_fname, _btn_name)                             \
	ALLY_BTN_SHOW(btn_mapping_##_fname##_macro, _btn_name, true);  \
	ALLY_BTN_STORE(btn_mapping_##_fname##_macro, _btn_name, true); \
	ALLY_DEVICE_ATTR_RW(btn_mapping_##_fname##_macro, macro_remap);

#define ALLY_BTN_MAPPING(_fname, _btn_name)                                       \
	_ALLY_BTN_REMAP(_fname, _btn_name)                                        \
	_ALLY_BTN_MACRO(_fname, _btn_name)                                        \
	static struct attribute *_fname##_attrs[] = {                             \
		&dev_attr_btn_mapping_##_fname##_remap.attr,                      \
		&dev_attr_btn_mapping_##_fname##_macro.attr,                      \
		NULL,                                                             \
	};                                                                        \
	static const struct attribute_group btn_mapping_##_fname##_attr_group = { \
		.name = __stringify(btn_##_fname),                                \
		.attrs = _fname##_attrs,                                          \
	}

#define ALLY_TURBO_BTN_MAPPING(_fname, _btn_name)                                 \
	_ALLY_BTN_REMAP(_fname, _btn_name)                                        \
	_ALLY_BTN_MACRO(_fname, _btn_name)                                        \
	ALLY_TURBO_SHOW(btn_mapping_##_fname##_turbo, _btn_name);                 \
	ALLY_TURBO_STORE(btn_mapping_##_fname##_turbo, _btn_name);                \
	ALLY_DEVICE_ATTR_RW(btn_mapping_##_fname##_turbo, turbo);                 \
	static struct attribute *_fname##_turbo_attrs[] = {                       \
		&dev_attr_btn_mapping_##_fname##_remap.attr,                      \
		&dev_attr_btn_mapping_##_fname##_macro.attr,                      \
		&dev_attr_btn_mapping_##_fname##_turbo.attr,                      \
		NULL,                                                             \
	};                                                                        \
	static const struct attribute_group btn_mapping_##_fname##_attr_group = { \
		.name = __stringify(btn_##_fname),                                \
		.attrs = _fname##_turbo_attrs,                                    \
	}
