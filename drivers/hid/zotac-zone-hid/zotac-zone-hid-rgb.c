// SPDX-License-Identifier: GPL-2.0-or-later
/*
	* HID driver for ZOTAC Gaming Zone Controller - RGB LED control
	*
	* Copyright (c) 2025 Luke D. Jones <luke@ljones.dev>
	*/

#include <linux/device.h>
#include <linux/hid.h>
#include <linux/module.h>
#include <linux/leds.h>
#include <linux/led-class-multicolor.h>
#include <linux/usb.h>

#include "zotac-zone.h"

#define SETTING_COLOR 0x00
#define SETTING_SPEED 0x01
#define SETTING_EFFECT 0x02
#define SETTING_BRIGHTNESS 0x03
#define SETTING_REAL_TIME 0x04

#define EFFECT_RAINBOW 0x00
#define EFFECT_BREATHE 0x01
#define EFFECT_STARS 0x02
#define EFFECT_FADE 0x03
#define EFFECT_DANCE 0x04
#define EFFECT_OFF 0xF0

#define SPEED_SLOW 0x00
#define SPEED_NORMAL 0x01
#define SPEED_FAST 0x02

#define BRIGHTNESS_OFF 0x00 /* 0% */
#define BRIGHTNESS_LOW 0x19 /* 25% */
#define BRIGHTNESS_MED 0x32 /* 50% */
#define BRIGHTNESS_HIGH 0x4B /* 75% */
#define BRIGHTNESS_MAX 0x64 /* 100% */

static void zotac_rgb_set_default_colors(struct zotac_device *zotac,
					 struct zotac_rgb_dev *led_rgb,
					 int zone_idx)
{
	int j, led_index;

	for (j = 0; j < ZOTAC_RGB_LEDS_PER_ZONE; j++) {
		led_index = zone_idx * ZOTAC_RGB_LEDS_PER_ZONE + j;

		led_rgb->red[led_index] = 128;
		led_rgb->green[led_index] = 128;
		led_rgb->blue[led_index] = 128;

		zotac->led_rgb_data.zone[zone_idx].red[j] = 128;
		zotac->led_rgb_data.zone[zone_idx].green[j] = 128;
		zotac->led_rgb_data.zone[zone_idx].blue[j] = 128;
	}
}

static int zotac_rgb_read_zone_colors(struct zotac_device *zotac,
				      struct zotac_rgb_dev *led_rgb,
				      u8 zone_idx)
{
	size_t expected_len = 1 + ZOTAC_RGB_LEDS_PER_ZONE * 3;
	u8 zone_rgb_data[1 + ZOTAC_RGB_LEDS_PER_ZONE * 3];
	size_t data_len = sizeof(zone_rgb_data);
	int ret, j, led_index, red_idx, green_idx, blue_idx;
	u8 red, green, blue;

	zone_rgb_data[0] = zone_idx;

	ret = zotac_send_get_command(zotac, CMD_GET_RGB, SETTING_COLOR,
				     &zone_idx, 1, zone_rgb_data, &data_len);

	if (ret < 0) {
		hid_err(zotac->hdev, "Failed to read RGB data for zone %d\n",
			zone_idx);
		zotac_rgb_set_default_colors(zotac, led_rgb, zone_idx);
		return ret;
	}

	if (data_len < expected_len) {
		hid_warn(zotac->hdev,
			 "Incomplete RGB data for zone %d: %zu bytes\n",
			 zone_idx, data_len);
		zotac_rgb_set_default_colors(zotac, led_rgb, zone_idx);
		return 0;
	}

	for (j = 0; j < ZOTAC_RGB_LEDS_PER_ZONE; j++) {
		led_index = zone_idx * ZOTAC_RGB_LEDS_PER_ZONE + j;
		red_idx = 1 + (j * 3);
		green_idx = red_idx + 1;
		blue_idx = red_idx + 2;

		if (red_idx >= data_len || green_idx >= data_len ||
		    blue_idx >= data_len) {
			hid_warn(zotac->hdev,
				 "Index out of bounds for zone %d, LED %d\n",
				 zone_idx, j);
			break;
		}

		red = zone_rgb_data[red_idx];
		green = zone_rgb_data[green_idx];
		blue = zone_rgb_data[blue_idx];

		if (led_index <
		    ZOTAC_RGB_ZONE_COUNT * ZOTAC_RGB_LEDS_PER_ZONE) {
			led_rgb->red[led_index] = red;
			led_rgb->green[led_index] = green;
			led_rgb->blue[led_index] = blue;

			zotac->led_rgb_data.zone[zone_idx].red[j] = red;
			zotac->led_rgb_data.zone[zone_idx].green[j] = green;
			zotac->led_rgb_data.zone[zone_idx].blue[j] = blue;
		} else {
			hid_warn(
				zotac->hdev,
				"Output index out of bounds for zone %d, LED %d\n",
				zone_idx, j);
			break;
		}
	}

	return 0;
}

static int zotac_rgb_set_globals(struct zotac_device *zotac)
{
	int effect, speed, brightness;

	effect = zotac_send_get_byte(zotac, CMD_GET_RGB, SETTING_EFFECT, NULL,
				     0);
	if (effect < 0) {
		hid_warn(
			zotac->hdev,
			"Could not read effect from device, using default: %d\n",
			EFFECT_RAINBOW);
		effect = EFFECT_RAINBOW;
	}

	speed = zotac_send_get_byte(zotac, CMD_GET_RGB, SETTING_SPEED, NULL, 0);
	if (speed < 0) {
		hid_warn(
			zotac->hdev,
			"Could not read speed from device, using default: %d\n",
			SPEED_NORMAL);
		speed = SPEED_NORMAL;
	}

	/* This brightness is firmware level, not LED class level */
	brightness = zotac_send_get_byte(zotac, CMD_GET_RGB, SETTING_BRIGHTNESS,
					 NULL, 0);
	if (brightness < 0) {
		hid_warn(
			zotac->hdev,
			"Could not read brightness from device, using default: %d\n",
			BRIGHTNESS_MED);
		brightness = BRIGHTNESS_MED;
	}

	zotac->led_rgb_data.effect = effect;
	zotac->led_rgb_data.speed = speed;
	zotac->led_rgb_data.brightness = brightness;

	return 0;
}

static void zotac_rgb_schedule_work(struct zotac_rgb_dev *led)
{
	unsigned long flags;

	spin_lock_irqsave(&led->lock, flags);
	if (!led->removed)
		schedule_work(&led->work);
	spin_unlock_irqrestore(&led->lock, flags);
}

static void zotac_rgb_do_work(struct work_struct *work)
{
	struct zotac_rgb_dev *led =
		container_of(work, struct zotac_rgb_dev, work);
	struct zotac_device *zotac = led->zotac;
	u8 zone_idx = led - zotac->led_rgb_dev;
	u8 zone_data[3 + ZOTAC_RGB_LEDS_PER_ZONE * 3];
	unsigned long flags;
	int j, led_index;

	spin_lock_irqsave(&led->lock, flags);
	if (!led->update_rgb) {
		spin_unlock_irqrestore(&led->lock, flags);
		return;
	}
	led->update_rgb = false;

	zone_data[0] = zone_idx;

	// [0] = zone number, [1..2] = blank, [3..] = data
	for (j = 0; j < ZOTAC_RGB_LEDS_PER_ZONE; j++) {
		led_index = zone_idx * ZOTAC_RGB_LEDS_PER_ZONE + j;
		zone_data[3 + (j * 3)] = led->red[led_index];
		zone_data[4 + (j * 3)] = led->green[led_index];
		zone_data[5 + (j * 3)] = led->blue[led_index];
	}
	spin_unlock_irqrestore(&led->lock, flags);

	zotac_send_set_command(zotac, CMD_SET_RGB, SETTING_COLOR, zone_data,
			       sizeof(zone_data));

	if (zone_idx == 0) {
		zotac_send_set_command(zotac, CMD_SET_RGB, SETTING_EFFECT,
				       &zotac->led_rgb_data.effect, 1);
		zotac_send_set_command(zotac, CMD_SET_RGB, SETTING_SPEED,
				       &zotac->led_rgb_data.speed, 1);
		zotac_send_set_command(zotac, CMD_SET_RGB, SETTING_BRIGHTNESS,
				       &led->brightness, 1);
	}

	zotac_send_set_command(zotac, CMD_SAVE_CONFIG, 0, NULL, 0);
}

static void zotac_rgb_set_brightness(struct led_classdev *cdev,
				     enum led_brightness brightness)
{
	struct led_classdev_mc *mc_cdev = lcdev_to_mccdev(cdev);
	struct zotac_rgb_dev *led =
		container_of(mc_cdev, struct zotac_rgb_dev, led_rgb_dev);
	struct zotac_device *zotac = led->zotac;
	u8 zone_idx = led - zotac->led_rgb_dev;
	unsigned long flags;
	int i, led_index, intensity, bright;

	led_mc_calc_color_components(mc_cdev, brightness);

	spin_lock_irqsave(&led->lock, flags);
	led->update_rgb = true;
	bright = mc_cdev->led_cdev.brightness;

	for (i = 0; i < ZOTAC_RGB_LEDS_PER_ZONE; i++) {
		led_index = zone_idx * ZOTAC_RGB_LEDS_PER_ZONE + i;
		intensity = mc_cdev->subled_info[i].intensity;
		led->red[led_index] = (((intensity >> 16) & 0xFF) * bright) / 255;
		led->green[led_index] = (((intensity >> 8) & 0xFF) * bright) / 255;
		led->blue[led_index] = ((intensity & 0xFF) * bright) / 255;

		zotac->led_rgb_data.zone[zone_idx].red[i] = led->red[led_index];
		zotac->led_rgb_data.zone[zone_idx].green[i] = led->green[led_index];
		zotac->led_rgb_data.zone[zone_idx].blue[i] = led->blue[led_index];
	}

	zotac->led_rgb_data.zone[zone_idx].brightness = bright;
	zotac->led_rgb_data.initialized = true;
	spin_unlock_irqrestore(&led->lock, flags);

	zotac_rgb_schedule_work(led);
}

static void zotac_rgb_store_settings(struct zotac_device *zotac)
{
	struct zotac_rgb_dev *led_rgb;
	int i, arr_size = ZOTAC_RGB_LEDS_PER_ZONE;

	for (i = 0; i < ZOTAC_RGB_ZONE_COUNT; i++) {
		led_rgb = &zotac->led_rgb_dev[i];

		zotac->led_rgb_data.zone[i].brightness =
			led_rgb->led_rgb_dev.led_cdev.brightness;

		memcpy(zotac->led_rgb_data.zone[i].red,
		       led_rgb->red + (i * ZOTAC_RGB_LEDS_PER_ZONE), arr_size);
		memcpy(zotac->led_rgb_data.zone[i].green,
		       led_rgb->green + (i * ZOTAC_RGB_LEDS_PER_ZONE),
		       arr_size);
		memcpy(zotac->led_rgb_data.zone[i].blue,
		       led_rgb->blue + (i * ZOTAC_RGB_LEDS_PER_ZONE), arr_size);
	}
}

static void zotac_rgb_restore_settings(struct zotac_rgb_dev *led_rgb,
				       struct led_classdev *led_cdev,
				       struct mc_subled *mc_led_info)
{
	struct zotac_device *zotac = led_rgb->zotac;
	u8 zone_idx = led_rgb - zotac->led_rgb_dev;
	int i, offset = zone_idx * ZOTAC_RGB_LEDS_PER_ZONE;
	int arr_size = ZOTAC_RGB_LEDS_PER_ZONE;

	memcpy(led_rgb->red + offset, zotac->led_rgb_data.zone[zone_idx].red,
	       arr_size);
	memcpy(led_rgb->green + offset,
	       zotac->led_rgb_data.zone[zone_idx].green, arr_size);
	memcpy(led_rgb->blue + offset, zotac->led_rgb_data.zone[zone_idx].blue,
	       arr_size);

	for (i = 0; i < ZOTAC_RGB_LEDS_PER_ZONE; i++) {
		mc_led_info[i].intensity =
			(zotac->led_rgb_data.zone[zone_idx].red[i] << 16) |
			(zotac->led_rgb_data.zone[zone_idx].green[i] << 8) |
			zotac->led_rgb_data.zone[zone_idx].blue[i];
	}

	led_cdev->brightness = zotac->led_rgb_data.zone[zone_idx].brightness;
}

static ssize_t rgb_effect_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	int effect;

	if (!zotac.cfg_data)
		return -ENODEV;
	effect = zotac_send_get_byte(&zotac, CMD_GET_RGB, SETTING_EFFECT, NULL,
				     0);
	if (effect < 0)
		return effect;

	return sysfs_emit(buf, "%d\n", effect);
}

static ssize_t rgb_effect_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t count)
{
	int effect, ret;
	u8 effect_val;

	if (!zotac.cfg_data)
		return -ENODEV;

	ret = kstrtoint(buf, 10, &effect);
	if (ret)
		return ret;

	switch (effect) {
	case EFFECT_RAINBOW:
	case EFFECT_BREATHE:
	case EFFECT_STARS:
	case EFFECT_FADE:
	case EFFECT_DANCE:
	case EFFECT_OFF:
		break;
	default:
		return -EINVAL;
	}

	effect_val = (u8)effect;
	ret = zotac_send_set_command(&zotac, CMD_SET_RGB, SETTING_EFFECT,
				     &effect_val, 1);
	if (ret < 0)
		return ret;

	zotac.led_rgb_data.effect = effect_val;

	return count;
}
static DEVICE_ATTR_RW_NAMED(rgb_effect, "effect");

static ssize_t rgb_speed_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	int speed;

	if (!zotac.cfg_data)
		return -ENODEV;

	speed = zotac_send_get_byte(&zotac, CMD_GET_RGB, SETTING_SPEED, NULL, 0);
	if (speed < 0)
		return speed;

	return sysfs_emit(buf, "%d\n", speed);
}

static ssize_t rgb_speed_store(struct device *dev,
			       struct device_attribute *attr, const char *buf,
			       size_t count)
{
	int speed, ret;
	u8 speed_val;

	if (!zotac.cfg_data)
		return -ENODEV;

	ret = kstrtoint(buf, 10, &speed);
	if (ret) {
		dev_err(dev, "Invalid speed value format\n");
		return ret;
	}

	switch (speed) {
	case SPEED_SLOW:
	case SPEED_NORMAL:
	case SPEED_FAST:
		break;
	default:
		dev_err(dev, "Invalid speed value: %d (valid: 0-2)\n", speed);
		return -EINVAL;
	}

	speed_val = (u8)speed;
	ret = zotac_send_set_command(&zotac, CMD_SET_RGB, SETTING_SPEED,
				     &speed_val, 1);
	if (ret < 0) {
		dev_err(dev, "Failed to set RGB speed: %d\n", ret);
		return ret;
	}

	zotac.led_rgb_data.speed = speed_val;

	return count;
}
static DEVICE_ATTR_RW_NAMED(rgb_speed, "speed");

static u8 brightness_level_to_value(unsigned int level)
{
	switch (level) {
	case 0:
		return BRIGHTNESS_OFF;
	case 1:
		return BRIGHTNESS_LOW;
	case 2:
		return BRIGHTNESS_MED;
	case 3:
		return BRIGHTNESS_HIGH;
	case 4:
		return BRIGHTNESS_MAX;
	default:
		return BRIGHTNESS_MED;
	}
}

static unsigned int brightness_value_to_level(u8 value)
{
	if (value <= (BRIGHTNESS_OFF + BRIGHTNESS_LOW) / 2)
		return 0;
	else if (value <= (BRIGHTNESS_LOW + BRIGHTNESS_MED) / 2)
		return 1;
	else if (value <= (BRIGHTNESS_MED + BRIGHTNESS_HIGH) / 2)
		return 2;
	else if (value <= (BRIGHTNESS_HIGH + BRIGHTNESS_MAX) / 2)
		return 3;
	else
		return 4;
}

static ssize_t rgb_brightness_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	int brightness = 0;
	unsigned int level;

	if (!zotac.cfg_data)
		return -ENODEV;

	brightness = zotac_send_get_byte(&zotac, CMD_GET_RGB, SETTING_BRIGHTNESS,
					 NULL, 0);
	if (brightness < 0)
		return brightness;

	level = brightness_value_to_level(brightness);

	return sysfs_emit(buf, "%u\n", level);
}

static ssize_t rgb_brightness_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	int level, ret;
	u8 brightness;

	if (!zotac.cfg_data)
		return -ENODEV;

	ret = kstrtoint(buf, 10, &level);
	if (ret)
		return ret;

	if (level > 4)
		return -EINVAL;

	brightness = brightness_level_to_value(level);

	ret = zotac_send_set_command(&zotac, CMD_SET_RGB, SETTING_BRIGHTNESS,
				     &brightness, 1);
	if (ret < 0)
		return ret;

	ret = zotac_send_set_command(&zotac, CMD_SAVE_CONFIG, 0, NULL, 0);
	if (ret < 0)
		return ret;

	zotac.led_rgb_data.brightness = brightness;

	return count;
}
static DEVICE_ATTR_RW_NAMED(rgb_brightness, "brightness");

static struct attribute *zotac_rgb_attrs[] = { &dev_attr_rgb_effect.attr,
					       &dev_attr_rgb_speed.attr,
					       &dev_attr_rgb_brightness.attr,
					       NULL };

static const struct attribute_group zotac_rgb_attr_group = {
	.name = "rgb",
	.attrs = zotac_rgb_attrs,
};

/**
* zotac_rgb_resume - Restore RGB LED settings after system resume
* @zotac: Pointer to the zotac device structure
*
* Restores previously saved RGB settings after the system resumes from
* suspend. This includes effect, speed, and color settings for all zones.
*/
void zotac_rgb_resume(struct zotac_device *zotac)
{
	struct zotac_rgb_dev *led_rgb;
	struct led_classdev *led_cdev;
	struct mc_subled *mc_led_info;
	int i;

	if (!zotac->led_rgb_dev)
		return;

	if (!zotac->led_rgb_data.initialized) {
		hid_warn(
			zotac->hdev,
			"RGB data not initialized, skipping resume restoration\n");
		return;
	}

	zotac_send_set_command(zotac, CMD_SET_RGB, SETTING_EFFECT,
			       &zotac->led_rgb_data.effect, 1);
	zotac_send_set_command(zotac, CMD_SET_RGB, SETTING_SPEED,
			       &zotac->led_rgb_data.speed, 1);
	zotac_send_set_command(zotac, CMD_SET_RGB, SETTING_BRIGHTNESS,
			       &zotac->led_rgb_data.brightness, 1);

	for (i = 0; i < ZOTAC_RGB_ZONE_COUNT; i++) {
		led_rgb = &zotac->led_rgb_dev[i];
		led_cdev = &led_rgb->led_rgb_dev.led_cdev;
		mc_led_info = led_rgb->led_rgb_dev.subled_info;

		zotac_rgb_restore_settings(led_rgb, led_cdev, mc_led_info);
		led_rgb->update_rgb = true;
		zotac_rgb_schedule_work(led_rgb);
	}
}

/**
* zotac_rgb_suspend - Save RGB LED settings before system suspend
* @zotac: Pointer to the zotac device structure
*
* Stores current RGB settings before the system suspends so they
* can be restored when the system resumes.
*/
void zotac_rgb_suspend(struct zotac_device *zotac)
{
	if (!zotac->led_rgb_dev)
		return;

	zotac_rgb_store_settings(zotac);
}

static int zotac_rgb_register_zone(struct hid_device *hdev,
				   struct zotac_rgb_dev *led_rgb,
				   int zone_index)
{
	struct mc_subled *mc_led_info;
	struct led_classdev *led_cdev;
	char name[32];
	int i, err;

	snprintf(name, sizeof(name), "zotac:rgb:spectra_zone_%d", zone_index);

	mc_led_info = devm_kmalloc_array(&hdev->dev, ZOTAC_RGB_LEDS_PER_ZONE,
					 sizeof(*mc_led_info),
					 GFP_KERNEL | __GFP_ZERO);
	if (!mc_led_info)
		return -ENOMEM;

	for (i = 0; i < ZOTAC_RGB_LEDS_PER_ZONE; i++) {
		mc_led_info[i].color_index = LED_COLOR_ID_RGB;
	}

	led_rgb->led_rgb_dev.subled_info = mc_led_info;
	led_rgb->led_rgb_dev.num_colors = ZOTAC_RGB_LEDS_PER_ZONE;

	led_cdev = &led_rgb->led_rgb_dev.led_cdev;
	led_cdev->brightness = 128;
	led_cdev->name = kstrdup(name, GFP_KERNEL);
	if (!led_cdev->name){
		devm_kfree(&hdev->dev, mc_led_info);
		return -ENOMEM;
	}

	led_cdev->max_brightness = 255;
	led_cdev->brightness_set = zotac_rgb_set_brightness;

	err = devm_led_classdev_multicolor_register(&hdev->dev,
						    &led_rgb->led_rgb_dev);
	if (err) {
		kfree(led_cdev->name);
		return err;
	}

	err = sysfs_create_group(&led_cdev->dev->kobj, &zotac_rgb_attr_group);
	if (err) {
		return err;
	}

	return 0;
}

static int zotac_rgb_init_zone(struct zotac_device *zotac, int zone_idx)
{
	struct zotac_rgb_dev *led_rgb = &zotac->led_rgb_dev[zone_idx];
	int ret;

	led_rgb->hdev = zotac->hdev;
	led_rgb->zotac = zotac;
	led_rgb->removed = false;
	led_rgb->brightness = 128;

	zotac->led_rgb_data.zone[zone_idx].brightness =
		zotac->led_rgb_data.brightness;

	zotac_rgb_read_zone_colors(zotac, led_rgb, zone_idx);

	INIT_WORK(&led_rgb->work, zotac_rgb_do_work);
	led_rgb->output_worker_initialized = true;
	spin_lock_init(&led_rgb->lock);

	ret = zotac_rgb_register_zone(zotac->hdev, led_rgb, zone_idx);
	if (ret < 0)
		return ret;

	return 0;
}

/**
	* zotac_rgb_cleanup - Clean up resources used by RGB LED subsystem
	* @zotac: Pointer to the zotac device structure
	*
	* Releases resources allocated for RGB LED control, including sysfs
	* attributes, scheduled work, and allocated memory.
	*/
void zotac_rgb_cleanup(struct zotac_device *zotac)
{
	struct zotac_rgb_dev *led_rgb;
	unsigned long flags;
	int i;

	if (!zotac->led_rgb_dev)
		return;

	sysfs_remove_group(&zotac->led_rgb_dev->led_rgb_dev.led_cdev.dev->kobj, &zotac_rgb_attr_group);

	for (i = 0; i < ZOTAC_RGB_ZONE_COUNT; i++) {
		led_rgb = &zotac->led_rgb_dev[i];

		if (led_rgb->removed)
			continue;

		spin_lock_irqsave(&led_rgb->lock, flags);
		led_rgb->removed = true;
		led_rgb->output_worker_initialized = false;
		spin_unlock_irqrestore(&led_rgb->lock, flags);

		cancel_work_sync(&led_rgb->work);
	}

	zotac->led_rgb_dev = NULL;
}

/**
* zotac_rgb_init - Initialize RGB LED subsystem
* @zotac: Pointer to the zotac device structure
*
* Initializes the RGB LED subsystem by allocating memory for LEDs,
* fetching current settings from the device, registering LED zones,
* and creating sysfs attributes for RGB control.
*
* Return: 0 on success, negative error code on failure
*/
int zotac_rgb_init(struct zotac_device *zotac)
{
	struct zotac_rgb_dev *led_rgb;
	int ret, i;

	led_rgb = devm_kcalloc(&zotac->hdev->dev, ZOTAC_RGB_ZONE_COUNT,
			       sizeof(*led_rgb), GFP_KERNEL);
	if (!led_rgb)
		return -ENOMEM;

	zotac->led_rgb_dev = led_rgb;

	zotac_rgb_set_globals(zotac);

	for (i = 0; i < ZOTAC_RGB_ZONE_COUNT; i++) {
		ret = zotac_rgb_init_zone(zotac, i);
		if (ret < 0) {
			zotac_rgb_cleanup(zotac);
			return ret;
		}
	}

	zotac->led_rgb_data.initialized = true;

	for (i = 0; i < ZOTAC_RGB_ZONE_COUNT; i++) {
		led_rgb = &zotac->led_rgb_dev[i];
		led_rgb->update_rgb = true;
		zotac_rgb_schedule_work(led_rgb);
	}

	return 0;
}
