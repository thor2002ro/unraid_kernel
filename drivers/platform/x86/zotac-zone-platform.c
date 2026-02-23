// SPDX-License-Identifier: GPL-2.0
/*
 * Zotac Handheld Platform Driver
 *
 * Copyright (C) 2025 Luke D. Jones
 */

#include "linux/mod_devicetable.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/mutex.h>
#include <linux/dmi.h>
#include <linux/err.h>
#include <linux/acpi.h>
#include <linux/ioport.h>
#include <linux/jiffies.h>
#include <linux/platform_profile.h>
#include <linux/wmi.h>

#include "firmware_attributes_class.h"

#define DRIVER_NAME "zotac_zone_platform"

#define EC_COMMAND_PORT 0x4E
#define EC_DATA_PORT 0x4F

#define EC_FAN_CTRL_ADDR 0x44A
#define EC_FAN_DUTY_ADDR 0x44B
#define EC_FAN_SPEED_UPPER_ADDR 0x476
#define EC_FAN_SPEED_LOWER_ADDR 0x477
#define EC_CPU_TEMP_ADDR 0x462

/* Internal values */
#define EC_FAN_MODE_AUTO 0
#define EC_FAN_MODE_MANUAL 1
/* Follow standard convention for userspace */
#define PWM_ENABLE_OFF    0
#define PWM_ENABLE_MANUAL 1
#define PWM_ENABLE_AUTO   2  /* Automatic control (EC control) */
#define PWM_ENABLE_CURVE  3  /* Custom curve control */

#define PWM_MIN 0
#define PWM_MAX 255

#define FAN_CURVE_POINTS 9 /* 9 points for 10-90°C like in the Zotac C# code */

/* AMD APU WMI DPTC constants */
#define AMD_APU_WMI_METHODS_GUID "1f72b0f1-bfea-4472-9877-6e62937ab616"
#define AMD_APU_WMI_DATA_GUID "05901221-d566-11d1-b2f0-00a0c9062910"

/* DPTC command IDs */
#define DPTC_STAPM_TIME_CONSTANT  1
#define DPTC_SUSTAINED_POWER      5
#define DPTC_FAST_POWER_1         6
#define DPTC_FAST_POWER_2         7
#define DPTC_SLOW_PPT_CONSTANT    8
#define DPTC_P3T_LIMIT            0x32

/* DPTC power limits in milliwatts */
#define DPTC_MIN_POWER            5000
#define DPTC_MAX_POWER            28000

#define PPT_PL1_SPL_MIN		8
#define PPT_PL1_SPL_MAX		28
#define PPT_PL2_SPPT_MIN	8
#define PPT_PL2_SPPT_MAX	28
#define PPT_PL3_FPPT_MIN	8
#define PPT_PL3_FPPT_MAX	28

struct power_limits {
	u8 ppt_pl1_spl;
	u8 ppt_pl2_sppt;
	u8 ppt_pl3_fppt;
};

static const struct power_limits ppt_quiet_profile = {
	.ppt_pl1_spl = 5,
	.ppt_pl2_sppt = 10,
	.ppt_pl3_fppt = 15,
};

static const struct power_limits ppt_balanced_profile = {
	.ppt_pl1_spl = 12,
	.ppt_pl2_sppt = 19,
	.ppt_pl3_fppt = 26,
};

static const struct power_limits ppt_performance_profile = {
	.ppt_pl1_spl = 28,
	.ppt_pl2_sppt = 35,
	.ppt_pl3_fppt = 45,
};

static struct timer_list fan_curve_timer;

struct zotac_platform_data {
	struct device *hwmon_dev;
	struct mutex update_lock;
	unsigned int fan_rpm;
	unsigned int pwm;
	unsigned int pwm_enable;
	unsigned int temp;
	unsigned long last_updated;
	bool valid;
	bool curve_enabled;

	/* Fan curve points */
	unsigned int curve_temp[FAN_CURVE_POINTS]; /* Temperature points */
	unsigned int curve_pwm[FAN_CURVE_POINTS]; /* PWM/duty points */

	/* DPTC values */
	struct device *ppdev;
	struct device *fw_attr_dev;
	struct kset *fw_attr_kset;

	bool wmi_dptc_supported;
	struct power_limits current_power_limits;
	enum platform_profile_option current_profile;
	/* TODO: hacking - must be removed later */
	unsigned int ppt_pl1_stapm_time_const;
	unsigned int ppt_pl2_sppt_time_const;
	unsigned int ppt_platform_sppt;
};

static struct platform_device *zotac_platform_device;
static DEFINE_MUTEX(ec_mutex);
static struct resource ec_io_ports[] = {
	{
		.start = EC_COMMAND_PORT,
		.end = EC_COMMAND_PORT,
		.name = "ec-command",
		.flags = IORESOURCE_IO,
	},
	{
		.start = EC_DATA_PORT,
		.end = EC_DATA_PORT,
		.name = "ec-data",
		.flags = IORESOURCE_IO,
	},
};

static u8 ec_read_byte(u16 addr)
{
	u8 addr_upper = (addr >> 8) & 0xFF;
	u8 addr_lower = addr & 0xFF;
	u8 value;

	mutex_lock(&ec_mutex);

	/* Select upper byte address */
	outb(0x2E, EC_COMMAND_PORT);
	outb(0x11, EC_DATA_PORT);
	outb(0x2F, EC_COMMAND_PORT);
	outb(addr_upper, EC_DATA_PORT);

	/* Select lower byte address */
	outb(0x2E, EC_COMMAND_PORT);
	outb(0x10, EC_DATA_PORT);
	outb(0x2F, EC_COMMAND_PORT);
	outb(addr_lower, EC_DATA_PORT);

	/* Read data */
	outb(0x2E, EC_COMMAND_PORT);
	outb(0x12, EC_DATA_PORT);
	outb(0x2F, EC_COMMAND_PORT);
	value = inb(EC_DATA_PORT);

	mutex_unlock(&ec_mutex);

	return value;
}

static int ec_write_byte(u16 addr, u8 value)
{
	u8 addr_upper = (addr >> 8) & 0xFF;
	u8 addr_lower = addr & 0xFF;

	mutex_lock(&ec_mutex);

	/* Select upper byte address */
	outb(0x2E, EC_COMMAND_PORT);
	outb(0x11, EC_DATA_PORT);
	outb(0x2F, EC_COMMAND_PORT);
	outb(addr_upper, EC_DATA_PORT);

	/* Select lower byte address */
	outb(0x2E, EC_COMMAND_PORT);
	outb(0x10, EC_DATA_PORT);
	outb(0x2F, EC_COMMAND_PORT);
	outb(addr_lower, EC_DATA_PORT);

	/* Write data */
	outb(0x2E, EC_COMMAND_PORT);
	outb(0x12, EC_DATA_PORT);
	outb(0x2F, EC_COMMAND_PORT);
	outb(value, EC_DATA_PORT);

	mutex_unlock(&ec_mutex);

	return 0;
}

static int send_dptc_cmd(u8 cmd_id, u32 value)
{
	struct acpi_buffer input = { 0, NULL };
	struct acpi_buffer output = { ACPI_ALLOCATE_BUFFER, NULL };
	u8 *buffer;
	acpi_status status;
	int ret;

	buffer = kzalloc(8, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	buffer[0] = cmd_id;
	*(u32 *)(buffer + 4) = value;

	input.length = 8;
	input.pointer = buffer;

	status = wmi_evaluate_method(AMD_APU_WMI_METHODS_GUID, 0, 9,
				&input, &output);

	ret = ACPI_SUCCESS(status) ? 0 : -EIO;

	kfree(buffer);
	if (output.pointer)
		kfree(output.pointer);

	return ret;
}

static struct zotac_platform_data *zotac_platform_update_device(struct device *dev)
{
	struct zotac_platform_data *data = dev_get_drvdata(dev);
	unsigned long current_time = jiffies;

	if (time_after(current_time, data->last_updated + HZ) || !data->valid) {
		mutex_lock(&data->update_lock);

		data->pwm_enable = ec_read_byte(EC_FAN_CTRL_ADDR);
		data->pwm = ec_read_byte(EC_FAN_DUTY_ADDR);

		u32 upper = ec_read_byte(EC_FAN_SPEED_UPPER_ADDR);
		u32 lower = ec_read_byte(EC_FAN_SPEED_LOWER_ADDR);
		data->fan_rpm = (upper << 8) | lower;

		data->temp = ec_read_byte(EC_CPU_TEMP_ADDR);

		data->last_updated = current_time;
		data->valid = true;

		mutex_unlock(&data->update_lock);
	}

	return data;
}

/* Internal version doesn't acquire the lock */
static int set_fan_duty_internal(unsigned int duty_percent)
{
	u8 duty_val;

	if (duty_percent > 100)
		return -EINVAL;

	duty_val =
		(duty_percent * (PWM_MAX - PWM_MIN)) / 100 +
		PWM_MIN;
	return ec_write_byte(EC_FAN_DUTY_ADDR, duty_val);
}

static void fan_curve_function(struct timer_list *t)
{
	struct zotac_platform_data *data = platform_get_drvdata(zotac_platform_device);
	unsigned int current_temp;
	unsigned int pwm = 0;
	int i;

	if (!data || !data->curve_enabled) {
		if (data && data->curve_enabled)
			mod_timer(&fan_curve_timer, jiffies + HZ);
		return;
	}

	mutex_lock(&data->update_lock);

	current_temp = ec_read_byte(EC_CPU_TEMP_ADDR);
	data->temp = current_temp;

	pwm = data->curve_pwm[0];

	if (current_temp >= data->curve_temp[FAN_CURVE_POINTS - 1]) {
		/* Above highest temperature point - use maximum PWM */
		pwm = data->curve_pwm[FAN_CURVE_POINTS - 1];
	} else {
		/* Find the temperature range and interpolate */
		for (i = 0; i < FAN_CURVE_POINTS - 1; i++) {
			if (current_temp >= data->curve_temp[i] &&
			    current_temp < data->curve_temp[i + 1]) {
				/* Linear interpolation between points */
				int temp_range = data->curve_temp[i + 1] -
						 data->curve_temp[i];
				int pwm_range = data->curve_pwm[i + 1] -
						data->curve_pwm[i];
				int temp_offset =
					current_temp - data->curve_temp[i];

				if (temp_range > 0) {
					pwm = data->curve_pwm[i] +
					      (pwm_range * temp_offset) /
						      temp_range;
				} else {
					pwm = data->curve_pwm[i];
				}

				break;
			}
		}
	}

	set_fan_duty_internal(pwm);
	mutex_unlock(&data->update_lock);

	mod_timer(&fan_curve_timer, jiffies + HZ);
}

/* Fan speed RPM */
static ssize_t fan1_input_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct zotac_platform_data *data = zotac_platform_update_device(dev);
	return sprintf(buf, "%u\n", data->fan_rpm);
}
static DEVICE_ATTR_RO(fan1_input);

/* Fan mode */

static int set_pwm_enable(struct device *dev, u8 mode)
{
	struct zotac_platform_data *data = dev_get_drvdata(dev);
	int err = 0;
	u8 ec_mode;

	/* Convert from standard modes to EC-specific modes */
	switch (mode) {
	case PWM_ENABLE_OFF:
		/* If supported by EC, turn fan off */
		return -EOPNOTSUPP; /* If EC doesn't support OFF mode */
	case PWM_ENABLE_MANUAL:
		ec_mode =
			EC_FAN_MODE_MANUAL; /* Assuming this is your actual EC value */
		data->curve_enabled = false;
		if (data->curve_enabled) {
			data->curve_enabled = false;
			timer_delete(&fan_curve_timer);
		}
		break;
	case PWM_ENABLE_AUTO:
		ec_mode =
			EC_FAN_MODE_AUTO; /* Assuming this is your actual EC value */
		data->curve_enabled = false;
		if (data->curve_enabled) {
			data->curve_enabled = false;
			timer_delete(&fan_curve_timer);
		}
		break;
	case PWM_ENABLE_CURVE:
		ec_mode =
			EC_FAN_MODE_MANUAL; /* We'll control manually but via the curve */
		data->curve_enabled = true;
		break;
	default:
		return -EINVAL;
	}

	/* Set mode to EC if needed */
	if (!data->curve_enabled || mode != PWM_ENABLE_CURVE) {
		err = ec_write_byte(EC_FAN_CTRL_ADDR, ec_mode);
	}

	if (err == 0) {
		data->pwm_enable = mode;
		if (mode == PWM_ENABLE_CURVE)
			mod_timer(&fan_curve_timer, jiffies + HZ);
	}

	return err;
}

/* Replace fan1_duty with pwm1 and scale to 0-255 */
static int set_pwm(struct device *dev, u8 pwm_value)
{
	struct zotac_platform_data *data = dev_get_drvdata(dev);
	int err;

	if (pwm_value > PWM_MAX)
		return -EINVAL;

	mutex_lock(&data->update_lock);
	err = ec_write_byte(EC_FAN_DUTY_ADDR, pwm_value);
	if (err == 0)
		data->pwm = pwm_value;
	mutex_unlock(&data->update_lock);

	return err;
}

static ssize_t pwm1_enable_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct zotac_platform_data *data = zotac_platform_update_device(dev);
	return sprintf(buf, "%u\n", data->pwm_enable);
}

static ssize_t pwm1_enable_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	unsigned long mode;
	int err;

	err = kstrtoul(buf, 10, &mode);
	if (err)
		return err;

	if (mode > PWM_ENABLE_CURVE)
		return -EINVAL;

	err = set_pwm_enable(dev, mode);
	if (err)
		return err;

	return count;
}
static DEVICE_ATTR_RW(pwm1_enable);

/* Fan duty cycle (percent) */
static ssize_t pwm1_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct zotac_platform_data *data = zotac_platform_update_device(dev);
	return sprintf(buf, "%u\n", data->pwm);
}

static ssize_t pwm1_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	unsigned long pwm_value;
	int err;

	err = kstrtoul(buf, 10, &pwm_value);
	if (err)
		return err;

	if (pwm_value > PWM_MAX)
		return -EINVAL;

	err = set_pwm(dev, pwm_value);
	if (err)
		return err;

	return count;
}
static DEVICE_ATTR_RW(pwm1);

/* Macro to generate temperature point attributes */
#define CURVE_TEMP_ATTR(index)                                                \
	static ssize_t pwm1_auto_point##index##_temp_show(                    \
		struct device *dev, struct device_attribute *attr, char *buf) \
	{                                                                     \
		struct zotac_platform_data *data = dev_get_drvdata(dev);      \
		return sprintf(buf, "%u\n", data->curve_temp[index - 1]);     \
	}                                                                     \
                                                                              \
	static ssize_t pwm1_auto_point##index##_temp_store(                   \
		struct device *dev, struct device_attribute *attr,            \
		const char *buf, size_t count)                                \
	{                                                                     \
		struct zotac_platform_data *data = dev_get_drvdata(dev);      \
		unsigned long temp;                                           \
		int err;                                                      \
                                                                              \
		err = kstrtoul(buf, 10, &temp);                               \
		if (err)                                                      \
			return err;                                           \
                                                                              \
		mutex_lock(&data->update_lock);                               \
		data->curve_temp[index - 1] = temp;                           \
		mutex_unlock(&data->update_lock);                             \
                                                                              \
		return count;                                                 \
	}                                                                     \
	static DEVICE_ATTR_RW(pwm1_auto_point##index##_temp)

/* Macro to generate PWM point attributes */
#define CURVE_PWM_ATTR(index)                                                 \
	static ssize_t pwm1_auto_point##index##_pwm_show(                     \
		struct device *dev, struct device_attribute *attr, char *buf) \
	{                                                                     \
		struct zotac_platform_data *data = dev_get_drvdata(dev);      \
		return sprintf(buf, "%u\n", data->curve_pwm[index - 1]);      \
	}                                                                     \
                                                                              \
	static ssize_t pwm1_auto_point##index##_pwm_store(                    \
		struct device *dev, struct device_attribute *attr,            \
		const char *buf, size_t count)                                \
	{                                                                     \
		struct zotac_platform_data *data = dev_get_drvdata(dev);      \
		unsigned long pwm;                                            \
		int err;                                                      \
                                                                              \
		err = kstrtoul(buf, 10, &pwm);                                \
		if (err)                                                      \
			return err;                                           \
                                                                              \
		if (pwm > 100)                                                \
			return -EINVAL;                                       \
                                                                              \
		mutex_lock(&data->update_lock);                               \
		data->curve_pwm[index - 1] = pwm;                             \
		mutex_unlock(&data->update_lock);                             \
                                                                              \
		return count;                                                 \
	}                                                                     \
	static DEVICE_ATTR_RW(pwm1_auto_point##index##_pwm)

/* Generate attributes for each point */
CURVE_TEMP_ATTR(1);
CURVE_PWM_ATTR(1);
CURVE_TEMP_ATTR(2);
CURVE_PWM_ATTR(2);
CURVE_TEMP_ATTR(3);
CURVE_PWM_ATTR(3);
CURVE_TEMP_ATTR(4);
CURVE_PWM_ATTR(4);
CURVE_TEMP_ATTR(5);
CURVE_PWM_ATTR(5);
CURVE_TEMP_ATTR(6);
CURVE_PWM_ATTR(6);
CURVE_TEMP_ATTR(7);
CURVE_PWM_ATTR(7);
CURVE_TEMP_ATTR(8);
CURVE_PWM_ATTR(8);
CURVE_TEMP_ATTR(9);
CURVE_PWM_ATTR(9);

/* Temperature reading */
static ssize_t temp1_input_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct zotac_platform_data *data = zotac_platform_update_device(dev);
	return sprintf(buf, "%u\n",
		       data->temp * 1000); /* Convert to milli-degrees */
}
static DEVICE_ATTR_RO(temp1_input);

static struct attribute *zotac_platform_hwmon_attrs[] = {
	&dev_attr_fan1_input.attr,
	&dev_attr_pwm1_enable.attr,
	&dev_attr_pwm1.attr,
	&dev_attr_temp1_input.attr,
	&dev_attr_pwm1_auto_point1_temp.attr,
	&dev_attr_pwm1_auto_point1_pwm.attr,
	&dev_attr_pwm1_auto_point2_temp.attr,
	&dev_attr_pwm1_auto_point2_pwm.attr,
	&dev_attr_pwm1_auto_point3_temp.attr,
	&dev_attr_pwm1_auto_point3_pwm.attr,
	&dev_attr_pwm1_auto_point4_temp.attr,
	&dev_attr_pwm1_auto_point4_pwm.attr,
	&dev_attr_pwm1_auto_point5_temp.attr,
	&dev_attr_pwm1_auto_point5_pwm.attr,
	&dev_attr_pwm1_auto_point6_temp.attr,
	&dev_attr_pwm1_auto_point6_pwm.attr,
	&dev_attr_pwm1_auto_point7_temp.attr,
	&dev_attr_pwm1_auto_point7_pwm.attr,
	&dev_attr_pwm1_auto_point8_temp.attr,
	&dev_attr_pwm1_auto_point8_pwm.attr,
	&dev_attr_pwm1_auto_point9_temp.attr,
	&dev_attr_pwm1_auto_point9_pwm.attr,
	NULL
};

/* DPTC attributes */
#define DPTC_ATTR(display_name, cmd_id, min_val, max_val)                     \
	static ssize_t display_name##_show(                                   \
		struct device *dev, struct device_attribute *attr, char *buf) \
	{                                                                     \
		struct zotac_platform_data *data = dev_get_drvdata(dev);      \
		return sprintf(buf, "%u\n", data->display_name);              \
	}                                                                     \
                                                                              \
	static ssize_t display_name##_store(struct device *dev,               \
					    struct device_attribute *attr,    \
					    const char *buf, size_t count)    \
	{                                                                     \
		struct zotac_platform_data *data = dev_get_drvdata(dev);      \
		unsigned long val;                                            \
		int err;                                                      \
                                                                              \
		if (!data->wmi_dptc_supported)                                \
			return -ENODEV;                                       \
                                                                              \
		err = kstrtoul(buf, 10, &val);                                \
		if (err)                                                      \
			return err;                                           \
                                                                              \
		if (val < min_val || val > max_val)                           \
			return -EINVAL;                                       \
                                                                              \
		mutex_lock(&data->update_lock);                               \
		err = send_dptc_cmd(cmd_id, val);                             \
		if (err == 0)                                                 \
			data->display_name = val;                             \
		mutex_unlock(&data->update_lock);                             \
                                                                              \
		return err ? err : count;                                     \
	}                                                                     \
	static DEVICE_ATTR_RW(display_name)

/* Generate DPTC attributes with AMD-specific naming */
DPTC_ATTR(ppt_pl1_stapm_time_const, DPTC_STAPM_TIME_CONSTANT, 1, 10000);
DPTC_ATTR(ppt_pl2_sppt_time_const, DPTC_SLOW_PPT_CONSTANT, 1, 0xFF);
DPTC_ATTR(ppt_platform_sppt, DPTC_P3T_LIMIT, DPTC_MIN_POWER, DPTC_MAX_POWER);

static struct attribute *zotac_platform_dptc_attrs[] = {
	&dev_attr_ppt_pl1_stapm_time_const.attr,
	&dev_attr_ppt_pl2_sppt_time_const.attr,
	&dev_attr_ppt_platform_sppt.attr,
	NULL
};

static const struct attribute_group zotac_platform_hwmon_group = {
	.attrs = zotac_platform_hwmon_attrs,
};

static const struct attribute_group zotac_platform_dptc_group = {
	.name = "dptc",
	.attrs = zotac_platform_dptc_attrs,
};

static const struct attribute_group *zotac_platform_hwmon_groups[] = {
	&zotac_platform_hwmon_group,
	NULL
};

/* Helper function to show a simple integer attribute */
static ssize_t show_int_attr(struct device *dev,
                             struct device_attribute *attr,
                             char *buf, int value)
{
	return sprintf(buf, "%d\n", value);
}

/* Helper function to show a simple string attribute */
static ssize_t show_string_attr(struct device *dev,
                                struct device_attribute *attr,
                                char *buf, const char *value)
{
	return sprintf(buf, "%s\n", value);
}

#define PPT_ATTR_RO(_name, _attr_name)                        \
	struct device_attribute dev_attr_##_name = {          \
		.attr = { .name = _attr_name, .mode = 0444 }, \
		.show = _name##_show,                         \
	}

#define PPT_ATTR_RW(_name, _attr_name)                        \
	struct device_attribute dev_attr_##_name = {          \
		.attr = { .name = _attr_name, .mode = 0644 }, \
		.show = _name##_show,                         \
		.store = _name##_store,                       \
	}

/* Macro that creates a complete set of attributes for a power limit */
#define DEFINE_POWER_LIMIT_ATTRS(attr_name, cmd_id, min, max, desc)           \
	static ssize_t attr_name##_current_value_show(                        \
		struct device *dev, struct device_attribute *attr, char *buf) \
	{                                                                     \
		struct zotac_platform_data *data =                            \
			platform_get_drvdata(zotac_platform_device);          \
		return show_int_attr(dev, attr, buf,                          \
				     data->current_power_limits.attr_name);   \
	}                                                                     \
                                                                              \
	static ssize_t attr_name##_current_value_store(                       \
		struct device *dev, struct device_attribute *attr,            \
		const char *buf, size_t count)                                \
	{                                                                     \
		struct zotac_platform_data *data =                            \
			platform_get_drvdata(zotac_platform_device);          \
		unsigned long val;                                            \
		int err;                                                      \
                                                                              \
		if (!data->wmi_dptc_supported)                                \
			return -ENODEV;                                       \
                                                                              \
		err = kstrtoul(buf, 10, &val);                                \
		if (err)                                                      \
			return err;                                           \
                                                                              \
		if (val < min || val > max)                                   \
			return -EINVAL;                                       \
                                                                              \
		mutex_lock(&data->update_lock);                               \
		data->current_power_limits.attr_name = val;                   \
		data->current_profile = PLATFORM_PROFILE_CUSTOM;              \
                                                                              \
		err = send_dptc_cmd(cmd_id, val * 1000);                      \
		mutex_unlock(&data->update_lock);                             \
                                                                              \
		return err ? err : count;                                     \
	}                                                                     \
                                                                              \
	static ssize_t attr_name##_min_value_show(                            \
		struct device *dev, struct device_attribute *attr, char *buf) \
	{                                                                     \
		return show_int_attr(dev, attr, buf, min);                    \
	}                                                                     \
                                                                              \
	static ssize_t attr_name##_max_value_show(                            \
		struct device *dev, struct device_attribute *attr, char *buf) \
	{                                                                     \
		return show_int_attr(dev, attr, buf, max);                    \
	}                                                                     \
                                                                              \
	static ssize_t attr_name##_default_value_show(                        \
		struct device *dev, struct device_attribute *attr, char *buf) \
	{                                                                     \
		struct zotac_platform_data *data =                            \
			platform_get_drvdata(zotac_platform_device);          \
		int default_value;                                            \
                                                                              \
		if (data->current_profile == PLATFORM_PROFILE_CUSTOM) {       \
			default_value = ppt_balanced_profile.attr_name;       \
		} else {                                                      \
			const struct power_limits *profile;                   \
                                                                              \
			switch (data->current_profile) {                      \
			case PLATFORM_PROFILE_LOW_POWER:                      \
				profile = &ppt_quiet_profile;                 \
				break;                                        \
			case PLATFORM_PROFILE_BALANCED:                       \
				profile = &ppt_balanced_profile;              \
				break;                                        \
			case PLATFORM_PROFILE_PERFORMANCE:                    \
				profile = &ppt_performance_profile;           \
				break;                                        \
			default:                                              \
				profile = &ppt_balanced_profile;              \
				break;                                        \
			}                                                     \
                                                                              \
			default_value = profile->attr_name;                   \
		}                                                             \
                                                                              \
		return show_int_attr(dev, attr, buf, default_value);          \
	}                                                                     \
                                                                              \
	static ssize_t attr_name##_scalar_increment_show(                     \
		struct device *dev, struct device_attribute *attr, char *buf) \
	{                                                                     \
		return show_int_attr(dev, attr, buf, 1);                      \
	}                                                                     \
                                                                              \
	static ssize_t attr_name##_display_name_show(                         \
		struct device *dev, struct device_attribute *attr, char *buf) \
	{                                                                     \
		return show_string_attr(dev, attr, buf, desc);                \
	}                                                                     \
                                                                              \
	static ssize_t attr_name##_type_show(                                 \
		struct device *dev, struct device_attribute *attr, char *buf) \
	{                                                                     \
		return show_string_attr(dev, attr, buf, "int");               \
	}                                                                     \
                                                                              \
	static PPT_ATTR_RW(attr_name##_current_value, "current_value");       \
	static PPT_ATTR_RO(attr_name##_min_value, "min_value");               \
	static PPT_ATTR_RO(attr_name##_max_value, "max_value");               \
	static PPT_ATTR_RO(attr_name##_default_value, "default_value");       \
	static PPT_ATTR_RO(attr_name##_scalar_increment, "scalar_increment"); \
	static PPT_ATTR_RO(attr_name##_display_name, "display_name");         \
	static PPT_ATTR_RO(attr_name##_type, "type");                         \
                                                                              \
	static struct attribute *attr_name##_attrs[] = {                      \
		&dev_attr_##attr_name##_current_value.attr,                   \
		&dev_attr_##attr_name##_min_value.attr,                       \
		&dev_attr_##attr_name##_max_value.attr,                       \
		&dev_attr_##attr_name##_default_value.attr,                   \
		&dev_attr_##attr_name##_scalar_increment.attr,                \
		&dev_attr_##attr_name##_display_name.attr,                    \
		&dev_attr_##attr_name##_type.attr,                            \
		NULL                                                          \
	};                                                                    \
                                                                              \
	static const struct attribute_group attr_name##_attr_group = {        \
		.name = #attr_name, .attrs = attr_name##_attrs                \
	}

/* Define the power limit attribute groups */
DEFINE_POWER_LIMIT_ATTRS(ppt_pl1_spl, DPTC_SUSTAINED_POWER, PPT_PL1_SPL_MIN,
			 PPT_PL1_SPL_MAX,
			 "CPU Sustained Power Limit (PL1/SPL)");

DEFINE_POWER_LIMIT_ATTRS(ppt_pl2_sppt, DPTC_FAST_POWER_1, PPT_PL2_SPPT_MIN,
			 PPT_PL2_SPPT_MAX,
			 "CPU Short Term Power Limit (PL2/SPPT)");

DEFINE_POWER_LIMIT_ATTRS(ppt_pl3_fppt, DPTC_FAST_POWER_2, PPT_PL3_FPPT_MIN,
			 PPT_PL3_FPPT_MAX, "CPU Fast Power Limit (PL3/FPPT)");

/* Combine all power attribute groups */
static const struct attribute_group *zotac_platform_power_groups[] = {
	&ppt_pl1_spl_attr_group, &ppt_pl2_sppt_attr_group,
	&ppt_pl3_fppt_attr_group, NULL
};

/* Helper function to create all power attribute groups */
static int create_power_attributes(struct platform_device *pdev, struct zotac_platform_data *data)
{
	int i, ret = 0;

	if (!data->wmi_dptc_supported)
		return 0;

	data->fw_attr_dev = device_create(&firmware_attributes_class, NULL, MKDEV(0, 0),
						NULL, "%s", DRIVER_NAME);
	if (IS_ERR(data->fw_attr_dev)) {
		ret = PTR_ERR(data->fw_attr_dev);
		goto fail_class_get;
	}

	data->fw_attr_kset = kset_create_and_add("attributes", NULL,
						&data->fw_attr_dev->kobj);
	if (!data->fw_attr_kset) {
		ret = -ENOMEM;
		goto err_destroy_kset;
	}

	for (i = 0; zotac_platform_power_groups[i]; i++) {
		ret = sysfs_create_group(&data->fw_attr_kset->kobj,
					 zotac_platform_power_groups[i]);
		if (ret) {
			dev_warn(&pdev->dev,
				 "Failed to create power limit group %d\n", i);
			goto error;
		}
	}

	return 0;

error:
	while (--i >= 0)
		sysfs_remove_group(&data->fw_attr_kset->kobj,
				   zotac_platform_power_groups[i]);
err_destroy_kset:
	kset_unregister(data->fw_attr_kset);
fail_class_get:
	device_destroy(&firmware_attributes_class, MKDEV(0, 0));
	return ret;
}

/* Helper function to remove all power attribute groups */
static void remove_power_attributes(struct platform_device *pdev)
{
	struct zotac_platform_data *data = platform_get_drvdata(pdev);
	int i;

	for (i = 0; zotac_platform_power_groups[i]; i++)
		sysfs_remove_group(&data->fw_attr_kset->kobj,
				   zotac_platform_power_groups[i]);

	kset_unregister(data->fw_attr_kset);
	device_destroy(&firmware_attributes_class, MKDEV(0, 0));
}

static int zotac_platform_profile_get(struct device *dev,
				     enum platform_profile_option *profile)
{
	struct zotac_platform_data *data = dev_get_drvdata(dev);
	*profile = data->current_profile;
	return 0;
}

static int zotac_platform_profile_set(struct device *dev,
				     enum platform_profile_option profile)
{
	struct zotac_platform_data *data = dev_get_drvdata(dev);
	const struct power_limits *limits;
	int ret = 0;

	if (!data->wmi_dptc_supported)
		return -ENODEV;

	switch (profile) {
	case PLATFORM_PROFILE_PERFORMANCE:
		limits = &ppt_performance_profile;
		break;
	case PLATFORM_PROFILE_BALANCED:
		limits = &ppt_balanced_profile;
		break;
	case PLATFORM_PROFILE_LOW_POWER:
		limits = &ppt_quiet_profile;
		break;
	case PLATFORM_PROFILE_CUSTOM:
		limits = &data->current_power_limits;
		break;
	default:
		return -EOPNOTSUPP;
	}

	mutex_lock(&data->update_lock);
	ret = send_dptc_cmd(DPTC_SUSTAINED_POWER, limits->ppt_pl1_spl * 1000);
	if (ret == 0)
		ret = send_dptc_cmd(DPTC_FAST_POWER_1, limits->ppt_pl2_sppt * 1000);
	if (ret == 0)
		ret = send_dptc_cmd(DPTC_FAST_POWER_2, limits->ppt_pl3_fppt * 1000);
	if (ret == 0) {
		data->current_profile = profile;
		if (profile != PLATFORM_PROFILE_CUSTOM)
			memcpy(&data->current_power_limits, limits, sizeof(struct power_limits));
	}
	mutex_unlock(&data->update_lock);

	return ret;
}

static int zotac_platform_profile_probe(void *drvdata, unsigned long *choices)
{
	set_bit(PLATFORM_PROFILE_LOW_POWER, choices);
	set_bit(PLATFORM_PROFILE_BALANCED, choices);
	set_bit(PLATFORM_PROFILE_PERFORMANCE, choices);
	set_bit(PLATFORM_PROFILE_CUSTOM, choices);
	return 0;
}

static const struct platform_profile_ops zotac_platform_profile_ops = {
	.probe = zotac_platform_profile_probe,
	.profile_get = zotac_platform_profile_get,
	.profile_set = zotac_platform_profile_set,
};

static int platform_profile_setup(struct zotac_platform_data *data)
{
	struct device *dev = &zotac_platform_device->dev;

	if (!data->wmi_dptc_supported)
		return 0;

	data->ppdev = devm_platform_profile_register(dev, DRIVER_NAME, data,
						     &zotac_platform_profile_ops);
	if (IS_ERR(data->ppdev)) {
		dev_err(dev, "Failed to register platform_profile device\n");
		return PTR_ERR(data->ppdev);
	}

	/* Set default profile */
	zotac_platform_profile_set(dev, PLATFORM_PROFILE_BALANCED);

	return 0;
}

static int zotac_platform_probe(struct platform_device *pdev)
{
	struct zotac_platform_data *data;
	struct device *hwmon_dev;
	int i, ret;

	data = devm_kzalloc(&pdev->dev, sizeof(struct zotac_platform_data),
			    GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->wmi_dptc_supported = wmi_has_guid(AMD_APU_WMI_METHODS_GUID);
	data->valid = false;
	data->curve_enabled = false;
	mutex_init(&data->update_lock);

	for (i = 0; i < FAN_CURVE_POINTS; i++) {
		/* Set default temperature points from 10°C to 90°C */
		data->curve_temp[i] = 10 + (i * 10);
		/* Set default PWM values - simple linear curve from 20% to 100% */
		data->curve_pwm[i] = 20 + (i * 10);
		if (data->curve_pwm[i] > 100)
			data->curve_pwm[i] = 100;
	}

	data->current_profile = PLATFORM_PROFILE_BALANCED;
	memcpy(&data->current_power_limits, &ppt_balanced_profile, sizeof(struct power_limits));
	data->ppt_pl1_stapm_time_const = 300;
	data->ppt_pl2_sppt_time_const = 0x11;
	data->ppt_platform_sppt = 13000;

	hwmon_dev = devm_hwmon_device_register_with_groups(
		&pdev->dev, "zotac_platform", data, zotac_platform_hwmon_groups);
	if (IS_ERR(hwmon_dev))
		return PTR_ERR(hwmon_dev);

	data->hwmon_dev = hwmon_dev;

	if (data->wmi_dptc_supported) {
		ret = sysfs_create_group(&pdev->dev.kobj, &zotac_platform_dptc_group);
		if (ret)
			dev_warn(&pdev->dev, "Failed to create DPTC sysfs group\n");
	}

	platform_set_drvdata(pdev, data);

	timer_setup(&fan_curve_timer, fan_curve_function, 0);

	zotac_platform_update_device(&pdev->dev);

	ret = platform_profile_setup(data);
	if (ret)
		dev_warn(&pdev->dev, "Failed to setup platform profile\n");

	ret = create_power_attributes(pdev, data);
	if (ret)
		dev_warn(&pdev->dev, "Failed to setup firmware attributes\n");

	return 0;
}

static void zotac_platform_remove(struct platform_device *pdev)
{
	struct zotac_platform_data *data = platform_get_drvdata(pdev);

	if (data && data->wmi_dptc_supported) {
		sysfs_remove_group(&pdev->dev.kobj, &zotac_platform_dptc_group);
		remove_power_attributes(pdev);
	}
}

static struct platform_driver zotac_platform_driver = {
	.driver = {
		.name = DRIVER_NAME,
	},
	.probe = zotac_platform_probe,
	.remove = zotac_platform_remove,
};

static const struct dmi_system_id zotac_platform_dmi_table[] __initconst = {
    {
        .ident = "Zotac Gaming Handheld",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "ZOTAC"),
            DMI_MATCH(DMI_BOARD_NAME, "G0A1W"),
        },
    },
    {
        .ident = "Zotac ZONE",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "ZOTAC"),
            DMI_MATCH(DMI_PRODUCT_NAME, "ZOTAC GAMING ZONE"),
        },
    },
    {}  /* Terminate list */
};
MODULE_DEVICE_TABLE(dmi, zotac_platform_dmi_table);

static int __init zotac_platform_init(void)
{
	int err;

	if (!dmi_check_system(zotac_platform_dmi_table)) {
		pr_info("No compatible Zotac hardware found\n");
		return -ENODEV;
	}

	/* Request I/O regions */
	if (!request_region(EC_COMMAND_PORT, 1, "zotac_platform_ec") ||
	    !request_region(EC_DATA_PORT, 1, "zotac_platform_ec")) {
		pr_err("Failed to request EC I/O ports\n");
		err = -EBUSY;
		goto err_release;
	}

	zotac_platform_device = platform_device_register_simple(
		DRIVER_NAME, -1, ec_io_ports, ARRAY_SIZE(ec_io_ports));
	if (IS_ERR(zotac_platform_device)) {
		err = PTR_ERR(zotac_platform_device);
		goto err_release;
	}

	err = platform_driver_register(&zotac_platform_driver);
	if (err)
		goto err_device_unregister;

	return 0;

err_device_unregister:
	platform_device_unregister(zotac_platform_device);
err_release:
	release_region(EC_COMMAND_PORT, 1);
	release_region(EC_DATA_PORT, 1);
	return err;
}

static void __exit zotac_platform_exit(void)
{
	timer_delete_sync(&fan_curve_timer);

	platform_driver_unregister(&zotac_platform_driver);
	platform_device_unregister(zotac_platform_device);
	release_region(EC_COMMAND_PORT, 1);
	release_region(EC_DATA_PORT, 1);
}

module_init(zotac_platform_init);
module_exit(zotac_platform_exit);

MODULE_AUTHOR("Luke D. Jones");
MODULE_DESCRIPTION("Zotac Handheld Platform Driver");
MODULE_LICENSE("GPL");
