// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <linux/export.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/thermal.h>
#include <linux/types.h>
#include <linux/string.h>

#include "thermal_core.h"

struct sensor_interface {
	struct thermal_zone_device *tz;
	int coeff;

	struct list_head node;
};

struct multi_sensor_thermal_zone {
	struct thermal_zone_device *tz;
	struct mutex sensors_lock;
	struct list_head sensors;

	struct list_head node;
};

static DEFINE_MUTEX(multi_tz_mutex);
static LIST_HEAD(multi_tz_list);

#define TJ_MAX 120000

static int multi_sensor_get_temp(struct thermal_zone_device *tz, int *temp)
{
	struct multi_sensor_thermal_zone *multi_tz = tz->devdata;
	struct sensor_interface *sensor;
	int accumulated_temp = 0;
	u32 accumulated_coeff;
	int ret;

	mutex_lock(&multi_tz->sensors_lock);

	if (list_empty(&multi_tz->sensors)) {
		mutex_unlock(&multi_tz->sensors_lock);
		return -ENODEV;
	}

	list_for_each_entry(sensor, &multi_tz->sensors, node) {
		ret = thermal_zone_get_temp(sensor->tz, temp);
		if (ret) {
			mutex_unlock(&multi_tz->sensors_lock);
			return ret;
		}

		accumulated_temp += *temp * sensor->coeff;
		accumulated_coeff += sensor->coeff;
	}

	mutex_unlock(&multi_tz->sensors_lock);

	*temp = accumulated_temp / accumulated_coeff;
	return ret;
}

struct thermal_zone_device_ops multi_sensor_ops = {
	.get_temp = multi_sensor_get_temp,
};

int thermal_multi_sensor_validate_coeff(int *coeff, int count, int offset)
{
	int max_accumulated_temp = 0;
	int i;

	for (i = 0; i < count; i++) {
		max_accumulated_temp += TJ_MAX * coeff[i];
		if (max_accumulated_temp < 0)
			return -EOVERFLOW;
	}

	max_accumulated_temp += offset;
	return max_accumulated_temp < 0 ? -EOVERFLOW : 0;
}

static struct thermal_zone_device *multi_sensor_tz_alloc(const char *name)
{
	struct thermal_zone_device *tz;
	struct thermal_zone_params tzp = {};
	struct multi_sensor_thermal_zone *multi_tz;

	tz = thermal_zone_get_zone_by_name(name);
	if (!IS_ERR(tz)) {
		mutex_unlock(&multi_tz_mutex);
		return tz;
	}

	multi_tz = kzalloc(sizeof(*multi_tz), GFP_KERNEL);
	if (!multi_tz)
		return ERR_PTR(-ENOMEM);
	mutex_init(&multi_tz->sensors_lock);
	INIT_LIST_HEAD(&multi_tz->sensors);

	tzp.no_hwmon = true;
	tzp.slope = 1;
	tzp.offset = 0;

	tz = thermal_tripless_zone_device_register(name, multi_tz,
						   &multi_sensor_ops, &tzp);
	if (IS_ERR(tz)) {
		kfree(multi_tz);
	} else {
		multi_tz->tz = tz;
		list_add(&multi_tz->node, &multi_tz_list);
	}

	return tz;
}

int thermal_multi_sensor_register(const char *name,
	struct thermal_zone_device *sensor_tz, int coeff)
{
	struct thermal_zone_device *tz;
	struct multi_sensor_thermal_zone *multi_tz;
	struct sensor_interface *sensor;

	mutex_lock(&multi_tz_mutex);

	tz = multi_sensor_tz_alloc(name);
	if (IS_ERR(tz)) {
		mutex_unlock(&multi_tz_mutex);
		return PTR_ERR(tz);
	}
	multi_tz =  tz->devdata;

	sensor = kzalloc(sizeof(*sensor), GFP_KERNEL);
	if (!sensor) {
		mutex_unlock(&multi_tz_mutex);
		return -ENOMEM;
	}

	sensor->tz = sensor_tz;
	sensor->coeff = coeff;
	mutex_lock(&multi_tz->sensors_lock);
	list_add(&sensor->node, &multi_tz->sensors);
	mutex_unlock(&multi_tz->sensors_lock);

	thermal_zone_device_enable(tz);

	mutex_unlock(&multi_tz_mutex);

	return 0;
}

void thermal_multi_sensor_unregister(struct thermal_zone_device *sensor_tz)
{
	struct multi_sensor_thermal_zone *multi_tz;
	struct sensor_interface *sensor, *tmp;

	mutex_lock(&multi_tz_mutex);
	list_for_each_entry(multi_tz, &multi_tz_list, node) {
		mutex_lock(&multi_tz->sensors_lock);
		list_for_each_entry_safe(sensor, tmp, &multi_tz->sensors, node) {
			if (sensor->tz == sensor_tz) {
				list_del(&sensor->node);
				kfree(sensor);
				break;
			}
		}

		if (list_empty(&multi_tz->sensors)) {
			thermal_zone_device_unregister(multi_tz->tz);
			mutex_unlock(&multi_tz->sensors_lock);
			kfree(multi_tz);
		} else {
			mutex_unlock(&multi_tz->sensors_lock);
		}
	}
	mutex_unlock(&multi_tz_mutex);
}
