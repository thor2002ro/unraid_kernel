// SPDX-License-Identifier: GPL-2.0
//
// CZ.NIC's Turris Omnia LEDs driver
//
// 2020 by Marek Behun <marek.behun@nic.cz>

#include <linux/i2c.h>
#include <linux/leds.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <uapi/linux/uleds.h>
#include "leds.h"

#define OMNIA_BOARD_LEDS		12

#define CMD_LED_MODE			3
#define CMD_LED_MODE_LED(l)		((l) & 0x0f)
#define CMD_LED_MODE_USER		0x10

#define CMD_LED_STATE			4
#define CMD_LED_STATE_LED(l)		((l) & 0x0f)
#define CMD_LED_STATE_ON		0x10

#define CMD_LED_COLOR			5
#define CMD_LED_SET_BRIGHTNESS		7
#define CMD_LED_GET_BRIGHTNESS		8

#define OMNIA_CMD			0

#define OMNIA_CMD_LED_COLOR_LED		1
#define OMNIA_CMD_LED_COLOR_R		2
#define OMNIA_CMD_LED_COLOR_G		3
#define OMNIA_CMD_LED_COLOR_B		4
#define OMNIA_CMD_LED_COLOR_LEN		5

struct omnia_led {
	struct led_classdev cdev;
	int reg, color;
};

#define to_omnia_led(l)	container_of(l, struct omnia_led, cdev)

struct omnia_leds {
	struct i2c_client *client;
	struct mutex lock;
	u8 cache[OMNIA_BOARD_LEDS][3];
	int nleds;
	struct omnia_led leds[0];
};

static int omnia_led_brightness_set_blocking(struct led_classdev *cdev,
					     enum led_brightness brightness)
{
	static const u8 color2cmd[] = {
		[LED_COLOR_ID_RED] = OMNIA_CMD_LED_COLOR_R,
		[LED_COLOR_ID_GREEN] = OMNIA_CMD_LED_COLOR_G,
		[LED_COLOR_ID_BLUE] = OMNIA_CMD_LED_COLOR_B,
	};
	struct omnia_leds *leds = dev_get_drvdata(cdev->dev->parent);
	struct omnia_led *led = to_omnia_led(cdev);
	u8 buf[OMNIA_CMD_LED_COLOR_LEN], state;
	int ret;

	mutex_lock(&leds->lock);

	buf[OMNIA_CMD] = CMD_LED_COLOR;
	buf[OMNIA_CMD_LED_COLOR_LED] = led->reg;

	if (led->color == LED_COLOR_ID_WHITE) {
		buf[OMNIA_CMD_LED_COLOR_R] = brightness;
		buf[OMNIA_CMD_LED_COLOR_G] = brightness;
		buf[OMNIA_CMD_LED_COLOR_B] = brightness;
	} else {
		buf[OMNIA_CMD_LED_COLOR_R] = leds->cache[led->reg][0];
		buf[OMNIA_CMD_LED_COLOR_G] = leds->cache[led->reg][1];
		buf[OMNIA_CMD_LED_COLOR_B] = leds->cache[led->reg][2];
		buf[color2cmd[led->color]] = brightness;
	}

	state = CMD_LED_STATE_LED(led->reg);
	if (buf[OMNIA_CMD_LED_COLOR_R] || buf[OMNIA_CMD_LED_COLOR_G] ||
	    buf[OMNIA_CMD_LED_COLOR_B])
		state |= CMD_LED_STATE_ON;

	ret = i2c_smbus_write_byte_data(leds->client, CMD_LED_STATE, state);
	if (ret >= 0 && (state & CMD_LED_STATE_ON))
		ret = i2c_master_send(leds->client, buf, 5);

	leds->cache[led->reg][0] = buf[OMNIA_CMD_LED_COLOR_R];
	leds->cache[led->reg][1] = buf[OMNIA_CMD_LED_COLOR_G];
	leds->cache[led->reg][2] = buf[OMNIA_CMD_LED_COLOR_B];

	mutex_unlock(&leds->lock);

	return ret;
}

static int omnia_led_register(struct omnia_leds *leds,
			      struct fwnode_handle *node)
{
	struct i2c_client *client = leds->client;
	struct led_init_data init_data = {};
	struct device *dev = &client->dev;
	struct omnia_led *led;
	int ret, nsources, color;
	u32 reg, led_sources[3];

	led = &leds->leds[leds->nleds];

	ret = fwnode_property_read_u32(node, "reg", &reg);
	if (ret) {
		dev_err(dev, "Node %pfw: 'reg' read failed!\n", node);
		return ret;
	}

	if (reg >= OMNIA_BOARD_LEDS) {
		dev_warn(dev, "Node %pfw: invalid 'reg' value %u\n", node, reg);
		return 0;
	}

	nsources = fwnode_property_count_u32(node, "led-sources");
	if (nsources != 1 && nsources != 3) {
		dev_warn(dev, "Node %pfw: either 1 or 3 'led-sources' must be specified!\n",
			 node);
		return 0;
	}

	ret = fwnode_property_read_u32_array(node, "led-sources", led_sources,
					     nsources);
	if (ret) {
		dev_err(dev, "Node %pfw: 'led-sources' read failed: %i\n",
			node, ret);
		return ret;
	}

	ret = fwnode_property_read_u32(node, "color", &led->color);
	if (ret) {
		dev_warn(dev, "Node %pfw: 'color' read failed!\n",
			 node);
		return 0;
	}

	if (nsources == 3) {
		if (led_sources[0] != 3 * reg ||
		    led_sources[1] != 3 * reg + 1 ||
		    led_sources[2] != 3 * reg + 2) {
			dev_warn(dev, "Node %pfw has invalid 'led-sources'!\n",
				 node);
			return 0;
		}

		color = LED_COLOR_ID_WHITE;
	} else {
		const int led_source_to_color[3] = {
			LED_COLOR_ID_RED,
			LED_COLOR_ID_GREEN,
			LED_COLOR_ID_BLUE
		};
		color = led_source_to_color[led_sources[0] % 3];

		if (led_sources[0] < 3 * reg || led_sources[0] > 3 * reg + 2) {
			dev_warn(dev, "Node %pfw has invalid 'led-sources'!\n",
				 node);
			return 0;
		}
	}

	if (led->color != color) {
		dev_warn(dev, "Node %pfw: 'color' should be %s!\n", node,
			 led_colors[color]);
		return 0;
	}

	init_data.devicename = "omnia";
	init_data.fwnode = node;
	init_data.devname_mandatory = true;

	led->reg = reg;
	led->cdev.max_brightness = 255;
	led->cdev.brightness_set_blocking = omnia_led_brightness_set_blocking;

	fwnode_property_read_string(node, "linux,default-trigger",
				    &led->cdev.default_trigger);

	/* put the LED into software mode */
	ret = i2c_smbus_write_byte_data(client, CMD_LED_MODE,
					CMD_LED_MODE_LED(reg) |
					CMD_LED_MODE_USER);
	if (ret < 0) {
		dev_err(dev, "Cannot set LED %pfw to software mode: %i\n", node,
			ret);
		return ret;
	}

	/* disable the LED */
	ret = i2c_smbus_write_byte_data(client, CMD_LED_STATE,
						CMD_LED_STATE_LED(reg));
	if (ret < 0) {
		dev_err(dev, "Cannot set LED %pfw brightness: %i\n", node, ret);
		return ret;
	}

	ret = devm_led_classdev_register_ext(dev, &led->cdev, &init_data);
	if (ret < 0) {
		dev_err(dev, "Cannot register LED %pfw: %i\n", node, ret);
		return ret;
	}

	++leds->nleds;

	return 0;
}

static int omnia_leds_probe(struct i2c_client *client,
			    const struct i2c_device_id *id)
{
	struct device *dev = &client->dev;
	struct device_node *np = dev->of_node, *child;
	struct omnia_leds *leds;
	int ret, count;

	count = of_get_available_child_count(np);
	if (!count) {
		dev_err(dev, "LEDs are not defined in device tree!\n");
		return -ENODEV;
	} else if (count > 3 * OMNIA_BOARD_LEDS) {
		dev_err(dev, "Too many LEDs defined in device tree!\n");
		return -EINVAL;
	}

	leds = devm_kzalloc(dev, sizeof(*leds) + count * sizeof(leds->leds[0]),
			    GFP_KERNEL);
	if (!leds)
		return -ENOMEM;

	leds->client = client;
	i2c_set_clientdata(client, leds);

	mutex_init(&leds->lock);

	for_each_available_child_of_node(np, child) {
		ret = omnia_led_register(leds, &child->fwnode);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int omnia_leds_remove(struct i2c_client *client)
{
	u8 buf[OMNIA_CMD_LED_COLOR_LEN];

	/* put all LEDs into default (HW triggered) mode */
	i2c_smbus_write_byte_data(client, CMD_LED_MODE,
				  CMD_LED_MODE_LED(OMNIA_BOARD_LEDS));

	/* set all LEDs color to [255, 255, 255] */
	buf[OMNIA_CMD] = CMD_LED_COLOR;
	buf[OMNIA_CMD_LED_COLOR_LED] = OMNIA_BOARD_LEDS;
	buf[OMNIA_CMD_LED_COLOR_R] = 255;
	buf[OMNIA_CMD_LED_COLOR_G] = 255;
	buf[OMNIA_CMD_LED_COLOR_B] = 255;

	i2c_master_send(client, buf, 5);

	return 0;
}

static const struct of_device_id of_omnia_leds_match[] = {
	{ .compatible = "cznic,turris-omnia-leds", },
	{},
};

static const struct i2c_device_id omnia_id[] = {
	{ "omnia", 0 },
	{ }
};

static struct i2c_driver omnia_leds_driver = {
	.probe		= omnia_leds_probe,
	.remove		= omnia_leds_remove,
	.id_table	= omnia_id,
	.driver		= {
		.name	= "leds-turris-omnia",
		.of_match_table = of_omnia_leds_match,
	},
};

module_i2c_driver(omnia_leds_driver);

MODULE_AUTHOR("Marek Behun <marek.behun@nic.cz>");
MODULE_DESCRIPTION("CZ.NIC's Turris Omnia LEDs");
MODULE_LICENSE("GPL v2");
