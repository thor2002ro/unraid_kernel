// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright 2019 IBM Corp. */

#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/sys_soc.h>

static u32 security_status;

static struct {
	const char *name;
	const u32 id;
} const rev_table[] = {
	/* AST2400 */
	{ "AST2400", 0x02000303 },
	{ "AST1400", 0x02010103 },
	{ "AST1250", 0x02010303 },
	/* AST2500 */
	{ "AST2500", 0x04000303 },
	{ "AST2510", 0x04000103 },
	{ "AST2520", 0x04000203 },
	{ "AST2530", 0x04000403 },
	/* AST2600 */
	{ "AST2600", 0x05000303 },
	{ "AST2620", 0x05010203 },
	{ "AST2605", 0x05030103 },
	{ "AST2625", 0x05030403 },
};

static const char *siliconid_to_name(u32 siliconid)
{
	unsigned int id = siliconid & 0xff00ffff;
	unsigned int i;

	for (i = 0 ; i < ARRAY_SIZE(rev_table) ; ++i) {
		if (rev_table[i].id == id)
			return rev_table[i].name;
	}

	return "Unknown";
}

static const char *siliconid_to_rev(u32 siliconid)
{
	unsigned int rev = (siliconid >> 16) & 0xff;
	unsigned int gen = (siliconid >> 24) & 0xff;

	if (gen < 0x5) {
		/* AST2500 and below */
		switch (rev) {
		case 0:
			return "A0";
		case 1:
			return "A1";
		case 3:
			return "A2";
		}
	} else {
		/* AST2600 */
		switch (rev) {
		case 0:
			return "A0";
		case 1:
			return "A1";
		case 2:
			return "A2";
		case 3:
			return "A3";
		}
	}

	return "??";
}

#define SEC_STATUS		0x14
#define ABR_IMAGE_SOURCE	BIT(13)
#define OTP_PROTECTED		BIT(8)
#define LOW_SEC_KEY		BIT(7)
#define SECURE_BOOT		BIT(6)
#define UART_BOOT		BIT(5)

static ssize_t abr_image_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!(security_status & ABR_IMAGE_SOURCE));
}
static DEVICE_ATTR_RO(abr_image);

static ssize_t low_security_key_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!(security_status & LOW_SEC_KEY));
}
static DEVICE_ATTR_RO(low_security_key);

static ssize_t otp_protected_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!(security_status & OTP_PROTECTED));
}
static DEVICE_ATTR_RO(otp_protected);

static ssize_t secure_boot_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!(security_status & SECURE_BOOT));
}
static DEVICE_ATTR_RO(secure_boot);

static ssize_t uart_boot_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	/* Invert the bit, as 1 is boot from SPI/eMMC */
	return sprintf(buf, "%d\n", !(security_status & UART_BOOT));
}
static DEVICE_ATTR_RO(uart_boot);

static struct attribute *aspeed_attrs[] = {
	&dev_attr_abr_image.attr,
	&dev_attr_low_security_key.attr,
	&dev_attr_otp_protected.attr,
	&dev_attr_secure_boot.attr,
	&dev_attr_uart_boot.attr,
	NULL,
};
ATTRIBUTE_GROUPS(aspeed);

static int __init aspeed_socinfo_init(void)
{
	struct soc_device_attribute *attrs;
	struct soc_device *soc_dev;
	struct device_node *np;
	void __iomem *reg;
	bool has_chipid = false;
	bool has_sbe = false;
	u32 siliconid;
	u32 chipid[2];
	const char *machine = NULL;

	np = of_find_compatible_node(NULL, NULL, "aspeed,silicon-id");
	if (!of_device_is_available(np)) {
		of_node_put(np);
		return -ENODEV;
	}

	reg = of_iomap(np, 0);
	if (!reg) {
		of_node_put(np);
		return -ENODEV;
	}
	siliconid = readl(reg);
	iounmap(reg);

	/* This is optional, the ast2400 does not have it */
	reg = of_iomap(np, 1);
	if (reg) {
		has_chipid = true;
		chipid[0] = readl(reg);
		chipid[1] = readl(reg + 4);
		iounmap(reg);
	}
	of_node_put(np);

	/* AST2600 only */
	np = of_find_compatible_node(NULL, NULL, "aspeed,ast2600-sbc");
	if (of_device_is_available(np)) {
		void __iomem *base = of_iomap(np, 0);
		if (!base) {
			of_node_put(np);
			return -ENODEV;
		}
		security_status = readl(base + SEC_STATUS);
		has_sbe = true;
		iounmap(base);
		of_node_put(np);
	}

	attrs = kzalloc(sizeof(*attrs), GFP_KERNEL);
	if (!attrs)
		return -ENODEV;

	/*
	 * Machine: Romulus BMC
	 * Family: AST2500
	 * Revision: A1
	 * SoC ID: raw silicon revision id
	 * Serial Number: 64-bit chipid
	 */

	np = of_find_node_by_path("/");
	of_property_read_string(np, "model", &machine);
	if (machine)
		attrs->machine = kstrdup(machine, GFP_KERNEL);
	of_node_put(np);

	attrs->family = siliconid_to_name(siliconid);
	attrs->revision = siliconid_to_rev(siliconid);
	attrs->soc_id = kasprintf(GFP_KERNEL, "%08x", siliconid);

	if (has_chipid)
		attrs->serial_number = kasprintf(GFP_KERNEL, "%08x%08x",
						 chipid[1], chipid[0]);

	if (has_sbe)
		attrs->custom_attr_group = aspeed_groups[0];

	soc_dev = soc_device_register(attrs);
	if (IS_ERR(soc_dev)) {
		kfree(attrs->soc_id);
		kfree(attrs->serial_number);
		kfree(attrs);
		return PTR_ERR(soc_dev);
	}

	pr_info("ASPEED %s rev %s (%s)\n",
			attrs->family,
			attrs->revision,
			attrs->soc_id);

	if (has_sbe) {
		pr_info("AST2600 secure boot %s\n",
			(security_status & SECURE_BOOT) ? "enabled" : "disabled");
	}

	return 0;
}
early_initcall(aspeed_socinfo_init);
