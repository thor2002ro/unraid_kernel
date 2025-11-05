// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2025 Aspeed Technology Inc.
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/phy/pcie.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/regulator/consumer.h>
#include <linux/reset.h>
#include <linux/slab.h>

/* AST2600 PCIe Host Controller Registers */
#define PEHR_GLOBAL		0x30
#define  AST2600_PORT_TYPE_MASK		GENMASK(5, 4)
#define  AST2600_PORT_TYPE(x)		FIELD_PREP(AST2600_PORT_TYPE_MASK, x)
#define PEHR_LOCK		0x7c
#define  PCIE_UNLOCK			0xa8

/* AST2700 PEHR */
#define PEHR_MISC_58		0x58
#define  LOCAL_SCALE_SUP		BIT(0)
#define PEHR_MISC_5C		0x5c
#define  CONFIG_RC_DEVICE		BIT(30)
#define PEHR_MISC_60		0x60
#define  AST2700_PORT_TYPE_MASK		GENMASK(7, 4)
#define  PORT_TYPE_ROOT			BIT(6)
#define PEHR_MISC_70		0x70
#define  POSTED_DATA_CREDITS(x)		FIELD_PREP(GENMASK(15, 0), x)
#define  POSTED_HEADER_CREDITS(x)	FIELD_PREP(GENMASK(27, 16), x)
#define PEHR_MISC_78		0x78
#define  COMPLETION_DATA_CREDITS(x)	FIELD_PREP(GENMASK(15, 0), x)
#define  COMPLETION_HEADER_CREDITS(x)	FIELD_PREP(GENMASK(27, 16), x)

/**
 * struct aspeed_pcie_phy - PCIe PHY information
 * @dev: pointer to device structure
 * @reg: PCIe host register base address
 * @phy: pointer to PHY structure
 * @platform: platform specific information
 */
struct aspeed_pcie_phy {
	struct device *dev;
	void __iomem *reg;
	struct phy *phy;
	const struct aspeed_pcie_phy_platform *platform;
};

/**
 * struct aspeed_pcie_phy_platform - Platform information
 * @phy_ops: phy operations
 */
struct aspeed_pcie_phy_platform {
	const struct phy_ops *phy_ops;
};

static int ast2600_phy_init(struct phy *phy)
{
	struct aspeed_pcie_phy *pcie_phy = phy_get_drvdata(phy);

	writel(PCIE_UNLOCK, pcie_phy->reg + PEHR_LOCK);

	return 0;
}

static int ast2600_phy_set_mode(struct phy *phy, enum phy_mode mode,
				int submode)
{
	struct aspeed_pcie_phy *pcie_phy = phy_get_drvdata(phy);

	switch (submode) {
	case PHY_MODE_PCIE_RC:
		writel(AST2600_PORT_TYPE(0x3), pcie_phy->reg + PEHR_GLOBAL);
		break;
	default:
		dev_err(&phy->dev, "Unsupported submode %d\n", submode);
		return -EINVAL;
	}

	return 0;
}

static const struct phy_ops ast2600_phy_ops = {
	.init		= ast2600_phy_init,
	.set_mode	= ast2600_phy_set_mode,
	.owner		= THIS_MODULE,
};

static int ast2700_phy_init(struct phy *phy)
{
	struct aspeed_pcie_phy *pcie_phy = phy_get_drvdata(phy);

	writel(POSTED_DATA_CREDITS(0xc0) | POSTED_HEADER_CREDITS(0xa),
	       pcie_phy->reg + PEHR_MISC_70);
	writel(COMPLETION_DATA_CREDITS(0x30) | COMPLETION_HEADER_CREDITS(0x8),
	       pcie_phy->reg + PEHR_MISC_78);
	writel(LOCAL_SCALE_SUP, pcie_phy->reg + PEHR_MISC_58);

	return 0;
}

static int ast2700_phy_set_mode(struct phy *phy, enum phy_mode mode,
				int submode)
{
	struct aspeed_pcie_phy *pcie_phy = phy_get_drvdata(phy);
	u32 cfg_val;

	switch (submode) {
	case PHY_MODE_PCIE_RC:
		writel(CONFIG_RC_DEVICE, pcie_phy->reg + PEHR_MISC_5C);
		cfg_val = readl(pcie_phy->reg + PEHR_MISC_60);
		cfg_val &= ~AST2700_PORT_TYPE_MASK;
		cfg_val |= PORT_TYPE_ROOT;
		writel(cfg_val, pcie_phy->reg + PEHR_MISC_60);
		break;
	default:
		dev_err(&phy->dev, "Unsupported submode %d\n", submode);
		return -EINVAL;
	}

	return 0;
}

static const struct phy_ops ast2700_phy_ops = {
	.init		= ast2700_phy_init,
	.set_mode	= ast2700_phy_set_mode,
	.owner		= THIS_MODULE,
};

const struct aspeed_pcie_phy_platform pcie_phy_ast2600 = {
	.phy_ops = &ast2600_phy_ops,
};

const struct aspeed_pcie_phy_platform pcie_phy_ast2700 = {
	.phy_ops = &ast2700_phy_ops,
};

static int aspeed_pcie_phy_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct phy_provider *phy_provider;
	struct aspeed_pcie_phy *pcie_phy;
	const struct aspeed_pcie_phy_platform *md;

	md = of_device_get_match_data(dev);
	if (!md)
		return -ENODEV;

	pcie_phy = devm_kzalloc(dev, sizeof(*pcie_phy), GFP_KERNEL);
	if (!pcie_phy)
		return -ENOMEM;

	pcie_phy->reg = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(pcie_phy->reg))
		return PTR_ERR(pcie_phy->reg);

	pcie_phy->dev = dev;
	pcie_phy->platform = md;

	pcie_phy->phy = devm_phy_create(dev, dev->of_node,
					pcie_phy->platform->phy_ops);
	if (IS_ERR(pcie_phy->phy))
		return dev_err_probe(dev, PTR_ERR(pcie_phy->phy),
				     "failed to create PHY\n");

	phy_set_drvdata(pcie_phy->phy, pcie_phy);
	phy_provider = devm_of_phy_provider_register(dev, of_phy_simple_xlate);

	return PTR_ERR_OR_ZERO(phy_provider);
}

static const struct of_device_id aspeed_pcie_phy_of_match_table[] = {
	{
		.compatible = "aspeed,ast2600-pcie-phy",
		.data = &pcie_phy_ast2600,
	},
	{
		.compatible = "aspeed,ast2700-pcie-phy",
		.data = &pcie_phy_ast2700,
	},
	{ },
};
MODULE_DEVICE_TABLE(of, aspeed_pcie_phy_of_match_table);

static struct platform_driver aspeed_pcie_driver = {
	.probe		= aspeed_pcie_phy_probe,
	.driver = {
		.name	= "aspeed-pcie-phy",
		.of_match_table = aspeed_pcie_phy_of_match_table,
	},
};

module_platform_driver(aspeed_pcie_driver);

MODULE_AUTHOR("Jacky Chou <jacky_chou@aspeedtech.com>");
MODULE_DESCRIPTION("ASPEED PCIe PHY");
MODULE_LICENSE("GPL");
