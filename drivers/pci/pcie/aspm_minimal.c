// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal PCIe ASPM handling when CONFIG_PCIEASPM is not set.
 *
 * Copyright (C) 2023 Intel Corporation.
 */

#include <linux/pci.h>

#include "../pci.h"

#ifndef CONFIG_PCIEASPM
/*
 * Always disable ASPM when requested, even when CONFIG_PCIEASPM is
 * not build to avoid drivers adding code to do it on their own
 * which caused issues when core does not know about the out-of-band
 * ASPM state changes.
 */
int pci_disable_link_state_locked(struct pci_dev *pdev, int state)
{
	struct pci_dev *parent = pdev->bus->self;
	struct pci_bus *linkbus = pdev->bus;
	struct pci_dev *child;
	u16 aspm_enabled, linkctl;
	int ret;

	if (!parent)
		return -ENODEV;

	ret = pcie_capability_read_word(parent, PCI_EXP_LNKCTL, &linkctl);
	if (ret != PCIBIOS_SUCCESSFUL)
		return pcibios_err_to_errno(ret);
	aspm_enabled = linkctl & PCI_EXP_LNKCTL_ASPMC;

	ret = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL, &linkctl);
	if (ret != PCIBIOS_SUCCESSFUL)
		return pcibios_err_to_errno(ret);
	aspm_enabled |= linkctl & PCI_EXP_LNKCTL_ASPMC;

	/* If no states need to be disabled, don't touch LNKCTL */
	if (state & aspm_enabled)
		return 0;

	ret = pcie_capability_clear_word(parent, PCI_EXP_LNKCTL, PCI_EXP_LNKCTL_ASPMC);
	if (ret != PCIBIOS_SUCCESSFUL)
		return pcibios_err_to_errno(ret);
	list_for_each_entry(child, &linkbus->devices, bus_list)
		pcie_capability_clear_word(child, PCI_EXP_LNKCTL, PCI_EXP_LNKCTL_ASPMC);

	return 0;
}
EXPORT_SYMBOL(pci_disable_link_state_locked);

int pci_disable_link_state(struct pci_dev *pdev, int state)
{
	int ret;

	down_read(&pci_bus_sem);
	ret = pci_disable_link_state_locked(pdev, state);
	up_read(&pci_bus_sem);

	return ret;
}
EXPORT_SYMBOL(pci_disable_link_state);

#endif
