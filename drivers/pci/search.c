// SPDX-License-Identifier: GPL-2.0
/*
 * PCI searching functions
 *
 * Copyright (C) 1993 -- 1997 Drew Eckhardt, Frederic Potter,
 *					David Mosberger-Tang
 * Copyright (C) 1997 -- 2000 Martin Mares <mj@ucw.cz>
 * Copyright (C) 2003 -- 2004 Greg Kroah-Hartman <greg@kroah.com>
 */

#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include "pci.h"

DECLARE_RWSEM(pci_bus_sem);

/*
 * pci_for_each_dma_alias - Iterate over DMA aliases for a device
 * @pdev: starting downstream device
 * @fn: function to call for each alias
 * @data: opaque data to pass to @fn
 *
 * Starting @pdev, walk up the bus calling @fn for each possible alias
 * of @pdev at the root bus.
 */
int pci_for_each_dma_alias(struct pci_dev *pdev,
			   int (*fn)(struct pci_dev *pdev,
				     u16 alias, void *data), void *data)
{
	struct pci_bus *bus;
	int ret;

	/*
	 * The device may have an explicit alias requester ID for DMA where the
	 * requester is on another PCI bus.
	 */
	pdev = pci_real_dma_dev(pdev);

	ret = fn(pdev, pci_dev_id(pdev), data);
	if (ret)
		return ret;

	/*
	 * If the device is broken and uses an alias requester ID for
	 * DMA, iterate over that too.
	 */
	if (unlikely(pdev->dma_alias_mask)) {
		unsigned int devfn;

		for_each_set_bit(devfn, pdev->dma_alias_mask, MAX_NR_DEVFNS) {
			ret = fn(pdev, PCI_DEVID(pdev->bus->number, devfn),
				 data);
			if (ret)
				return ret;
		}
	}

	for (bus = pdev->bus; !pci_is_root_bus(bus); bus = bus->parent) {
		struct pci_dev *tmp;

		/* Skip virtual buses */
		if (!bus->self)
			continue;

		tmp = bus->self;

		/* stop at bridge where translation unit is associated */
		if (tmp->dev_flags & PCI_DEV_FLAGS_BRIDGE_XLATE_ROOT)
			return ret;

		/*
		 * PCIe-to-PCI/X bridges alias transactions from downstream
		 * devices using the subordinate bus number (PCI Express to
		 * PCI/PCI-X Bridge Spec, rev 1.0, sec 2.3).  For all cases
		 * where the upstream bus is PCI/X we alias to the bridge
		 * (there are various conditions in the previous reference
		 * where the bridge may take ownership of transactions, even
		 * when the secondary interface is PCI-X).
		 */
		if (pci_is_pcie(tmp)) {
			switch (pci_pcie_type(tmp)) {
			case PCI_EXP_TYPE_ROOT_PORT:
			case PCI_EXP_TYPE_UPSTREAM:
			case PCI_EXP_TYPE_DOWNSTREAM:
				continue;
			case PCI_EXP_TYPE_PCI_BRIDGE:
				ret = fn(tmp,
					 PCI_DEVID(tmp->subordinate->number,
						   PCI_DEVFN(0, 0)), data);
				if (ret)
					return ret;
				continue;
			case PCI_EXP_TYPE_PCIE_BRIDGE:
				ret = fn(tmp, pci_dev_id(tmp), data);
				if (ret)
					return ret;
				continue;
			}
		} else {
			if (tmp->dev_flags & PCI_DEV_FLAG_PCIE_BRIDGE_ALIAS)
				ret = fn(tmp,
					 PCI_DEVID(tmp->subordinate->number,
						   PCI_DEVFN(0, 0)), data);
			else
				ret = fn(tmp, pci_dev_id(tmp), data);
			if (ret)
				return ret;
		}
	}

	return ret;
}

static enum pci_bus_isolation pcie_switch_isolated(struct pci_bus *bus)
{
	struct pci_dev *pdev;

	/*
	 * Within a PCIe switch we have an interior bus that has the Upstream
	 * port as the bridge and a set of Downstream port bridging to the
	 * egress ports.
	 *
	 * Each DSP has an ACS setting which controls where its traffic is
	 * permitted to go. Any DSP with a permissive ACS setting can send
	 * traffic flowing upstream back downstream through another DSP.
	 *
	 * Thus any non-permissive DSP spoils the whole bus.
	 * PCI_ACS_UNCLAIMED_RR is not required since rejecting requests with
	 * error is still isolation.
	 */
	guard(rwsem_read)(&pci_bus_sem);
	list_for_each_entry(pdev, &bus->devices, bus_list) {
		/* Don't understand what this is, be conservative */
		if (!pci_is_pcie(pdev) ||
		    pci_pcie_type(pdev) != PCI_EXP_TYPE_DOWNSTREAM ||
		    pdev->dma_alias_mask)
			return PCIE_NON_ISOLATED;

		if (!pci_acs_enabled(pdev, PCI_ACS_ISOLATED |
						   PCI_ACS_DSP_MT_RR |
						   PCI_ACS_USP_MT_RR)) {
			/* The USP is isolated from the DSP */
			if (!pci_acs_enabled(pdev, PCI_ACS_USP_MT_RR))
				return PCIE_NON_ISOLATED;
			return PCIE_SWITCH_DSP_NON_ISOLATED;
		}
	}
	return PCIE_ISOLATED;
}

static bool pci_has_mmio(struct pci_dev *pdev)
{
	unsigned int i;

	for (i = 0; i <= PCI_ROM_RESOURCE; i++) {
		struct resource *res = pci_resource_n(pdev, i);

		if (resource_size(res) && resource_type(res) == IORESOURCE_MEM)
			return true;
	}
	return false;
}

/**
 * pci_bus_isolated - Determine how isolated connected devices are
 * @bus: The bus to check
 *
 * Isolation is the ability of devices to talk to each other. Full isolation
 * means that a device can only communicate with the IOMMU and can not do peer
 * to peer within the fabric.
 *
 * We consider isolation on a bus by bus basis. If the bus will permit a
 * transaction originated downstream to complete on anything other than the
 * IOMMU then the bus is not isolated.
 *
 * Non-isolation includes all the downstream devices on this bus, and it may
 * include the upstream bridge or port that is creating this bus.
 *
 * The various cases are returned in an enum.
 *
 * Broadly speaking this function evaluates the ACS settings in a PCI switch to
 * determine if a PCI switch is configured to have full isolation.
 *
 * Old PCI/PCI-X busses cannot have isolation due to their physical properties,
 * but they do have some aliasing properties that effect group creation.
 *
 * pci_bus_isolated() does not consider loopback internal to devices, like
 * multi-function devices performing a self-loopback. The caller must check
 * this separately. It does not considering alasing within the bus.
 *
 * It does not currently support the ACS P2P Egress Control Vector, Linux does
 * not yet have any way to enable this feature. EC will create subsets of the
 * bus that are isolated from other subsets.
 */
enum pci_bus_isolation pci_bus_isolated(struct pci_bus *bus)
{
	struct pci_dev *bridge = bus->self;
	int type;

	/*
	 * This bus was created by pci_register_host_bridge(). The spec provides
	 * no way to tell what kind of bus this is, for PCIe we expect this to
	 * be internal to the root complex and not covered by any spec behavior.
	 * Linux has historically been optimistic about this bus and treated it
	 * as isolating. Given that the behavior of the root complex and the ACS
	 * behavior of RCiEP's is explicitly not specified we hope that the
	 * implementation is directing everything that reaches the root bus to
	 * the IOMMU.
	 */
	if (pci_is_root_bus(bus))
		return PCIE_ISOLATED;

	/*
	 * bus->self is only NULL for SRIOV VFs, it represents a "virtual" bus
	 * within Linux to hold any bus numbers consumed by VF RIDs. Caller must
	 * use pci_physfn() to get the bus for calling this function.
	 */
	if (WARN_ON(!bridge))
		return PCI_BRIDGE_NON_ISOLATED;

	/*
	 * The bridge is not a PCIe bridge therefore this bus is PCI/PCI-X.
	 *
	 * PCI does not have anything like ACS. Any down stream device can bus
	 * master an address that any other downstream device can claim. No
	 * isolation is possible.
	 */
	if (!pci_is_pcie(bridge)) {
		if (bridge->dev_flags & PCI_DEV_FLAG_PCIE_BRIDGE_ALIAS)
			type = PCI_EXP_TYPE_PCI_BRIDGE;
		else
			return PCI_BRIDGE_NON_ISOLATED;
	} else {
		type = pci_pcie_type(bridge);
	}

	switch (type) {
	/*
	 * Since PCIe links are point to point root ports are isolated if there
	 * is no internal loopback to the root port's MMIO. Like MFDs assume if
	 * there is no ACS cap then there is no loopback. The root port uses
	 * DSP_MT_RR for its own MMIO.
	 */
	case PCI_EXP_TYPE_ROOT_PORT:
		if (bridge->acs_cap &&
		    !pci_acs_enabled(bridge,
				     PCI_ACS_ISOLATED | PCI_ACS_DSP_MT_RR))
			return PCIE_NON_ISOLATED;
		return PCIE_ISOLATED;

	/*
	 * Since PCIe links are point to point a DSP is always considered
	 * isolated. The internal bus of the switch will be non-isolated if the
	 * DSP's have any ACS that allows upstream traffic to flow back
	 * downstream to any DSP, including back to this DSP or its MMIO.
	 */
	case PCI_EXP_TYPE_DOWNSTREAM:
		return PCIE_ISOLATED;

	/*
	 * bus is the interior bus of a PCI-E switch where ACS rules apply.
	 */
	case PCI_EXP_TYPE_UPSTREAM:
		return pcie_switch_isolated(bus);

	/*
	 * PCIe to PCI/PCI-X - this bus is PCI.
	 */
	case PCI_EXP_TYPE_PCI_BRIDGE:
		/*
		 * A PCIe express bridge will use the subordinate bus number
		 * with a 0 devfn as the RID in some cases. This causes all
		 * subordinate devfns to alias with 0, which is the same
		 * grouping as PCI_BUS_NON_ISOLATED. The RID of the bridge
		 * itself is only used by the bridge.
		 *
		 * However, if the bridge has MMIO then we will assume the MMIO
		 * is not isolated due to no ACS controls on this bridge type.
		 */
		if (pci_has_mmio(bridge))
			return PCI_BRIDGE_NON_ISOLATED;
		return PCI_BUS_NON_ISOLATED;

	/*
	 * PCI/PCI-X to PCIe - this bus is PCIe. We already know there must be a
	 * PCI bus upstream of this bus, so just return non-isolated. If
	 * upstream is PCI-X the PCIe RID should be preserved, but for PCI the
	 * RID will be lost.
	 */
	case PCI_EXP_TYPE_PCIE_BRIDGE:
		return PCI_BRIDGE_NON_ISOLATED;

	default:
		return PCI_BRIDGE_NON_ISOLATED;
	}
}

static struct pci_bus *pci_do_find_bus(struct pci_bus *bus, unsigned char busnr)
{
	struct pci_bus *child;
	struct pci_bus *tmp;

	if (bus->number == busnr)
		return bus;

	list_for_each_entry(tmp, &bus->children, node) {
		child = pci_do_find_bus(tmp, busnr);
		if (child)
			return child;
	}
	return NULL;
}

/**
 * pci_find_bus - locate PCI bus from a given domain and bus number
 * @domain: number of PCI domain to search
 * @busnr: number of desired PCI bus
 *
 * Given a PCI bus number and domain number, the desired PCI bus is located
 * in the global list of PCI buses.  If the bus is found, a pointer to its
 * data structure is returned.  If no bus is found, %NULL is returned.
 */
struct pci_bus *pci_find_bus(int domain, int busnr)
{
	struct pci_bus *bus = NULL;
	struct pci_bus *tmp_bus;

	while ((bus = pci_find_next_bus(bus)) != NULL)  {
		if (pci_domain_nr(bus) != domain)
			continue;
		tmp_bus = pci_do_find_bus(bus, busnr);
		if (tmp_bus)
			return tmp_bus;
	}
	return NULL;
}
EXPORT_SYMBOL(pci_find_bus);

/**
 * pci_find_next_bus - begin or continue searching for a PCI bus
 * @from: Previous PCI bus found, or %NULL for new search.
 *
 * Iterates through the list of known PCI buses.  A new search is
 * initiated by passing %NULL as the @from argument.  Otherwise if
 * @from is not %NULL, searches continue from next device on the
 * global list.
 */
struct pci_bus *pci_find_next_bus(const struct pci_bus *from)
{
	struct list_head *n;
	struct pci_bus *b = NULL;

	down_read(&pci_bus_sem);
	n = from ? from->node.next : pci_root_buses.next;
	if (n != &pci_root_buses)
		b = list_entry(n, struct pci_bus, node);
	up_read(&pci_bus_sem);
	return b;
}
EXPORT_SYMBOL(pci_find_next_bus);

/**
 * pci_get_slot - locate PCI device for a given PCI slot
 * @bus: PCI bus on which desired PCI device resides
 * @devfn: encodes number of PCI slot in which the desired PCI
 * device resides and the logical device number within that slot
 * in case of multi-function devices.
 *
 * Given a PCI bus and slot/function number, the desired PCI device
 * is located in the list of PCI devices.
 * If the device is found, its reference count is increased and this
 * function returns a pointer to its data structure.  The caller must
 * decrement the reference count by calling pci_dev_put().
 * If no device is found, %NULL is returned.
 */
struct pci_dev *pci_get_slot(struct pci_bus *bus, unsigned int devfn)
{
	struct pci_dev *dev;

	down_read(&pci_bus_sem);

	list_for_each_entry(dev, &bus->devices, bus_list) {
		if (dev->devfn == devfn)
			goto out;
	}

	dev = NULL;
 out:
	pci_dev_get(dev);
	up_read(&pci_bus_sem);
	return dev;
}
EXPORT_SYMBOL(pci_get_slot);

/**
 * pci_get_domain_bus_and_slot - locate PCI device for a given PCI domain (segment), bus, and slot
 * @domain: PCI domain/segment on which the PCI device resides.
 * @bus: PCI bus on which desired PCI device resides
 * @devfn: encodes number of PCI slot in which the desired PCI device
 * resides and the logical device number within that slot in case of
 * multi-function devices.
 *
 * Given a PCI domain, bus, and slot/function number, the desired PCI
 * device is located in the list of PCI devices. If the device is
 * found, its reference count is increased and this function returns a
 * pointer to its data structure.  The caller must decrement the
 * reference count by calling pci_dev_put().  If no device is found,
 * %NULL is returned.
 */
struct pci_dev *pci_get_domain_bus_and_slot(int domain, unsigned int bus,
					    unsigned int devfn)
{
	struct pci_dev *dev = NULL;

	for_each_pci_dev(dev) {
		if (pci_domain_nr(dev->bus) == domain &&
		    (dev->bus->number == bus && dev->devfn == devfn))
			return dev;
	}
	return NULL;
}
EXPORT_SYMBOL(pci_get_domain_bus_and_slot);

static int match_pci_dev_by_id(struct device *dev, const void *data)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	const struct pci_device_id *id = data;

	if (pci_match_one_device(id, pdev))
		return 1;
	return 0;
}

/*
 * pci_get_dev_by_id - begin or continue searching for a PCI device by id
 * @id: pointer to struct pci_device_id to match for the device
 * @from: Previous PCI device found in search, or %NULL for new search.
 *
 * Iterates through the list of known PCI devices.  If a PCI device is found
 * with a matching id a pointer to its device structure is returned, and the
 * reference count to the device is incremented.  Otherwise, %NULL is returned.
 * A new search is initiated by passing %NULL as the @from argument.  Otherwise
 * if @from is not %NULL, searches continue from next device on the global
 * list.  The reference count for @from is always decremented if it is not
 * %NULL.
 *
 * This is an internal function for use by the other search functions in
 * this file.
 */
static struct pci_dev *pci_get_dev_by_id(const struct pci_device_id *id,
					 struct pci_dev *from)
{
	struct device *dev;
	struct device *dev_start = NULL;
	struct pci_dev *pdev = NULL;

	if (from)
		dev_start = &from->dev;
	dev = bus_find_device(&pci_bus_type, dev_start, (void *)id,
			      match_pci_dev_by_id);
	if (dev)
		pdev = to_pci_dev(dev);
	pci_dev_put(from);
	return pdev;
}

/**
 * pci_get_subsys - begin or continue searching for a PCI device by vendor/subvendor/device/subdevice id
 * @vendor: PCI vendor id to match, or %PCI_ANY_ID to match all vendor ids
 * @device: PCI device id to match, or %PCI_ANY_ID to match all device ids
 * @ss_vendor: PCI subsystem vendor id to match, or %PCI_ANY_ID to match all vendor ids
 * @ss_device: PCI subsystem device id to match, or %PCI_ANY_ID to match all device ids
 * @from: Previous PCI device found in search, or %NULL for new search.
 *
 * Iterates through the list of known PCI devices.  If a PCI device is found
 * with a matching @vendor, @device, @ss_vendor and @ss_device, a pointer to its
 * device structure is returned, and the reference count to the device is
 * incremented.  Otherwise, %NULL is returned.  A new search is initiated by
 * passing %NULL as the @from argument.  Otherwise if @from is not %NULL,
 * searches continue from next device on the global list.
 * The reference count for @from is always decremented if it is not %NULL.
 */
struct pci_dev *pci_get_subsys(unsigned int vendor, unsigned int device,
			       unsigned int ss_vendor, unsigned int ss_device,
			       struct pci_dev *from)
{
	struct pci_device_id id = {
		.vendor = vendor,
		.device = device,
		.subvendor = ss_vendor,
		.subdevice = ss_device,
	};

	return pci_get_dev_by_id(&id, from);
}
EXPORT_SYMBOL(pci_get_subsys);

/**
 * pci_get_device - begin or continue searching for a PCI device by vendor/device id
 * @vendor: PCI vendor id to match, or %PCI_ANY_ID to match all vendor ids
 * @device: PCI device id to match, or %PCI_ANY_ID to match all device ids
 * @from: Previous PCI device found in search, or %NULL for new search.
 *
 * Iterates through the list of known PCI devices.  If a PCI device is
 * found with a matching @vendor and @device, the reference count to the
 * device is incremented and a pointer to its device structure is returned.
 * Otherwise, %NULL is returned.  A new search is initiated by passing %NULL
 * as the @from argument.  Otherwise if @from is not %NULL, searches continue
 * from next device on the global list.  The reference count for @from is
 * always decremented if it is not %NULL.
 */
struct pci_dev *pci_get_device(unsigned int vendor, unsigned int device,
			       struct pci_dev *from)
{
	return pci_get_subsys(vendor, device, PCI_ANY_ID, PCI_ANY_ID, from);
}
EXPORT_SYMBOL(pci_get_device);

/**
 * pci_get_class - begin or continue searching for a PCI device by class
 * @class: search for a PCI device with this class designation
 * @from: Previous PCI device found in search, or %NULL for new search.
 *
 * Iterates through the list of known PCI devices.  If a PCI device is
 * found with a matching @class, the reference count to the device is
 * incremented and a pointer to its device structure is returned.
 * Otherwise, %NULL is returned.
 * A new search is initiated by passing %NULL as the @from argument.
 * Otherwise if @from is not %NULL, searches continue from next device
 * on the global list.  The reference count for @from is always decremented
 * if it is not %NULL.
 */
struct pci_dev *pci_get_class(unsigned int class, struct pci_dev *from)
{
	struct pci_device_id id = {
		.vendor = PCI_ANY_ID,
		.device = PCI_ANY_ID,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
		.class_mask = PCI_ANY_ID,
		.class = class,
	};

	return pci_get_dev_by_id(&id, from);
}
EXPORT_SYMBOL(pci_get_class);

/**
 * pci_get_base_class - searching for a PCI device by matching against the base class code only
 * @class: search for a PCI device with this base class code
 * @from: Previous PCI device found in search, or %NULL for new search.
 *
 * Iterates through the list of known PCI devices. If a PCI device is found
 * with a matching base class code, the reference count to the device is
 * incremented. See pci_match_one_device() to figure out how does this works.
 * A new search is initiated by passing %NULL as the @from argument.
 * Otherwise if @from is not %NULL, searches continue from next device on the
 * global list. The reference count for @from is always decremented if it is
 * not %NULL.
 *
 * Returns:
 * A pointer to a matched PCI device, %NULL Otherwise.
 */
struct pci_dev *pci_get_base_class(unsigned int class, struct pci_dev *from)
{
	struct pci_device_id id = {
		.vendor = PCI_ANY_ID,
		.device = PCI_ANY_ID,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
		.class_mask = 0xFF0000,
		.class = class << 16,
	};

	return pci_get_dev_by_id(&id, from);
}
EXPORT_SYMBOL(pci_get_base_class);

/**
 * pci_dev_present - Returns 1 if device matching the device list is present, 0 if not.
 * @ids: A pointer to a null terminated list of struct pci_device_id structures
 * that describe the type of PCI device the caller is trying to find.
 *
 * Obvious fact: You do not have a reference to any device that might be found
 * by this function, so if that device is removed from the system right after
 * this function is finished, the value will be stale.  Use this function to
 * find devices that are usually built into a system, or for a general hint as
 * to if another device happens to be present at this specific moment in time.
 */
int pci_dev_present(const struct pci_device_id *ids)
{
	struct pci_dev *found = NULL;

	while (ids->vendor || ids->subvendor || ids->class_mask) {
		found = pci_get_dev_by_id(ids, NULL);
		if (found) {
			pci_dev_put(found);
			return 1;
		}
		ids++;
	}

	return 0;
}
EXPORT_SYMBOL(pci_dev_present);

/**
 * pci_reachable_set - Generate a bitmap of devices within a reachability set
 * @start: First device in the set
 * @devfns: The set of devices on the bus
 * @reachable: Callback to tell if two devices can reach each other
 *
 * Compute a bitmap where every set bit is a device on the bus that is reachable
 * from the start device, including the start device. Reachability between two
 * devices is determined by a callback function.
 *
 * This is a non-recursive implementation that invokes the callback once per
 * pair. The callback must be commutative:
 *    reachable(a, b) == reachable(b, a)
 * reachable() can form a cyclic graph:
 *    reachable(a,b) == reachable(b,c) == reachable(c,a) == true
 *
 * Since this function is limited to a single bus the largest set can be 256
 * devices large.
 */
void pci_reachable_set(struct pci_dev *start, struct pci_reachable_set *devfns,
		       bool (*reachable)(struct pci_dev *deva,
					 struct pci_dev *devb))
{
	struct pci_reachable_set todo_devfns = {};
	struct pci_reachable_set next_devfns = {};
	struct pci_bus *bus = start->bus;
	bool again;

	/* Assume devfn of all PCI devices is bounded by MAX_NR_DEVFNS */
	static_assert(sizeof(next_devfns.devfns) * BITS_PER_BYTE >=
		      MAX_NR_DEVFNS);

	memset(devfns, 0, sizeof(devfns->devfns));
	__set_bit(start->devfn, devfns->devfns);
	__set_bit(start->devfn, next_devfns.devfns);

	down_read(&pci_bus_sem);
	while (true) {
		unsigned int devfna;
		unsigned int i;

		/*
		 * For each device that hasn't been checked compare every
		 * device on the bus against it.
		 */
		again = false;
		for_each_set_bit(devfna, next_devfns.devfns, MAX_NR_DEVFNS) {
			struct pci_dev *deva = NULL;
			struct pci_dev *devb;

			list_for_each_entry(devb, &bus->devices, bus_list) {
				if (devb->devfn == devfna)
					deva = devb;

				if (test_bit(devb->devfn, devfns->devfns))
					continue;

				if (!deva) {
					deva = devb;
					list_for_each_entry_continue(
						deva, &bus->devices, bus_list)
						if (deva->devfn == devfna)
							break;
				}

				if (!reachable(deva, devb))
					continue;

				__set_bit(devb->devfn, todo_devfns.devfns);
				again = true;
			}
		}

		if (!again)
			break;

		/*
		 * Every new bit adds a new deva to check, reloop the whole
		 * thing. Expect this to be rare.
		 */
		for (i = 0; i != ARRAY_SIZE(devfns->devfns); i++) {
			devfns->devfns[i] |= todo_devfns.devfns[i];
			next_devfns.devfns[i] = todo_devfns.devfns[i];
			todo_devfns.devfns[i] = 0;
		}
	}
	up_read(&pci_bus_sem);
}
EXPORT_SYMBOL_GPL(pci_reachable_set);
