// SPDX-License-Identifier: GPL-2.0

#include <linux/cpuhotplug.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include <asm/apic.h>

#include "local.h"

struct cluster_mask {
	unsigned int	clusterid;
	int		node;
	struct cpumask	mask;
};

/*
 * __x2apic_send_IPI_mask() possibly needs to read
 * x86_cpu_to_logical_apicid for all online cpus in a sequential way.
 * Using per cpu variable would cost one cache line per cpu.
 */
static u32 *x86_cpu_to_logical_apicid __read_mostly;

static DEFINE_PER_CPU(cpumask_var_t, ipi_mask);
static DEFINE_PER_CPU_READ_MOSTLY(struct cluster_mask *, cluster_masks);

static int x2apic_acpi_madt_oem_check(char *oem_id, char *oem_table_id)
{
	return x2apic_enabled();
}

static void x2apic_send_IPI(int cpu, int vector)
{
	u32 dest = x86_cpu_to_logical_apicid[cpu];

	/* x2apic MSRs are special and need a special fence: */
	weak_wrmsr_fence();
	__x2apic_send_IPI_dest(dest, vector, APIC_DEST_LOGICAL);
}

static void
__x2apic_send_IPI_mask(const struct cpumask *mask, int vector, int apic_dest)
{
	unsigned int cpu, clustercpu;
	struct cpumask *tmpmsk;
	unsigned long flags;
	u32 dest;

	/* x2apic MSRs are special and need a special fence: */
	weak_wrmsr_fence();
	local_irq_save(flags);

	tmpmsk = this_cpu_cpumask_var_ptr(ipi_mask);
	cpumask_copy(tmpmsk, mask);
	/* If IPI should not be sent to self, clear current CPU */
	if (apic_dest != APIC_DEST_ALLINC)
		__cpumask_clear_cpu(smp_processor_id(), tmpmsk);

	/* Collapse cpus in a cluster so a single IPI per cluster is sent */
	for_each_cpu(cpu, tmpmsk) {
		struct cluster_mask *cmsk = per_cpu(cluster_masks, cpu);

		dest = 0;
		for_each_cpu_and(clustercpu, tmpmsk, &cmsk->mask)
			dest |= x86_cpu_to_logical_apicid[clustercpu];

		if (!dest)
			continue;

		__x2apic_send_IPI_dest(dest, vector, APIC_DEST_LOGICAL);
		/* Remove cluster CPUs from tmpmask */
		cpumask_andnot(tmpmsk, tmpmsk, &cmsk->mask);
	}

	local_irq_restore(flags);
}

static void x2apic_send_IPI_mask(const struct cpumask *mask, int vector)
{
	__x2apic_send_IPI_mask(mask, vector, APIC_DEST_ALLINC);
}

static void
x2apic_send_IPI_mask_allbutself(const struct cpumask *mask, int vector)
{
	__x2apic_send_IPI_mask(mask, vector, APIC_DEST_ALLBUT);
}

static void x2apic_send_IPI_allbutself(int vector)
{
	__x2apic_send_IPI_shorthand(vector, APIC_DEST_ALLBUT);
}

static void x2apic_send_IPI_all(int vector)
{
	__x2apic_send_IPI_shorthand(vector, APIC_DEST_ALLINC);
}

static u32 x2apic_calc_apicid(unsigned int cpu)
{
	return x86_cpu_to_logical_apicid[cpu];
}

static void init_x2apic_ldr(void)
{
	struct cluster_mask *cmsk = this_cpu_read(cluster_masks);

	BUG_ON(!cmsk);

	cpumask_set_cpu(smp_processor_id(), &cmsk->mask);
}

static int alloc_clustermask(unsigned int cpu, u32 cluster, int node)
{
	struct cluster_mask *cmsk = NULL;
	unsigned int cpu_i;
	u32 apicid;

	if (per_cpu(cluster_masks, cpu))
		return 0;

	/* For the hotplug case, don't always allocate a new one */
	for_each_present_cpu(cpu_i) {
		apicid = apic->cpu_present_to_apicid(cpu_i);
		if (apicid != BAD_APICID && apicid >> 4 == cluster) {
			cmsk = per_cpu(cluster_masks, cpu_i);
			if (cmsk)
				break;
		}
	}
	if (!cmsk) {
		cmsk = kzalloc_node(sizeof(*cmsk), GFP_KERNEL, node);
	}
	if (!cmsk)
		return -ENOMEM;

	cmsk->node = node;
	cmsk->clusterid = cluster;

	per_cpu(cluster_masks, cpu) = cmsk;

        /*
	 * As an optimisation during boot, set the cluster_mask for *all*
	 * present CPUs at once, to prevent *each* of them having to iterate
	 * over the others to find the existing cluster_mask.
	 */
	if (system_state < SYSTEM_RUNNING) {
		for_each_present_cpu(cpu) {
			u32 apicid = apic->cpu_present_to_apicid(cpu);
			if (apicid != BAD_APICID && apicid >> 4 == cluster) {
				struct cluster_mask **cpu_cmsk = &per_cpu(cluster_masks, cpu);
				if (*cpu_cmsk)
					BUG_ON(*cpu_cmsk != cmsk);
				else
					*cpu_cmsk = cmsk;
			}
		}
	}

	return 0;
}

static int x2apic_prepare_cpu(unsigned int cpu)
{
	u32 phys_apicid = apic->cpu_present_to_apicid(cpu);
	u32 cluster = phys_apicid >> 4;
	u32 logical_apicid = (cluster << 16) | (1 << (phys_apicid & 0xf));

	x86_cpu_to_logical_apicid[cpu] = logical_apicid;

	if (alloc_clustermask(cpu, cluster, cpu_to_node(cpu)) < 0)
		return -ENOMEM;
	if (!zalloc_cpumask_var(&per_cpu(ipi_mask, cpu), GFP_KERNEL))
		return -ENOMEM;
	return 0;
}

static int x2apic_dead_cpu(unsigned int dead_cpu)
{
	struct cluster_mask *cmsk = per_cpu(cluster_masks, dead_cpu);

	if (cmsk)
		cpumask_clear_cpu(dead_cpu, &cmsk->mask);
	free_cpumask_var(per_cpu(ipi_mask, dead_cpu));
	return 0;
}

static int x2apic_cluster_probe(void)
{
	u32 slots;

	if (!x2apic_mode)
		return 0;

	slots = max_t(u32, L1_CACHE_BYTES/sizeof(u32), nr_cpu_ids);
	x86_cpu_to_logical_apicid = kcalloc(slots, sizeof(u32), GFP_KERNEL);
	if (!x86_cpu_to_logical_apicid)
		return 0;

	if (cpuhp_setup_state(CPUHP_X2APIC_PREPARE, "x86/x2apic:prepare",
			      x2apic_prepare_cpu, x2apic_dead_cpu) < 0) {
		pr_err("Failed to register X2APIC_PREPARE\n");
		kfree(x86_cpu_to_logical_apicid);
		x86_cpu_to_logical_apicid = NULL;
		return 0;
	}
	init_x2apic_ldr();
	return 1;
}

static struct apic apic_x2apic_cluster __ro_after_init = {

	.name				= "cluster x2apic",
	.probe				= x2apic_cluster_probe,
	.acpi_madt_oem_check		= x2apic_acpi_madt_oem_check,
	.apic_id_valid			= x2apic_apic_id_valid,
	.apic_id_registered		= x2apic_apic_id_registered,

	.delivery_mode			= APIC_DELIVERY_MODE_FIXED,
	.dest_mode_logical		= true,

	.disable_esr			= 0,

	.check_apicid_used		= NULL,
	.init_apic_ldr			= init_x2apic_ldr,
	.ioapic_phys_id_map		= NULL,
	.setup_apic_routing		= NULL,
	.cpu_present_to_apicid		= default_cpu_present_to_apicid,
	.apicid_to_cpu_present		= NULL,
	.check_phys_apicid_present	= default_check_phys_apicid_present,
	.phys_pkg_id			= x2apic_phys_pkg_id,

	.get_apic_id			= x2apic_get_apic_id,
	.set_apic_id			= x2apic_set_apic_id,

	.calc_dest_apicid		= x2apic_calc_apicid,

	.send_IPI			= x2apic_send_IPI,
	.send_IPI_mask			= x2apic_send_IPI_mask,
	.send_IPI_mask_allbutself	= x2apic_send_IPI_mask_allbutself,
	.send_IPI_allbutself		= x2apic_send_IPI_allbutself,
	.send_IPI_all			= x2apic_send_IPI_all,
	.send_IPI_self			= x2apic_send_IPI_self,

	.inquire_remote_apic		= NULL,

	.read				= native_apic_msr_read,
	.write				= native_apic_msr_write,
	.eoi_write			= native_apic_msr_eoi_write,
	.icr_read			= native_x2apic_icr_read,
	.icr_write			= native_x2apic_icr_write,
	.wait_icr_idle			= native_x2apic_wait_icr_idle,
	.safe_wait_icr_idle		= native_safe_x2apic_wait_icr_idle,
};

apic_driver(apic_x2apic_cluster);
