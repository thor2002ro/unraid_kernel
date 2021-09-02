/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_AMD_NB_H
#define _ASM_X86_AMD_NB_H

#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/refcount.h>

struct amd_nb_bus_dev_range {
	u8 bus;
	u8 dev_base;
	u8 dev_limit;
};

extern const struct amd_nb_bus_dev_range amd_nb_bus_dev_ranges[];

extern bool early_is_amd_nb(u32 value);
extern struct resource *amd_get_mmconfig_range(struct resource *res);
extern int amd_cache_northbridges(void);
extern void amd_flush_garts(void);
extern int amd_numa_init(void);
extern int amd_get_subcaches(int);
extern int amd_set_subcaches(int, unsigned long);

extern int amd_smn_read(u16 node, u32 address, u32 *value);
extern int amd_smn_write(u16 node, u32 address, u32 value);
extern int amd_df_indirect_read(u16 node, u8 func, u16 reg, u8 instance_id, u32 *lo);

struct amd_l3_cache {
	unsigned indices;
	u8	 subcaches[4];
};

struct threshold_block {
	unsigned int	 block;			/* Number within bank */
	unsigned int	 bank;			/* MCA bank the block belongs to */
	unsigned int	 cpu;			/* CPU which controls MCA bank */
	u32		 address;		/* MSR address for the block */
	u16		 interrupt_enable;	/* Enable/Disable APIC interrupt */
	bool		 interrupt_capable;	/* Bank can generate an interrupt. */

	u16		 threshold_limit;	/*
						 * Value upon which threshold
						 * interrupt is generated.
						 */

	struct kobject	 kobj;			/* sysfs object */
	struct list_head miscj;			/*
						 * List of threshold blocks
						 * within a bank.
						 */
};

struct threshold_bank {
	struct kobject		*kobj;
	struct threshold_block	*blocks;

	/* initialized to the number of CPUs on the node sharing this bank */
	refcount_t		cpus;
	unsigned int		shared;
};

struct amd_northbridge {
	struct pci_dev *root;
	struct pci_dev *misc;
	struct pci_dev *link;
	struct amd_l3_cache l3_cache;
	struct threshold_bank *bank4;
	struct semaphore hsmp_sem_lock;
};

struct amd_northbridge_info {
	u16 num;
	u64 flags;
	struct amd_northbridge *nb;
};

#define AMD_NB_GART			BIT(0)
#define AMD_NB_L3_INDEX_DISABLE		BIT(1)
#define AMD_NB_L3_PARTITIONING		BIT(2)
#define AMD_NB_HSMP			BIT(3)

#ifdef CONFIG_AMD_NB

u16 amd_nb_num(void);
bool amd_nb_has_feature(unsigned int feature);
struct amd_northbridge *node_to_amd_nb(int node);

static inline u16 amd_pci_dev_to_node_id(struct pci_dev *pdev)
{
	struct pci_dev *misc;
	int i;

	for (i = 0; i != amd_nb_num(); i++) {
		misc = node_to_amd_nb(i)->misc;

		if (pci_domain_nr(misc->bus) == pci_domain_nr(pdev->bus) &&
		    PCI_SLOT(misc->devfn) == PCI_SLOT(pdev->devfn))
			return i;
	}

	WARN(1, "Unable to find AMD Northbridge id for %s\n", pci_name(pdev));
	return 0;
}

static inline bool amd_gart_present(void)
{
	if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD)
		return false;

	/* GART present only on Fam15h, upto model 0fh */
	if (boot_cpu_data.x86 == 0xf || boot_cpu_data.x86 == 0x10 ||
	    (boot_cpu_data.x86 == 0x15 && boot_cpu_data.x86_model < 0x10))
		return true;

	return false;
}

#else

#define amd_nb_num(x)		0
#define amd_nb_has_feature(x)	false
#define node_to_amd_nb(x)	NULL
#define amd_gart_present(x)	false

#endif

/*
 * HSMP Message types supported
 */
enum hsmp_message_ids {
	HSMP_TEST = 1,
	HSMP_GET_SMU_VER,
	HSMP_GET_PROTO_VER,
	HSMP_GET_SOCKET_POWER,
	HSMP_SET_SOCKET_POWER_LIMIT,
	HSMP_GET_SOCKET_POWER_LIMIT,
	HSMP_GET_SOCKET_POWER_LIMIT_MAX,
	HSMP_SET_BOOST_LIMIT,
	HSMP_SET_BOOST_LIMIT_SOCKET,
	HSMP_GET_BOOST_LIMIT,
	HSMP_GET_PROC_HOT,
	HSMP_SET_XGMI_LINK_WIDTH,
	HSMP_SET_DF_PSTATE,
	HSMP_AUTO_DF_PSTATE,
	HSMP_GET_FCLK_MCLK,
	HSMP_GET_CCLK_THROTTLE_LIMIT,
	HSMP_GET_C0_PERCENT,
	HSMP_SET_NBIO_DPM_LEVEL,
	HSMP_RESERVED,
	HSMP_GET_DDR_BANDWIDTH,
	HSMP_MSG_ID_MAX,
};

#define HSMP_MAX_MSG_LEN	8

struct hsmp_message {
	u32	msg_id;			/* Message ID */
	u16	num_args;		/* Number of arguments in message */
	u16	response_sz;		/* Number of expected response words */
	u32	args[HSMP_MAX_MSG_LEN];	/* Argument(s) */
	u32	response[HSMP_MAX_MSG_LEN];	/* Response word(s) */
};

int hsmp_send_message(int socket_id, struct hsmp_message *msg);

#endif /* _ASM_X86_AMD_NB_H */
