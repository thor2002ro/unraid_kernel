// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/kgdb.h>
#include <linux/printk.h>
#include <linux/sched/debug.h>
#include <linux/delay.h>
#include <linux/reboot.h>

#include <asm/pdc.h>
#include <asm/pdc_chassis.h>

unsigned int __aligned(16) toc_lock = 1;

static void toc20_to_pt_regs(struct pt_regs *regs, struct pdc_toc_pim_20 *toc)
{
	int i;

	regs->gr[0] = (unsigned long)toc->cr[22];

	for (i = 1; i < 32; i++)
		regs->gr[i] = (unsigned long)toc->gr[i];

	for (i = 0; i < 8; i++)
		regs->sr[i] = (unsigned long)toc->sr[i];

	regs->iasq[0] = (unsigned long)toc->cr[17];
	regs->iasq[1] = (unsigned long)toc->iasq_back;
	regs->iaoq[0] = (unsigned long)toc->cr[18];
	regs->iaoq[1] = (unsigned long)toc->iaoq_back;

	regs->sar = (unsigned long)toc->cr[11];
	regs->iir = (unsigned long)toc->cr[19];
	regs->isr = (unsigned long)toc->cr[20];
	regs->ior = (unsigned long)toc->cr[21];
}

static void toc11_to_pt_regs(struct pt_regs *regs, struct pdc_toc_pim_11 *toc)
{
	int i;

	regs->gr[0] = toc->cr[22];

	for (i = 1; i < 32; i++)
		regs->gr[i] = toc->gr[i];

	for (i = 0; i < 8; i++)
		regs->sr[i] = toc->sr[i];

	regs->iasq[0] = toc->cr[17];
	regs->iasq[1] = toc->iasq_back;
	regs->iaoq[0] = toc->cr[18];
	regs->iaoq[1] = toc->iaoq_back;

	regs->sar  = toc->cr[11];
	regs->iir  = toc->cr[19];
	regs->isr  = toc->cr[20];
	regs->ior  = toc->cr[21];
}

void notrace __noreturn __cold toc_intr(struct pt_regs *regs)
{
	struct pdc_toc_pim_20 pim_data20;
	struct pdc_toc_pim_11 pim_data11;

	nmi_enter();

	if (boot_cpu_data.cpu_type >= pcxu) {
		if (pdc_pim_toc20(&pim_data20))
			panic("Failed to get PIM data");
		toc20_to_pt_regs(regs, &pim_data20);
	} else {
		if (pdc_pim_toc11(&pim_data11))
			panic("Failed to get PIM data");
		toc11_to_pt_regs(regs, &pim_data11);
	}

#ifdef CONFIG_KGDB
	if (atomic_read(&kgdb_active) != -1)
		kgdb_nmicallback(raw_smp_processor_id(), regs);
	kgdb_handle_exception(9, SIGTRAP, 0, regs);
#endif
	show_regs(regs);

	/* give other CPUs time to show their backtrace */
	mdelay(2000);
	machine_restart("TOC");

	/* should never reach this */
	panic("TOC");
}

static __init int setup_toc(void)
{
	unsigned int csum = 0;
	unsigned long toc_code = (unsigned long)dereference_function_descriptor(toc_handler);
	int i;

	PAGE0->vec_toc = __pa(toc_code) & 0xffffffff;
#ifdef CONFIG_64BIT
	PAGE0->vec_toc_hi = __pa(toc_code) >> 32;
#endif
	PAGE0->vec_toclen = toc_handler_size;

	for (i = 0; i < toc_handler_size/4; i++)
		csum += ((u32 *)toc_code)[i];
	toc_handler_csum = -csum;
	pr_info("TOC handler registered\n");
	return 0;
}
early_initcall(setup_toc);


#ifdef CONFIG_KGDB_KDB
/* read a character, return -1 if no char can be polled. */
static int kgdbpdc_read_char(void)
{
	return pdc_iodc_getc();
}

static void kgdbpdc_write_char(u8 chr)
{
	/* no need to print char. kdb will do it. */
}

static struct kgdb_io kgdbpdc_io_ops = {
	.name		= "kgdb_pdc",
	.read_char	= kgdbpdc_read_char,
	.write_char	= kgdbpdc_write_char,
};

static int __init kgdbpdc_init(void)
{
	kgdb_register_io_module(&kgdbpdc_io_ops);
	return 0;
}
early_initcall(kgdbpdc_init);
#endif
