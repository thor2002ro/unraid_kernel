/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_SYSCTL_H
#define _LINUX_SCHED_SYSCTL_H

#include <linux/types.h>

struct ctl_table;

#ifdef CONFIG_DETECT_HUNG_TASK
/* used for hung_task and block/ */
extern unsigned long sysctl_hung_task_timeout_secs;
#else
/* Avoid need for ifdefs elsewhere in the code */
enum { sysctl_hung_task_timeout_secs = 0 };
#endif

enum sched_tunable_scaling {
	SCHED_TUNABLESCALING_NONE,
	SCHED_TUNABLESCALING_LOG,
	SCHED_TUNABLESCALING_LINEAR,
	SCHED_TUNABLESCALING_END,
};

#ifdef CONFIG_SCHED_AUTOGROUP
extern unsigned int sysctl_sched_autogroup_enabled;
#endif

int sysctl_numa_balancing(struct ctl_table *table, int write, void *buffer,
		size_t *lenp, loff_t *ppos);

#if defined(CONFIG_ENERGY_MODEL) && defined(CONFIG_CPU_FREQ_GOV_SCHEDUTIL)
extern unsigned int sysctl_sched_energy_aware;
int sched_energy_aware_handler(struct ctl_table *table, int write,
		void *buffer, size_t *lenp, loff_t *ppos);
#endif

#endif /* _LINUX_SCHED_SYSCTL_H */
