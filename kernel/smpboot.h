/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SMPBOOT_H
#define SMPBOOT_H

struct task_struct;

#ifdef CONFIG_GENERIC_SMP_IDLE_THREAD
void idle_thread_set_boot_cpu(void);
void idle_threads_init(void);
#else
static inline void idle_thread_set_boot_cpu(void) { }
static inline void idle_threads_init(void) { }
#endif

int smpboot_create_threads(unsigned int cpu);
int smpboot_park_threads(unsigned int cpu);
int smpboot_unpark_threads(unsigned int cpu);

void __init cpuhp_threads_init(void);

#endif
