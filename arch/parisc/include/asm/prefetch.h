/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/asm-parisc/prefetch.h
 *
 * PA 2.0 defines data prefetch instructions on page 6-11 of the Kane book.
 * In addition, many implementations do hardware prefetching of both
 * instructions and data.
 *
 * PA7300LC (page 14-4 of the ERS) also implements prefetching by a load
 * to gr0 but not in a way that Linux can use.  If the load would cause an
 * interruption (eg due to prefetching 0), it is suppressed on PA2.0
 * processors, but not on 7300LC.
 *
 */

#ifndef __ASM_PARISC_PREFETCH_H
#define __ASM_PARISC_PREFETCH_H

#ifndef __ASSEMBLY__
#if defined(CONFIG_PREFETCH) && !defined(CONFIG_64BIT)
#define ARCH_HAS_PREFETCH
#define ARCH_HAS_PREFETCHW
#define prefetchw	prefetch
static inline void prefetch(const void *addr)
{
	__asm__(
		/* Need to avoid prefetch of NULL on PA7300LC */
		"	extrw,u,= %0, 31-12, 32-12, %%r0\n"
		"	ldw 0(%0), %%r0" : : "r" (addr));
}
#endif /* CONFIG_PREFETCH */

#endif /* __ASSEMBLY__ */

#endif /* __ASM_PARISC_PROCESSOR_H */
