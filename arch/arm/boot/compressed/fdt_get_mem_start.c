// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kernel.h>
#include <linux/libfdt.h>
#include <linux/sizes.h>

static const void *getprop(const void *fdt, const char *node_path,
			   const char *property)
{
	int offset = fdt_path_offset(fdt, node_path);

	if (offset == -FDT_ERR_NOTFOUND)
		return NULL;

	return fdt_getprop(fdt, offset, property, NULL);
}

static uint32_t get_addr_size(const void *fdt)
{
	const __be32 *addr_len = getprop(fdt, "/", "#address-cells");

	if (!addr_len) {
		/* default */
		return 1;
	}

	return fdt32_to_cpu(*addr_len);
}

/*
 * Get the start of physical memory
 */

unsigned long fdt_get_mem_start(const void *fdt)
{
	uint32_t addr_size, mem_start;
	const __be32 *memory;

	if (!fdt)
		return -1;

	if (*(__be32 *)fdt != cpu_to_fdt32(FDT_MAGIC))
		return -1;

	/* Find the first memory node */
	memory = getprop(fdt, "/memory", "reg");
	if (!memory)
		return -1;

	/* There may be multiple cells on LPAE platforms */
	addr_size = get_addr_size(fdt);

	mem_start = fdt32_to_cpu(memory[addr_size - 1]);
	/* Must be a multiple of 16 MiB for phys/virt patching */
	return round_up(mem_start, SZ_16M);
}
