// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdint.h>
#include <malloc.h>
#include <sys/mman.h>
#include "../kselftest.h"

#define PAGEMAP_PATH		"/proc/self/pagemap"
#define CLEAR_REFS_PATH		"/proc/self/clear_refs"
#define SMAP_PATH		"/proc/self/smaps"
#define PMD_SIZE_PATH		"/sys/kernel/mm/transparent_hugepage/hpage_pmd_size"
#define MAX_LINE_LENGTH		512
#define TEST_ITERATIONS		10000
#define PAGE_NUM_TO_TEST	2

int clear_refs;
int pagemap;

int pagesize;
int mmap_size;	/* Size of test region */

static void clear_all_refs(void)
{
	const char *ctrl = "4";

	if (write(clear_refs, ctrl, strlen(ctrl)) != strlen(ctrl))
		ksft_exit_fail_msg("%s: failed to clear references\n", __func__);
}

static void touch_page(char *map, int n)
{
	map[(pagesize * n) + 1]++;
}

static int check_page(char *start, int page_num, int clear)
{
	unsigned long pfn = (unsigned long)start / pagesize;
	uint64_t entry;
	int ret;

	ret = pread(pagemap, &entry, sizeof(entry), (pfn + page_num) * sizeof(entry));
	if (ret != sizeof(entry))
		ksft_exit_fail_msg("reading pagemap failed\n");
	if (clear)
		clear_all_refs();

	return ((entry >> 55) & 1);
}

static void test_simple(void)
{
	int i;
	char *map;

	map = aligned_alloc(pagesize, mmap_size);
	if (!map)
		ksft_exit_fail_msg("mmap failed\n");

	clear_all_refs();

	for (i = 0 ; i < TEST_ITERATIONS; i++) {
		if (check_page(map, PAGE_NUM_TO_TEST, 1) == 1) {
			ksft_print_msg("dirty bit was 1, but should be 0 (i=%d)\n", i);
			break;
		}

		touch_page(map, 2);

		if (check_page(map, PAGE_NUM_TO_TEST, 1) == 0) {
			ksft_print_msg("dirty bit was 0, but should be 1 (i=%d)\n", i);
			break;
		}

	}
	free(map);

	ksft_test_result(i == TEST_ITERATIONS, "Test %s\n", __func__);
}

static void test_vma_reuse(void)
{
	char *map, *map2;

	map = (char *) 0x900000000000;
	map = mmap(map, mmap_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
	if (map == MAP_FAILED)
		ksft_exit_fail_msg("mmap failed");

	clear_all_refs();
	touch_page(map, PAGE_NUM_TO_TEST);

	munmap(map, mmap_size);
	map2 = mmap(map, mmap_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
	if (map2 == MAP_FAILED)
		ksft_exit_fail_msg("mmap failed");

	ksft_test_result(map == map2, "Test %s reused memory location\n", __func__);

	ksft_test_result(check_page(map, PAGE_NUM_TO_TEST, 1) != 0,
			 "Test %s dirty bit of previous page\n", __func__);

	munmap(map2, mmap_size);
}

/*
 * read_pmd_pagesize(), check_for_pattern() and check_huge() adapted
 * from 'tools/testing/selftest/vm/split_huge_page_test.c'
 */
static uint64_t read_pmd_pagesize(void)
{
	int fd;
	char buf[20];
	ssize_t num_read;

	fd = open(PMD_SIZE_PATH, O_RDONLY);
	if (fd == -1)
		ksft_exit_fail_msg("Open hpage_pmd_size failed\n");

	num_read = read(fd, buf, 19);
	if (num_read < 1) {
		close(fd);
		ksft_exit_fail_msg("Read hpage_pmd_size failed\n");
	}
	buf[num_read] = '\0';
	close(fd);

	return strtoul(buf, NULL, 10);
}

static bool check_for_pattern(FILE *fp, const char *pattern, char *buf)
{
	while (fgets(buf, MAX_LINE_LENGTH, fp) != NULL) {
		if (!strncmp(buf, pattern, strlen(pattern)))
			return true;
	}
	return false;
}

static uint64_t check_huge(void *addr)
{
	uint64_t thp = 0;
	int ret;
	FILE *fp;
	char buffer[MAX_LINE_LENGTH];
	char addr_pattern[MAX_LINE_LENGTH];

	ret = snprintf(addr_pattern, MAX_LINE_LENGTH, "%08lx-",
		       (unsigned long) addr);
	if (ret >= MAX_LINE_LENGTH)
		ksft_print_msg("%s: Pattern is too long\n", __func__);

	fp = fopen(SMAP_PATH, "r");
	if (!fp)
		ksft_print_msg("%s: Failed to open file %s\n", __func__, SMAP_PATH);

	if (!check_for_pattern(fp, addr_pattern, buffer))
		goto err_out;

	/*
	 * Fetch the AnonHugePages: in the same block and check the number of
	 * hugepages.
	 */
	if (!check_for_pattern(fp, "AnonHugePages:", buffer))
		goto err_out;

	if (sscanf(buffer, "AnonHugePages:%10ld kB", &thp) != 1)
		ksft_print_msg("Reading smap error\n");

err_out:
	fclose(fp);

	return thp;
}

static void test_hugepage(void)
{
	char *map;
	int i, ret;
	size_t hpage_len = read_pmd_pagesize();

	map = memalign(hpage_len, hpage_len);
	if (!map)
		ksft_exit_fail_msg("memalign failed\n");

	ret = madvise(map, hpage_len, MADV_HUGEPAGE);
	if (ret)
		ksft_exit_fail_msg("madvise failed %d\n", ret);

	for (i = 0; i < hpage_len; i++)
		map[i] = (char)i;

	ksft_test_result(check_huge(map), "Test %s huge page allocation\n", __func__);

	clear_all_refs();
	for (i = 0 ; i < TEST_ITERATIONS ; i++) {
		if (check_page(map, PAGE_NUM_TO_TEST, 1) == 1) {
			ksft_print_msg("dirty bit was 1, but should be 0 (i=%d)\n", i);
			break;
		}

		touch_page(map, PAGE_NUM_TO_TEST);

		if (check_page(map, PAGE_NUM_TO_TEST, 1) == 0) {
			ksft_print_msg("dirty bit was 0, but should be 1 (i=%d)\n", i);
			break;
		}
	}

	ksft_test_result(i == TEST_ITERATIONS, "Test %s dirty bit\n", __func__);

	munmap(map, mmap_size);
}

int main(int argc, char **argv)
{
	ksft_print_header();
	ksft_set_plan(5);

	pagemap = open(PAGEMAP_PATH, O_RDONLY);
	if (pagemap < 0)
		ksft_exit_fail_msg("Failed to open %s\n", PAGEMAP_PATH);

	clear_refs = open(CLEAR_REFS_PATH, O_WRONLY);
	if (clear_refs < 0)
		ksft_exit_fail_msg("Failed to open %s\n", CLEAR_REFS_PATH);

	pagesize = getpagesize();
	mmap_size = 10 * pagesize;

	test_simple();
	test_vma_reuse();
	test_hugepage();

	return ksft_exit_pass();
}
