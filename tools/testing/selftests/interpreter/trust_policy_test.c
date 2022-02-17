// SPDX-License-Identifier: GPL-2.0
/*
 * Test trusted_for(2) with fs.trusted_for_policy sysctl
 *
 * Copyright © 2018-2020 ANSSI
 *
 * Author: Mickaël Salaün <mic@digikod.net>
 */

#define _GNU_SOURCE
#include <asm-generic/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/trusted-for.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include "../kselftest_harness.h"

#ifndef trusted_for
static int trusted_for(const int fd, const enum trusted_for_usage usage,
		const __u32 flags)
{
	errno = 0;
	return syscall(__NR_trusted_for, fd, usage, flags);
}
#endif

static const char sysctl_path[] = "/proc/sys/fs/trusted_for_policy";

static const char workdir_path[] = "./test-mount";
static const char reg_file_path[] = "./test-mount/regular_file";
static const char dir_path[] = "./test-mount/directory";
static const char block_dev_path[] = "./test-mount/block_device";
static const char char_dev_path[] = "./test-mount/character_device";
static const char fifo_path[] = "./test-mount/fifo";

static void ignore_dac(struct __test_metadata *_metadata, int override)
{
	cap_t caps;
	const cap_value_t cap_val[2] = {
		CAP_DAC_OVERRIDE,
		CAP_DAC_READ_SEARCH,
	};

	caps = cap_get_proc();
	ASSERT_NE(NULL, caps);
	ASSERT_EQ(0, cap_set_flag(caps, CAP_EFFECTIVE, 2, cap_val,
				override ? CAP_SET : CAP_CLEAR));
	ASSERT_EQ(0, cap_set_proc(caps));
	EXPECT_EQ(0, cap_free(caps));
}

static void ignore_sys_admin(struct __test_metadata *_metadata, int override)
{
	cap_t caps;
	const cap_value_t cap_val[1] = {
		CAP_SYS_ADMIN,
	};

	caps = cap_get_proc();
	ASSERT_NE(NULL, caps);
	ASSERT_EQ(0, cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_val,
				override ? CAP_SET : CAP_CLEAR));
	ASSERT_EQ(0, cap_set_proc(caps));
	EXPECT_EQ(0, cap_free(caps));
}

static void test_omx(struct __test_metadata *_metadata,
		const char *const path, const int err_access)
{
	int flags = O_RDONLY | O_CLOEXEC;
	int fd, access_ret, access_errno;

	/* Do not block on pipes. */
	if (path == fifo_path)
		flags |= O_NONBLOCK;

	fd = open(path, flags);
	ASSERT_LE(0, fd) {
		TH_LOG("Failed to open %s: %s", path, strerror(errno));
	}
	access_ret = trusted_for(fd, TRUSTED_FOR_EXECUTION, 0);
	access_errno = errno;
	if (err_access) {
		ASSERT_EQ(err_access, access_errno) {
			TH_LOG("Wrong error for trusted_for(2) with %s: %s",
					path, strerror(access_errno));
		}
		ASSERT_EQ(-1, access_ret);
	} else {
		ASSERT_EQ(0, access_ret) {
			TH_LOG("Access denied for %s: %s", path, strerror(access_errno));
		}
	}

	/* Tests unsupported trusted usage. */
	access_ret = trusted_for(fd, 0, 0);
	ASSERT_EQ(-1, access_ret);
	ASSERT_EQ(EINVAL, errno);

	access_ret = trusted_for(fd, 2, 0);
	ASSERT_EQ(-1, access_ret);
	ASSERT_EQ(EINVAL, errno);

	EXPECT_EQ(0, close(fd));
}

static void test_policy_fd(struct __test_metadata *_metadata, const int fd,
		const bool has_policy)
{
	const int ret = trusted_for(fd, TRUSTED_FOR_EXECUTION, 0);

	if (has_policy) {
		ASSERT_EQ(-1, ret);
		ASSERT_EQ(EACCES, errno) {
			TH_LOG("Wrong error for trusted_for(2) with FD: %s", strerror(errno));
		}
	} else {
		ASSERT_EQ(0, ret) {
			TH_LOG("Access denied for FD: %s", strerror(errno));
		}
	}
}

FIXTURE(access) {
	char initial_sysctl_value;
	int memfd, pipefd;
	int pipe_fds[2], socket_fds[2];
};

static void test_file_types(struct __test_metadata *_metadata, FIXTURE_DATA(access) *self,
		const int err_code, const bool has_policy)
{
	/* Tests are performed on a tmpfs mount point. */
	test_omx(_metadata, reg_file_path, err_code);
	test_omx(_metadata, dir_path, has_policy ? EACCES : 0);
	test_omx(_metadata, block_dev_path, has_policy ? EACCES : 0);
	test_omx(_metadata, char_dev_path, has_policy ? EACCES : 0);
	test_omx(_metadata, fifo_path, has_policy ? EACCES : 0);

	/* Checks that exec is denied for any socket FD. */
	test_policy_fd(_metadata, self->socket_fds[0], has_policy);

	/* Checks that exec is denied for any memfd. */
	test_policy_fd(_metadata, self->memfd, has_policy);

	/* Checks that exec is denied for any pipefs FD. */
	test_policy_fd(_metadata, self->pipefd, has_policy);
}

static void test_files(struct __test_metadata *_metadata, FIXTURE_DATA(access) *self,
		const int err_code, const bool has_policy)
{
	/* Tests as root. */
	ignore_dac(_metadata, 1);
	test_file_types(_metadata, self, err_code, has_policy);

	/* Tests without bypass. */
	ignore_dac(_metadata, 0);
	test_file_types(_metadata, self, err_code, has_policy);
}

static void sysctl_write_char(struct __test_metadata *_metadata, const char value)
{
	int fd;

	fd = open(sysctl_path, O_WRONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	ASSERT_EQ(1, write(fd, &value, 1));
	EXPECT_EQ(0, close(fd));
}

static char sysctl_read_char(struct __test_metadata *_metadata)
{
	int fd;
	char sysctl_value;

	fd = open(sysctl_path, O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	ASSERT_EQ(1, read(fd, &sysctl_value, 1));
	EXPECT_EQ(0, close(fd));
	return sysctl_value;
}

FIXTURE_VARIANT(access) {
	const bool mount_exec;
	const bool file_exec;
	const int sysctl_err_code[3];
};

FIXTURE_VARIANT_ADD(access, mount_exec_file_exec) {
	.mount_exec = true,
	.file_exec = true,
	.sysctl_err_code = {0, 0, 0},
};

FIXTURE_VARIANT_ADD(access, mount_exec_file_noexec)
{
	.mount_exec = true,
	.file_exec = false,
	.sysctl_err_code = {0, EACCES, EACCES},
};

FIXTURE_VARIANT_ADD(access, mount_noexec_file_exec)
{
	.mount_exec = false,
	.file_exec = true,
	.sysctl_err_code = {EACCES, 0, EACCES},
};

FIXTURE_VARIANT_ADD(access, mount_noexec_file_noexec)
{
	.mount_exec = false,
	.file_exec = false,
	.sysctl_err_code = {EACCES, EACCES, EACCES},
};

FIXTURE_SETUP(access)
{
	int procfd_path_size;
	static const char path_template[] = "/proc/self/fd/%d";
	char procfd_path[sizeof(path_template) + 10];

	/*
	 * Cleans previous workspace if any error previously happened (don't
	 * check errors).
	 */
	umount(workdir_path);
	rmdir(workdir_path);

	/* Creates a clean mount point. */
	ASSERT_EQ(0, mkdir(workdir_path, 00700));
	ASSERT_EQ(0, mount("test", workdir_path, "tmpfs", MS_MGC_VAL |
				(variant->mount_exec ? 0 : MS_NOEXEC),
				"mode=0700,size=4k"));

	/* Creates a regular file. */
	ASSERT_EQ(0, mknod(reg_file_path, S_IFREG | (variant->file_exec ? 0500 : 0400), 0));
	/* Creates a directory. */
	ASSERT_EQ(0, mkdir(dir_path, variant->file_exec ? 0500 : 0400));
	/* Creates a character device: /dev/null. */
	ASSERT_EQ(0, mknod(char_dev_path, S_IFCHR | 0400, makedev(1, 3)));
	/* Creates a block device: /dev/loop0 */
	ASSERT_EQ(0, mknod(block_dev_path, S_IFBLK | 0400, makedev(7, 0)));
	/* Creates a fifo. */
	ASSERT_EQ(0, mknod(fifo_path, S_IFIFO | 0400, 0));

	/* Creates a regular file without user mount point. */
	self->memfd = memfd_create("test-interpreted", MFD_CLOEXEC);
	ASSERT_LE(0, self->memfd);
	/* Sets mode, which must be ignored by the exec check. */
	ASSERT_EQ(0, fchmod(self->memfd, variant->file_exec ? 0500 : 0400));

	/* Creates a pipefs file descriptor. */
	ASSERT_EQ(0, pipe(self->pipe_fds));
	procfd_path_size = snprintf(procfd_path, sizeof(procfd_path),
			path_template, self->pipe_fds[0]);
	ASSERT_LT(procfd_path_size, sizeof(procfd_path));
	self->pipefd = open(procfd_path, O_RDONLY | O_CLOEXEC);
	ASSERT_LE(0, self->pipefd);
	ASSERT_EQ(0, fchmod(self->pipefd, variant->file_exec ? 0500 : 0400));

	/* Creates a socket file descriptor. */
	ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, self->socket_fds));

	/* Saves initial sysctl value. */
	self->initial_sysctl_value = sysctl_read_char(_metadata);

	/* Prepares for sysctl writes. */
	ignore_sys_admin(_metadata, 1);
}

FIXTURE_TEARDOWN(access)
{
	EXPECT_EQ(0, close(self->memfd));
	EXPECT_EQ(0, close(self->pipefd));
	EXPECT_EQ(0, close(self->pipe_fds[0]));
	EXPECT_EQ(0, close(self->pipe_fds[1]));
	EXPECT_EQ(0, close(self->socket_fds[0]));
	EXPECT_EQ(0, close(self->socket_fds[1]));

	/* Restores initial sysctl value. */
	sysctl_write_char(_metadata, self->initial_sysctl_value);

	/* There is no need to unlink the test files. */
	ASSERT_EQ(0, umount(workdir_path));
	ASSERT_EQ(0, rmdir(workdir_path));
}

TEST_F(access, sysctl_0)
{
	/* Do not enforce anything. */
	sysctl_write_char(_metadata, '0');
	test_files(_metadata, self, 0, false);
}

TEST_F(access, sysctl_1)
{
	/* Enforces mount exec check. */
	sysctl_write_char(_metadata, '1');
	test_files(_metadata, self, variant->sysctl_err_code[0], true);
}

TEST_F(access, sysctl_2)
{
	/* Enforces file exec check. */
	sysctl_write_char(_metadata, '2');
	test_files(_metadata, self, variant->sysctl_err_code[1], true);
}

TEST_F(access, sysctl_3)
{
	/* Enforces mount and file exec check. */
	sysctl_write_char(_metadata, '3');
	test_files(_metadata, self, variant->sysctl_err_code[2], true);
}

FIXTURE(cleanup) {
	char initial_sysctl_value;
};

FIXTURE_SETUP(cleanup)
{
	/* Saves initial sysctl value. */
	self->initial_sysctl_value = sysctl_read_char(_metadata);
}

FIXTURE_TEARDOWN(cleanup)
{
	/* Restores initial sysctl value. */
	ignore_sys_admin(_metadata, 1);
	sysctl_write_char(_metadata, self->initial_sysctl_value);
}

TEST_F(cleanup, sysctl_access_write)
{
	int fd;
	ssize_t ret;

	ignore_sys_admin(_metadata, 1);
	sysctl_write_char(_metadata, '0');

	ignore_sys_admin(_metadata, 0);
	fd = open(sysctl_path, O_WRONLY | O_CLOEXEC);
	ASSERT_LE(0, fd);
	ret = write(fd, "0", 1);
	ASSERT_EQ(-1, ret);
	ASSERT_EQ(EPERM, errno);
	EXPECT_EQ(0, close(fd));
}

TEST_HARNESS_MAIN
