/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_TRUSTED_FOR_H
#define _UAPI_LINUX_TRUSTED_FOR_H

/**
 * enum trusted_for_usage - Usage for which a file descriptor is trusted
 *
 * Argument of trusted_for(2).
 */
enum trusted_for_usage {
	/**
	 * @TRUSTED_FOR_EXECUTION: Check that the data read from a file
	 * descriptor is trusted to be executed or interpreted (e.g. scripts).
	 */
	TRUSTED_FOR_EXECUTION = 1,
};

#endif /* _UAPI_LINUX_TRUSTED_FOR_H */
