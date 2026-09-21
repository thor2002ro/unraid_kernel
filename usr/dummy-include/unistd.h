/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _DUMMY_UNISTD_H
#define _DUMMY_UNISTD_H

# ifndef __pid_t_defined
typedef int pid_t;
#  define __pid_t_defined
# endif

extern int close(int __fd);

#endif /* _DUMMY_UNISTD_H */
