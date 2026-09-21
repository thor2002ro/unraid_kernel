/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _DUMMY_FCNTL_H
#define _DUMMY_FCNTL_H

#ifndef O_RDWR
#define O_RDWR		00000002
#endif
extern int open(const char *__file, int __oflag, ...);

#endif /* _DUMMY_FCNTL_H */
