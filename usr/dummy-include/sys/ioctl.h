/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _DUMMY_SYS_IOCTL_H
#define _DUMMY_SYS_IOCTL_H

#define _IOC_NRBITS	8
#define _IOC_TYPEBITS	8

#ifndef _IOC_SIZEBITS
# define _IOC_SIZEBITS	14
#endif

#define _IOC_NRSHIFT	0
#define _IOC_TYPESHIFT	(_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT	(_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT	(_IOC_SIZESHIFT+_IOC_SIZEBITS)

#ifndef _IOC_WRITE
# define _IOC_WRITE	1U
#endif

#ifndef _IOC_READ
# define _IOC_READ	2U
#endif

#define _IOC(dir, type, nr, size) \
	(((dir)  << _IOC_DIRSHIFT) | \
	 ((type) << _IOC_TYPESHIFT) | \
	 ((nr)   << _IOC_NRSHIFT) | \
	 ((size) << _IOC_SIZESHIFT))

#define _IOC_TYPECHECK(t) (sizeof(t))

#define _IOW(type, nr, size)	_IOC(_IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(size)))
#define _IOWR(type, nr, size)	_IOC(_IOC_READ|_IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(size)))

extern int ioctl(int __fd, unsigned long __request, ...);

#endif /* _DUMMY_SYS_IOCTL_H */
