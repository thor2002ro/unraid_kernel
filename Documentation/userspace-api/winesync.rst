=====================================
Wine synchronization primitive driver
=====================================

This page documents the user-space API for the winesync driver.

winesync is a support driver for emulation of NT synchronization
primitives by the Wine project. It exists because implementation in
user-space, using existing tools, cannot simultaneously satisfy
performance, correctness, and security constraints. It is implemented
entirely in software, and does not drive any hardware device.

This interface is meant as a compatibility tool only, and should not
be used for general synchronization. Instead use generic, versatile
interfaces such as futex(2) and poll(2).

Synchronization primitives
==========================

The winesync driver exposes two types of synchronization primitives,
semaphores and mutexes.

A semaphore holds a single volatile 32-bit counter, and a static
32-bit integer denoting the maximum value. It is considered signaled
when the counter is nonzero. The counter is decremented by one when a
wait is satisfied. Both the initial and maximum count are established
when the semaphore is created.

A mutex holds a volatile 32-bit recursion count, and a volatile 32-bit
identifier denoting its owner. A mutex is considered signaled when its
owner is zero (indicating that it is not owned). The recursion count
is incremented when a wait is satisfied, and ownership is set to the
given identifier.

A mutex also holds an internal flag denoting whether its previous
owner has died; such a mutex is said to be inconsistent. Owner death
is not tracked automatically based on thread death, but rather must be
communicated using ``WINESYNC_IOC_KILL_OWNER``. An inconsistent mutex
is inherently considered unowned.

Except for the "unowned" semantics of zero, the actual value of the
owner identifier is not interpreted by the winesync driver at all. The
intended use is to store a thread identifier; however, the winesync
driver does not actually validate that a calling thread provides
consistent or unique identifiers.

Objects are represented by unsigned 32-bit integers.

Char device
===========

The winesync driver creates a single char device /dev/winesync. Each
file description opened on the device represents a unique namespace.
That is, objects created on one open file description are shared
across all its individual descriptors, but are not shared with other
open() calls on the same device. The same file description may be
shared across multiple processes.

ioctl reference
===============

All operations on the device are done through ioctls. There are four
structures used in ioctl calls::

   struct winesync_sem_args {
   	__u32 sem;
   	__u32 count;
   	__u32 max;
   };

   struct winesync_mutex_args {
   	__u32 mutex;
   	__u32 owner;
   	__u32 count;
   };

   /* used in struct winesync_wait_args */
   struct winesync_wait_obj {
   	__u32 obj;
   	__u32 flags;
   };

   struct winesync_wait_args {
   	__u64 sigmask;
   	__u64 sigsetsize;
   	__u64 timeout;
   	__u64 objs;
   	__u32 count;
   	__u32 owner;
   	__u32 index;
   	__u32 pad;
   };

Depending on the ioctl, members of the structure may be used as input,
output, or not at all.

All ioctls return 0 on success, and -1 on error, in which case `errno`
will be set to a nonzero error code.

The ioctls are as follows:

.. c:macro:: WINESYNC_IOC_CREATE_SEM

  Create a semaphore object. Takes a pointer to struct
  :c:type:`winesync_sem_args`, which is used as follows:

    ``count`` and ``max`` are input-only arguments, denoting the
    initial and maximum count of the semaphore.

    ``sem`` is an output-only argument, which will be filled with the
    identifier of the created semaphore if successful.

  Fails with ``EINVAL`` if ``count`` is greater than ``max``, or
  ``ENOMEM`` if not enough memory is available.

.. c:macro:: WINESYNC_IOC_CREATE_MUTEX

  Create a mutex object. Takes a pointer to struct
  :c:type:`winesync_mutex_args`, which is used as follows:

    ``owner`` is an input-only argument denoting the initial owner of
    the mutex.

    ``count`` is an input-only argument denoting the initial recursion
    count of the mutex. If ``owner`` is nonzero and ``count`` is zero,
    or if ``owner`` is zero and ``count`` is nonzero, the function
    fails with ``EINVAL``.

    ``mutex`` is an output-only argument, which will be filled with
    the identifier of the created mutex if successful.

  Fails with ``ENOMEM`` if not enough memory is available.

.. c:macro:: WINESYNC_IOC_DELETE

  Delete an object of any type. Takes an input-only pointer to a
  32-bit integer denoting the object to delete. Fails with ``EINVAL``
  if the object is not valid. Further ioctls attempting to use the
  object return ``EINVAL``, unless the object identifier is reused for
  another object.

  Wait ioctls currently in progress are not interrupted, and behave as
  if the object remains valid.

.. c:macro:: WINESYNC_IOC_PUT_SEM

  Post to a semaphore object. Takes a pointer to struct
  :c:type:`winesync_sem_args`, which is used as follows:

    ``sem`` is an input-only argument denoting the semaphore object.
    If ``sem`` does not identify a valid semaphore object, the ioctl
    fails with ``EINVAL``.

    ``count`` contains on input the count to add to the semaphore, and
    on output is filled with its previous count.

    ``max`` is not used.

  If adding ``count`` to the semaphore's current count would raise the
  latter past the semaphore's maximum count, the ioctl fails with
  ``EOVERFLOW`` and the semaphore is not affected. If raising the
  semaphore's count causes it to become signaled, eligible threads
  waiting on this semaphore will be woken and the semaphore's count
  decremented appropriately.

  The operation is atomic and totally ordered with respect to other
  operations on the same semaphore.

.. c:macro:: WINESYNC_IOC_PULSE_SEM

  This operation is identical to ``WINESYNC_IOC_PUT_SEM``, with one
  notable exception: the semaphore is always left in an *unsignaled*
  state, regardless of the initial count or the count added by the
  ioctl. That is, the count after a pulse operation will always be
  zero.

  A pulse operation can be thought of as a put operation, followed by
  clearing the semaphore's current count back to zero. Confer the
  following examples:

  * If three eligible threads are waiting on a semaphore, all with
    ``WINESYNC_WAIT_FLAG_GET``, and the semaphore is pulsed with a
    count of 2, only two of them will be woken, and the third will
    remain asleep.

  * If only one such thread is waiting, it will be woken up, but the
    semaphore's count will remain at zero.

  * If three eligible threads are waiting and none of them specify
    ``WINESYNC_WAIT_FLAG_GET``, all three threads will be woken, and
    the semaphore's count will remain at zero.

  In either case, a simultaneous ``WINESYNC_IOC_READ_SEM`` ioctl from
  another thread will always report a count of zero.

  If adding ``count`` to the semaphore's current count would raise the
  latter past the semaphore's maximum count, the ioctl fails with
  ``EOVERFLOW``. However, in this case the semaphore's count will
  still be reset to zero.

  The operation is atomic and totally ordered with respect to other
  operations on the same semaphore.

.. c:macro:: WINESYNC_IOC_PUT_MUTEX

  Release a mutex object. Takes a pointer to struct
  :c:type:`winesync_mutex_args`, which is used as follows:

    ``mutex`` is an input-only argument denoting the mutex object. If
    ``mutex`` does not identify a valid mutex object, the ioctl fails
    with ``EINVAL``.

    ``owner`` is an input-only argument denoting the mutex owner. If
    ``owner`` is zero, the ioctl fails with ``EINVAL``. If ``owner``
    is not the current owner of the mutex, the ioctl fails with
    ``EPERM``.

    ``count`` is an output-only argument which will be filled on
    success with the mutex's previous recursion count.

  The mutex's count will be decremented by one. If decrementing the
  mutex's count causes it to become zero, the mutex is marked as
  unowned and signaled, and eligible threads waiting on it will be
  woken as appropriate.

  The operation is atomic and totally ordered with respect to other
  operations on the same mutex.

.. c:macro:: WINESYNC_IOC_READ_SEM

  Read the current state of a semaphore object. Takes a pointer to
  struct :c:type:`winesync_sem_args`, which is used as follows:

    ``sem`` is an input-only argument denoting the semaphore object.
    If ``sem`` does not identify a valid semaphore object, the ioctl
    fails with ``EINVAL``.

    ``count`` and ``max`` are output-only arguments, which will be
    filled with the current and maximum count of the given semaphore.

  The operation is atomic and totally ordered with respect to other
  operations on the same semaphore.

.. c:macro:: WINESYNC_IOC_READ_MUTEX

  Read the current state of a mutex object. Takes a pointer to struct
  :c:type:`winesync_mutex_args`, which is used as follows:

    ``mutex`` is an input-only argument denoting the mutex object. If
    ``mutex`` does not identify a valid mutex object, the ioctl fails
    with ``EINVAL``.

    ``count`` and ``owner`` are output-only arguments, which will be
    filled with the current recursion count and owner of the given
    mutex. If the mutex is not owned, both ``count`` and ``owner`` are
    set to zero.

  If the mutex is marked as inconsistent, the function fails with
  ``EOWNERDEAD``. In this case, ``count`` and ``owner`` are set to
  zero.

  The operation is atomic and totally ordered with respect to other
  operations on the same mutex.

.. c:macro:: WINESYNC_IOC_KILL_OWNER

  Mark any mutexes owned by the given owner as unowned and
  inconsistent. Takes an input-only pointer to a 32-bit integer
  denoting the owner. If the owner is zero, the ioctl fails with
  ``EINVAL``.

  For each mutex currently owned by the given owner, eligible threads
  waiting on said mutex will be woken as appropriate (and such waits
  will fail with ``EOWNERDEAD``, as described below).

  The operation as a whole is not atomic; however, the modification of
  each mutex is atomic and totally ordered with respect to other
  operations on the same mutex.

.. c:macro:: WINESYNC_IOC_WAIT_ANY

  Poll on any of a list of objects, possibly acquiring at most one of
  them. Takes a pointer to struct :c:type:`winesync_wait_args`, which
  is used as follows:

    ``sigmask`` is an optional input-only pointer to a
    :c:type:`sigset_t` structure (specified as an integer so that the
    :c:type:`winesync_wait_args` structure has the same size
    regardless of architecture). If the pointer is not NULL, it holds
    a signal mask which will be applied to the current thread for the
    duration of the call, in the same fashion as ``pselect(2)``.

    ``sigsetsize`` specifies the size of the :c:type:`sigset_t`
    structure passed in ``sigmask``. It is ignored if ``sigmask`` is
    NULL.

    ``timeout`` is an optional input-only pointer to a 64-bit struct
    :c:type:`timespec` (specified as an integer so that the structure
    has the same size regardless of architecture). The timeout is
    specified in absolute format, as measured against the MONOTONIC
    clock. If the timeout is equal to or earlier than the current
    time, the function returns immediately without sleeping. If
    ``timeout`` is zero, i.e. NULL, the function will sleep until an
    object is signaled, and will not fail with ``ETIMEDOUT``.

    ``objs`` is a input-only pointer to an array of ``count``
    consecutive ``winesync_wait_obj`` structures (specified as an
    integer so that the structure has the same size regardless of
    architecture). In each structure, ``obj`` denotes an object to
    wait for, and ``flags`` specifies a combination of zero or more
    ``WINESYNC_WAIT_FLAG_*`` flags modifying the behaviour when
    waiting for that object. If any identifier is invalid, the
    function fails with ``EINVAL``.

    ``owner`` is an input-only argument denoting the mutex owner
    identifier. If any object in ``objs`` is a mutex, the ioctl will
    attempt to acquire that mutex on behalf of ``owner``. If ``owner``
    is zero, the ioctl fails with ``EINVAL``.

    ``index`` is an output-only argument which, if the ioctl is
    successful, is filled with the index of the object actually
    signaled. If unsuccessful, ``index`` is not modified.

    ``pad`` is unused, and exists to keep a consistent structure size.

  This function sleeps until one or more of the given objects is
  signaled, subsequently returning the index of the first signaled
  object, or until the timeout expires. In the latter case it fails
  with ``ETIMEDOUT``.

  Each object may optionally be accompanied by the
  ``WINESYNC_WAIT_FLAG_GET`` flag. If an object marked with this flag
  becomes signaled, the object will be atomically acquired by the
  waiter.

  A semaphore is considered to be signaled if its count is nonzero,
  and is acquired by decrementing its count by one. A mutex is
  considered to be signaled if it is unowned or if its owner matches
  the ``owner`` argument, and is acquired by incrementing its
  recursion count by one and setting its owner to the ``owner``
  argument.

  Acquisition is atomic and totally ordered with respect to other
  operations on the same object. If two wait operations (with
  different ``owner`` identifiers) are queued on the same mutex, both
  with the ``WINESYNC_WAIT_FLAG_GET`` flag set, only one is signaled.
  If two wait operations are queued on the same semaphore, both with
  the ``WINESYNC_WAIT_FLAG_GET`` flag set, and a value of one is
  posted to it, only one is signaled. The order in which threads are
  signaled is not specified.

  On the other hand, if neither waiter specifies
  ``WINESYNC_WAIT_FLAG_GET``, and the object becomes signaled, both
  waiters will be woken, and the object will not be modified. If one
  waiter specifies ``WINESYNC_WAIT_FLAG_GET``, that waiter will be
  woken and will acquire the object; it is unspecified whether the
  other waiter will be woken.

  If a mutex is inconsistent (in which case it is unacquired and
  therefore signaled), the ioctl fails with ``EOWNERDEAD``. Although
  this is a failure return, the function may otherwise be considered
  successful, and ``index`` is still set to the index of the mutex. If
  ``WINESYNC_WAIT_FLAG_GET`` is specified for said mutex, the mutex is
  marked as owned by the given owner (with a recursion count of 1) and
  as no longer inconsistent.

  It is valid to pass the same object more than once. If a wakeup
  occurs due to that object being signaled, ``index`` is set to the
  lowest index corresponding to that object.

  Fails with ``ENOMEM`` if not enough memory is available, or
  ``EINTR`` if a signal is received.

.. c:macro:: WINESYNC_IOC_WAIT_ALL

  Poll on a list of objects, waiting until all of them are
  simultaneously signaled. Takes a pointer to struct
  :c:type:`winesync_wait_args`, which is used identically to
  ``WINESYNC_IOC_WAIT_ANY``, except that ``index`` is always filled
  with zero on success.

  This function sleeps until all of the given objects are signaled. If
  all objects are not simultaneously signaled at any point before the
  timeout expires, it fails with ``ETIMEDOUT``.

  Objects may become signaled and subsequently designaled (through
  acquisition by other threads) while this thread is sleeping. Only
  once all objects are simultaneously signaled does the ioctl return.

  The flag ``WINESYNC_WAIT_FLAG_GET`` may optionally be specified for
  some or all of the objects, in which case the function will also
  simultaneously acquire every object so marked. The entire
  acquisition is atomic and totally ordered with respect to other
  operations on any of the given objects.

  If any mutex waited for is inconsistent at the time the function
  returns, the ioctl fails with ``EOWNERDEAD``. Similarly to
  ``WINESYNC_IOC_WAIT_ANY``, the function may be considered to have
  succeeded, and all objects marked with ``WINESYNC_WIAT_FLAG_GET``
  are still acquired. Note that if multiple mutex objects are
  specified, there is no way to know which were marked as
  inconsistent.

  Unlike ``WINESYNC_IOC_WAIT_ANY``, it is not valid to pass the same
  object more than once. If this is attempted, the function fails with
  ``EINVAL``.

  Fails with ``ENOMEM`` if not enough memory is available, or
  ``EINTR`` if a signal is received.
