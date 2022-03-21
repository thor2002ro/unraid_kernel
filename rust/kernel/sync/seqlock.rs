// SPDX-License-Identifier: GPL-2.0

//! A kernel sequential lock (seqlock).
//!
//! This module allows Rust code to use the sequential locks based on the kernel's `seqcount_t` and
//! any locks implementing the [`CreatableLock`] trait.
//!
//! See <https://www.kernel.org/doc/Documentation/locking/seqlock.rst>.

use super::{CreatableLock, Guard, Lock, NeedsLockClass, ReadLock};
use crate::{bindings, str::CStr, Opaque};
use core::{cell::UnsafeCell, marker::PhantomPinned, ops::Deref, pin::Pin};

/// Exposes sequential locks backed by the kernel's `seqcount_t`.
///
/// The write-side critical section is protected by a lock implementing the `CreatableLock` trait.
///
/// # Examples
///
///```
/// # use kernel::prelude::*;
/// use kernel::sync::{SeqLock, SpinLock};
/// use core::sync::atomic::{AtomicU32, Ordering};
///
/// struct Example {
///     a: AtomicU32,
///     b: AtomicU32,
/// }
///
/// fn get_sum(v: &SeqLock<SpinLock<Example>>) -> u32 {
///     // Use `access` to access the fields of `Example`.
///     v.access(|e| e.a.load(Ordering::Relaxed) + e.b.load(Ordering::Relaxed))
/// }
///
/// fn get_sum_with_guard(v: &SeqLock<SpinLock<Example>>) -> u32 {
///     // Use `read` and `need_retry` in a loop to access the fields of `Example`.
///     loop {
///         let guard = v.read();
///         let sum = guard.a.load(Ordering::Relaxed) + guard.b.load(Ordering::Relaxed);
///         if !guard.need_retry() {
///             break sum;
///         }
///     }
/// }
///
/// fn inc_each(v: &SeqLock<SpinLock<Example>>) {
///     // Use a write-side guard to access the fields of `Example`.
///     let guard = v.write();
///     let a = guard.a.load(Ordering::Relaxed);
///     guard.a.store(a + 1, Ordering::Relaxed);
///     let b = guard.b.load(Ordering::Relaxed);
///     guard.b.store(b + 1, Ordering::Relaxed);
/// }
/// ```
pub struct SeqLock<L: CreatableLock + Lock + ?Sized> {
    _p: PhantomPinned,
    count: Opaque<bindings::seqcount>,
    write_lock: L,
}

// SAFETY: `SeqLock` can be transferred across thread boundaries iff the data it protects and the
// underlying lock can.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl<L: CreatableLock + Lock + Send> Send for SeqLock<L> where L::Inner: Send {}

// SAFETY: `SeqLock` allows concurrent access to the data it protects by both readers and writers,
// so it requires that the data it protects be `Sync`, as well as the underlying lock.
unsafe impl<L: CreatableLock + Lock + Sync> Sync for SeqLock<L> where L::Inner: Sync {}

impl<L: CreatableLock + Lock> SeqLock<L> {
    /// Constructs a new instance of [`SeqLock`].
    ///
    /// # Safety
    ///
    /// The caller must call [`SeqLock::init`] before using the seqlock.
    pub unsafe fn new(data: L::CreateArgType) -> Self
    where
        L::CreateArgType: Sized,
    {
        Self {
            _p: PhantomPinned,
            count: Opaque::uninit(),
            // SAFETY: `L::init_lock` is called from `SeqLock::init`, which is required to be
            // called by the function's safety requirements.
            write_lock: unsafe { L::new_lock(data) },
        }
    }
}

impl<L: CreatableLock + Lock + ?Sized> SeqLock<L> {
    /// Accesses the protected data in read mode.
    ///
    /// Readers and writers are allowed to run concurrently, so callers must check if they need to
    /// refetch the values before they are used (e.g., because a writer changed them concurrently,
    /// rendering them potentially inconsistent). The check is performed via calls to
    /// [`SeqLockReadGuard::need_retry`].
    pub fn read(&self) -> SeqLockReadGuard<'_, L> {
        SeqLockReadGuard {
            lock: self,
            // SAFETY: `count` contains valid memory.
            start_count: unsafe { bindings::read_seqcount_begin(self.count.get()) },
        }
    }

    /// Accesses the protected data in read mode.
    ///
    /// The provided closure is called repeatedly if it may have accessed inconsistent data (e.g.,
    /// because a concurrent writer modified it). This is a wrapper around [`SeqLock::read`] and
    /// [`SeqLockReadGuard::need_retry`] in a loop.
    pub fn access<F: Fn(&L::Inner) -> R, R>(&self, cb: F) -> R {
        loop {
            let guard = self.read();
            let ret = cb(&guard);
            if !guard.need_retry() {
                return ret;
            }
        }
    }

    /// Locks the underlying lock and returns a guard that allows access to the protected data.
    ///
    /// The guard is not mutable though because readers are still allowed to concurrently access
    /// the data. The protected data structure needs to provide interior mutability itself (e.g.,
    /// via atomic types) for the individual fields that can be mutated.
    pub fn write(&self) -> Guard<'_, Self, ReadLock> {
        let ctx = self.lock_noguard();
        // SAFETY: The seqlock was just acquired.
        unsafe { Guard::new(self, ctx) }
    }
}

impl<L: CreatableLock + Lock + ?Sized> NeedsLockClass for SeqLock<L> {
    unsafe fn init(
        mut self: Pin<&mut Self>,
        name: &'static CStr,
        key1: *mut bindings::lock_class_key,
        key2: *mut bindings::lock_class_key,
    ) {
        // SAFETY: `write_lock` is pinned when `self` is.
        let pinned = unsafe { self.as_mut().map_unchecked_mut(|s| &mut s.write_lock) };
        // SAFETY: `key1` is valid by the safety requirements of this function.
        unsafe { pinned.init_lock(name, key1) };
        // SAFETY: `key2` is valid by the safety requirements of this function.
        unsafe { bindings::__seqcount_init(self.count.get(), name.as_char_ptr(), key2) };
    }
}

// SAFETY: The underlying lock ensures mutual exclusion.
unsafe impl<L: CreatableLock + Lock + ?Sized> Lock<ReadLock> for SeqLock<L> {
    type Inner = L::Inner;
    type GuardContext = L::GuardContext;

    fn lock_noguard(&self) -> L::GuardContext {
        let ctx = self.write_lock.lock_noguard();
        // SAFETY: `count` contains valid memory.
        unsafe { bindings::write_seqcount_begin(self.count.get()) };
        ctx
    }

    fn relock(&self, ctx: &mut L::GuardContext) {
        self.write_lock.relock(ctx);
        // SAFETY: `count` contains valid memory.
        unsafe { bindings::write_seqcount_begin(self.count.get()) };
    }

    unsafe fn unlock(&self, ctx: &mut L::GuardContext) {
        // SAFETY: The safety requirements of the function ensure that lock is owned by the caller.
        unsafe { bindings::write_seqcount_end(self.count.get()) };
        // SAFETY: The safety requirements of the function ensure that lock is owned by the caller.
        unsafe { self.write_lock.unlock(ctx) };
    }

    fn locked_data(&self) -> &UnsafeCell<L::Inner> {
        self.write_lock.locked_data()
    }
}

/// Allows read-side access to data protected by a sequential lock.
pub struct SeqLockReadGuard<'a, L: CreatableLock + Lock + ?Sized> {
    lock: &'a SeqLock<L>,
    start_count: u32,
}

impl<L: CreatableLock + Lock + ?Sized> SeqLockReadGuard<'_, L> {
    /// Determine if the callers needs to retry reading values.
    ///
    /// It returns `true` when a concurrent writer ran between the guard being created and
    /// [`Self::need_retry`] being called.
    pub fn need_retry(&self) -> bool {
        // SAFETY: `count` is valid because the guard guarantees that the lock remains alive.
        unsafe { bindings::read_seqcount_retry(self.lock.count.get(), self.start_count) != 0 }
    }
}

impl<L: CreatableLock + Lock + ?Sized> Deref for SeqLockReadGuard<'_, L> {
    type Target = L::Inner;

    fn deref(&self) -> &Self::Target {
        // SAFETY: We only ever allow shared access to the protected data.
        unsafe { &*self.lock.locked_data().get() }
    }
}
