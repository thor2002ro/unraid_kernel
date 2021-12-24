// SPDX-License-Identifier: GPL-2.0

//! A generic lock guard and trait.
//!
//! This module contains a lock guard that can be used with any locking primitive that implements
//! the ([`Lock`]) trait. It also contains the definition of the trait, which can be leveraged by
//! other constructs to work on generic locking primitives.

use super::NeedsLockClass;
use crate::{bindings, str::CStr};
use core::pin::Pin;

/// Allows mutual exclusion primitives that implement the [`Lock`] trait to automatically unlock
/// when a guard goes out of scope. It also provides a safe and convenient way to access the data
/// protected by the lock.
#[must_use = "the lock unlocks immediately when the guard is unused"]
pub struct GuardMut<'a, L: Lock + ?Sized> {
    pub(crate) guard: Guard<'a, L>,
}

// SAFETY: `GuardMut` is sync when the data protected by the lock is also sync. This is more
// conservative than the default compiler implementation; more details can be found on
// https://github.com/rust-lang/rust/issues/41622 -- it refers to `MutexGuard` from the standard
// library.
unsafe impl<L> Sync for GuardMut<'_, L>
where
    L: Lock + ?Sized,
    L::Inner: Sync,
{
}

impl<L: Lock + ?Sized> core::ops::Deref for GuardMut<'_, L> {
    type Target = L::Inner;

    fn deref(&self) -> &Self::Target {
        self.guard.deref()
    }
}

impl<L: Lock + ?Sized> core::ops::DerefMut for GuardMut<'_, L> {
    fn deref_mut(&mut self) -> &mut L::Inner {
        // SAFETY: The caller owns the lock, so it is safe to deref the protected data.
        unsafe { &mut *self.guard.lock.locked_data().get() }
    }
}

impl<'a, L: Lock + ?Sized> GuardMut<'a, L> {
    /// Constructs a new lock guard.
    ///
    /// # Safety
    ///
    /// The caller must ensure that it owns the lock.
    pub(crate) unsafe fn new(lock: &'a L, context: L::GuardContext) -> Self {
        // SAFETY: The safety requirements for this function satisfy the `Guard::new` ones.
        Self {
            guard: unsafe { Guard::new(lock, context) },
        }
    }
}

/// Allows mutual exclusion primitives that implement the [`Lock`] trait to automatically unlock
/// when a guard goes out of scope. It also provides a safe and convenient way to immutably access
/// the data protected by the lock.
#[must_use = "the lock unlocks immediately when the guard is unused"]
pub struct Guard<'a, L: Lock + ?Sized> {
    pub(crate) lock: &'a L,
    pub(crate) context: L::GuardContext,
}

// SAFETY: `Guard` is sync when the data protected by the lock is also sync. This is more
// conservative than the default compiler implementation; more details can be found on
// https://github.com/rust-lang/rust/issues/41622 -- it refers to `MutexGuard` from the standard
// library.
unsafe impl<L> Sync for Guard<'_, L>
where
    L: Lock + ?Sized,
    L::Inner: Sync,
{
}

impl<L: Lock + ?Sized> core::ops::Deref for Guard<'_, L> {
    type Target = L::Inner;

    fn deref(&self) -> &Self::Target {
        // SAFETY: The caller owns the lock, so it is safe to deref the protected data.
        unsafe { &*self.lock.locked_data().get() }
    }
}

impl<L: Lock + ?Sized> Drop for Guard<'_, L> {
    fn drop(&mut self) {
        // SAFETY: The caller owns the lock, so it is safe to unlock it.
        unsafe { self.lock.unlock(&mut self.context) };
    }
}

impl<'a, L: Lock + ?Sized> Guard<'a, L> {
    /// Constructs a new immutable lock guard.
    ///
    /// # Safety
    ///
    /// The caller must ensure that it owns the lock.
    pub(crate) unsafe fn new(lock: &'a L, context: L::GuardContext) -> Self {
        Self { lock, context }
    }
}

/// A generic mutual exclusion primitive.
///
/// [`Guard`] and [`GuardMut`] are written such that any mutual exclusion primitive that can
/// implement this trait can also benefit from having an automatic way to unlock itself.
///
/// # Safety
///
/// Implementers of this trait must ensure that only one thread/CPU may access the protected data
/// once the lock is held, that is, between calls to `lock_noguard` and `unlock`.
pub unsafe trait Lock {
    /// The type of the data protected by the lock.
    type Inner: ?Sized;

    /// The type of context, if any, that needs to be stored in the guard.
    type GuardContext;

    /// Acquires the lock, making the caller its owner.
    #[must_use]
    fn lock_noguard(&self) -> Self::GuardContext;

    /// Reacquires the lock, making the caller its owner.
    ///
    /// The guard context before the last unlock is passed in.
    ///
    /// Locks that don't require this state on relock can simply use the default implementation
    /// that calls [`Lock::lock_noguard`].
    fn relock(&self, ctx: &mut Self::GuardContext) {
        *ctx = self.lock_noguard();
    }

    /// Releases the lock, giving up ownership of the lock.
    ///
    /// # Safety
    ///
    /// It must only be called by the current owner of the lock.
    unsafe fn unlock(&self, context: &mut Self::GuardContext);

    /// Returns the data protected by the lock.
    fn locked_data(&self) -> &core::cell::UnsafeCell<Self::Inner>;
}

/// A generic mutual exclusion primitive that can be instantiated generically.
pub trait CreatableLock: Lock {
    /// Constructs a new instance of the lock.
    ///
    /// # Safety
    ///
    /// The caller must call [`CreatableLock::init_lock`] before using the lock.
    unsafe fn new_lock(data: Self::Inner) -> Self;

    /// Initialises the lock type instance so that it can be safely used.
    ///
    /// # Safety
    ///
    /// `key` must point to a valid memory location that will remain valid until the lock is
    /// dropped.
    unsafe fn init_lock(
        self: Pin<&mut Self>,
        name: &'static CStr,
        key: *mut bindings::lock_class_key,
    );
}

impl<L: CreatableLock> NeedsLockClass for L {
    unsafe fn init(
        self: Pin<&mut Self>,
        name: &'static CStr,
        key: *mut bindings::lock_class_key,
        _: *mut bindings::lock_class_key,
    ) {
        // SAFETY: The safety requirements of this function satisfy those of `init_lock`.
        unsafe { self.init_lock(name, key) };
    }
}
