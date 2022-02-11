// SPDX-License-Identifier: GPL-2.0

//! Credentials management.
//!
//! C header: [`include/linux/cred.h`](../../../../include/linux/cred.h)
//!
//! Reference: <https://www.kernel.org/doc/html/latest/security/credentials.html>

use crate::bindings;
use core::{marker::PhantomData, mem::ManuallyDrop, ops::Deref};

/// Wraps the kernel's `struct cred`.
///
/// # Invariants
///
/// The pointer `Credential::ptr` is non-null and valid. Its reference count is also non-zero.
pub struct Credential {
    pub(crate) ptr: *const bindings::cred,
}

impl Clone for Credential {
    fn clone(&self) -> Self {
        // SAFETY: The type invariants guarantee that `self.ptr` has a non-zero reference count.
        let ptr = unsafe { bindings::get_cred(self.ptr) };

        // INVARIANT: We incremented the reference count to account for the new `Credential` being
        // created.
        Self { ptr }
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        // SAFETY: The type invariants guarantee that `ptr` has a non-zero reference count.
        unsafe { bindings::put_cred(self.ptr) };
    }
}

/// A wrapper for [`Credential`] that doesn't automatically decrement the refcount when dropped.
///
/// We need the wrapper because [`ManuallyDrop`] alone would allow callers to call
/// [`ManuallyDrop::into_inner`]. This would allow an unsafe sequence to be triggered without
/// `unsafe` blocks because it would trigger an unbalanced call to `put_cred`.
///
/// # Invariants
///
/// The wrapped [`Credential`] remains valid for the lifetime of the object.
pub struct CredentialRef<'a> {
    cred: ManuallyDrop<Credential>,
    _p: PhantomData<&'a ()>,
}

impl CredentialRef<'_> {
    /// Constructs a new [`struct cred`] wrapper that doesn't change its reference count.
    ///
    /// # Safety
    ///
    /// The pointer `ptr` must be non-null and valid for the lifetime of the object.
    pub(crate) unsafe fn from_ptr(ptr: *const bindings::cred) -> Self {
        Self {
            cred: ManuallyDrop::new(Credential { ptr }),
            _p: PhantomData,
        }
    }
}

impl Deref for CredentialRef<'_> {
    type Target = Credential;

    fn deref(&self) -> &Self::Target {
        self.cred.deref()
    }
}
