// SPDX-License-Identifier: GPL-2.0

//! Generic devices that are part of the kernel's driver model.
//!
//! C header: [`include/linux/device.h`](../../../../include/linux/device.h)

use crate::{
    bindings,
    revocable::{Revocable, RevocableGuard},
    str::CStr,
    sync::{NeedsLockClass, RevocableMutex, RevocableMutexGuard, UniqueRef},
    Result,
};
use core::{
    ops::{Deref, DerefMut},
    pin::Pin,
};

/// A raw device.
///
/// # Safety
///
/// Implementers must ensure that the `*mut device` returned by [`RawDevice::raw_device`] is
/// related to `self`, that is, actions on it will affect `self`. For example, if one calls
/// `get_device`, then the refcount on the device represented by `self` will be incremented.
///
/// Additionally, implementers must ensure that the device is never renamed. Commit a5462516aa994
/// has details on why `device_rename` should not be used.
pub unsafe trait RawDevice {
    /// Returns the raw `struct device` related to `self`.
    fn raw_device(&self) -> *mut bindings::device;

    /// Returns the name of the device.
    fn name(&self) -> &CStr {
        let ptr = self.raw_device();

        // SAFETY: `ptr` is valid because `self` keeps it alive.
        let name = unsafe { bindings::dev_name(ptr) };

        // SAFETY: The name of the device remains valid while it is alive (because the device is
        // never renamed, per the safety requirement of this trait). This is guaranteed to be the
        // case because the reference to `self` outlives the one of the returned `CStr` (enforced
        // by the compiler because of their lifetimes).
        unsafe { CStr::from_char_ptr(name) }
    }
}

/// A ref-counted device.
///
/// # Invariants
///
/// `ptr` is valid, non-null, and has a non-zero reference count. One of the references is owned by
/// `self`, and will be decremented when `self` is dropped.
pub struct Device {
    pub(crate) ptr: *mut bindings::device,
}

impl Device {
    /// Creates a new device instance.
    ///
    /// # Safety
    ///
    /// Callers must ensure that `ptr` is valid, non-null, and has a non-zero reference count.
    pub unsafe fn new(ptr: *mut bindings::device) -> Self {
        // SAFETY: By the safety requiments, ptr is valid and its refcounted will be incremented.
        unsafe { bindings::get_device(ptr) };
        // INVARIANT: The safety requirements satisfy all but one invariant, which is that `self`
        // owns a reference. This is satisfied by the call to `get_device` above.
        Self { ptr }
    }

    /// Creates a new device instance from an existing [`RawDevice`] instance.
    pub fn from_dev(dev: &dyn RawDevice) -> Self {
        // SAFETY: The requirements are satisfied by the existence of `RawDevice` and its safety
        // requirements.
        unsafe { Self::new(dev.raw_device()) }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: By the type invariants, we know that `self` owns a reference, so it is safe to
        // relinquish it now.
        unsafe { bindings::put_device(self.ptr) };
    }
}

/// Device data.
///
/// When a device is removed (for whatever reason, for example, because the device was unplugged or
/// because the user decided to unbind the driver), the driver is given a chance to clean its state
/// up, and all io resources should ideally not be used anymore.
///
/// However, the device data is reference-counted because other subsystems hold pointers to it. So
/// some device state must be freed and not used anymore, while others must remain accessible.
///
/// This struct separates the device data into three categories:
/// 1. Registrations: are destroyed when the device is removed, but before the io resources
///    become inaccessible.
/// 2. Io resources: are available until the device is removed.
/// 3. General data: remain available as long as the ref count is nonzero.
///
/// This struct implements the `DeviceRemoval` trait so that it can clean resources up even if not
/// explicitly called by the device drivers.
pub struct Data<T, U, V> {
    registrations: RevocableMutex<T>,
    resources: Revocable<U>,
    general: V,
}

/// Safely creates an new reference-counted instance of [`Data`].
#[doc(hidden)]
#[macro_export]
macro_rules! new_device_data {
    ($reg:expr, $res:expr, $gen:expr, $name:literal) => {{
        static mut CLASS1: core::mem::MaybeUninit<$crate::bindings::lock_class_key> =
            core::mem::MaybeUninit::uninit();
        static mut CLASS2: core::mem::MaybeUninit<$crate::bindings::lock_class_key> =
            core::mem::MaybeUninit::uninit();
        let regs = $reg;
        let res = $res;
        let gen = $gen;
        let name = $crate::c_str!($name);
        // SAFETY: `CLASS1` and `CLASS2` are never used by Rust code directly; the C portion of the
        // kernel may change it though.
        unsafe {
            $crate::device::Data::try_new(
                regs,
                res,
                gen,
                name,
                CLASS1.as_mut_ptr(),
                CLASS2.as_mut_ptr(),
            )
        }
    }};
}

impl<T, U, V> Data<T, U, V> {
    /// Creates a new instance of `Data`.
    ///
    /// It is recommended that the [`new_device_data`] macro be used as it automatically creates
    /// the lock classes.
    ///
    /// # Safety
    ///
    /// `key1` and `key2` must point to valid memory locations and remain valid until `self` is
    /// dropped.
    pub unsafe fn try_new(
        registrations: T,
        resources: U,
        general: V,
        name: &'static CStr,
        key1: *mut bindings::lock_class_key,
        key2: *mut bindings::lock_class_key,
    ) -> Result<Pin<UniqueRef<Self>>> {
        let mut ret = Pin::from(UniqueRef::try_new(Self {
            // SAFETY: We call `RevocableMutex::init` below.
            registrations: unsafe { RevocableMutex::new(registrations) },
            resources: Revocable::new(resources),
            general,
        })?);

        // SAFETY: `Data::registrations` is pinned when `Data` is.
        let pinned = unsafe { ret.as_mut().map_unchecked_mut(|d| &mut d.registrations) };

        // SAFETY: The safety requirements of this function satisfy those of `RevocableMutex::init`.
        unsafe { pinned.init(name, key1, key2) };
        Ok(ret)
    }

    /// Returns the resources if they're still available.
    pub fn resources(&self) -> Option<RevocableGuard<'_, U>> {
        self.resources.try_access()
    }

    /// Returns the locked registrations if they're still available.
    pub fn registrations(&self) -> Option<RevocableMutexGuard<'_, T>> {
        self.registrations.try_lock()
    }
}

impl<T, U, V> crate::driver::DeviceRemoval for Data<T, U, V> {
    fn device_remove(&self) {
        // We revoke the registrations first so that resources are still available to them during
        // unregistration.
        self.registrations.revoke();

        // Release resources now. General data remains available.
        self.resources.revoke();
    }
}

impl<T, U, V> Deref for Data<T, U, V> {
    type Target = V;

    fn deref(&self) -> &V {
        &self.general
    }
}

impl<T, U, V> DerefMut for Data<T, U, V> {
    fn deref_mut(&mut self) -> &mut V {
        &mut self.general
    }
}
