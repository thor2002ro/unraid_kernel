// SPDX-License-Identifier: GPL-2.0

//! Generic support for drivers of different buses (e.g., PCI, Platform, Amba, etc.).
//!
//! Each bus/subsystem is expected to implement [`DriverOps`], which allows drivers to register
//! using the [`Registration`] class.

use crate::{str::CStr, Error, KernelModule, Result, ScopeGuard, ThisModule};
use alloc::{boxed::Box, vec::Vec};
use core::{cell::UnsafeCell, mem::MaybeUninit, pin::Pin};

/// A subsystem (e.g., PCI, Platform, Amba, etc.) that allows drivers to be written for it.
pub trait DriverOps {
    /// The type that holds information about the registration. This is typically a struct defined
    /// by the C portion of the kernel.
    type RegType: Default;

    /// The type that holds identification data for the devices supported by the driver. In
    /// addition to the information required by the bus, it may also store device-specific data
    /// using Rust types.
    type IdType: 'static;

    /// The table of ids containing all supported devices.
    const ID_TABLE: &'static [Self::IdType];

    /// The raw type that holds identification data for the devices supported by the driver. This
    /// is typically a struct defined by the C portion of the kernel.
    ///
    /// A zero-terminated array of this type is produced and passed to the C portion during
    /// registration.
    type RawIdType;

    /// Registers a driver.
    ///
    /// # Safety
    ///
    /// `reg` must point to valid, initialised, and writable memory. It may be modified by this
    /// function to hold registration state.
    ///
    /// `id_table` must point to a valid for read zero-terminated array of ids.
    ///
    /// On success, `reg` and `id_table` must remain pinned and valid until the matching call to
    /// [`DriverOps::unregister`].
    unsafe fn register(
        reg: *mut Self::RegType,
        name: &'static CStr,
        id_table: *const Self::RawIdType,
    ) -> Result;

    /// Unregisters a driver previously registered with [`DriverOps::register`].
    ///
    /// # Safety
    ///
    /// `reg` must point to valid writable memory, initialised by a previous successful call to
    /// [`DriverOps::register`].
    unsafe fn unregister(reg: *mut Self::RegType);

    /// Converts an id into a raw id.
    ///
    /// This is used when building a zero-terminated array from the Rust array.
    fn to_raw_id(index: usize, id: &Self::IdType) -> Self::RawIdType;
}

/// The registration of a driver.
pub struct Registration<T: DriverOps> {
    is_registered: bool,
    concrete_reg: UnsafeCell<T::RegType>,
    id_table: Vec<MaybeUninit<T::RawIdType>>,
}

// SAFETY: `Registration` has no fields or methods accessible via `&Registration`, so it is safe to
// share references to it with multiple threads as nothing can be done.
unsafe impl<T: DriverOps> Sync for Registration<T> {}

impl<T: DriverOps> Registration<T> {
    /// Creates a new instance of the registration object.
    pub fn new() -> Self {
        Self {
            is_registered: false,
            concrete_reg: UnsafeCell::new(T::RegType::default()),
            id_table: Vec::new(),
        }
    }

    /// Allocates a pinned registration object and registers it.
    ///
    /// Returns a pinned heap-allocated representation of the registration.
    pub fn new_pinned(name: &'static CStr) -> Result<Pin<Box<Self>>> {
        let mut reg = Pin::from(Box::try_new(Self::new())?);
        reg.as_mut().register(name)?;
        Ok(reg)
    }

    /// Registers a driver with its subsystem.
    ///
    /// It must be pinned because the memory block that represents the registration is potentially
    /// self-referential.
    pub fn register(self: Pin<&mut Self>, name: &'static CStr) -> Result {
        // SAFETY: We never move out of `this`.
        let this = unsafe { self.get_unchecked_mut() };
        if this.is_registered {
            // Already registered.
            return Err(Error::EINVAL);
        }

        if this.id_table.is_empty() {
            this.build_table()?;
        }

        // SAFETY: `concrete_reg` was initialised via its default constructor. `id_table` was just
        // initialised above with a zero terminating entry. Both are only freed after `Self::drop`
        // is called, which first calls `T::unregister`.
        unsafe {
            T::register(
                this.concrete_reg.get(),
                name,
                &this.id_table[0] as *const _ as *const _,
            )
        }?;

        this.is_registered = true;
        Ok(())
    }

    /// Builds the zero-terminated raw-type array of supported devices.
    ///
    /// This is not ideal because the table is built at runtime. Once Rust fully supports const
    /// generics, we can build the table at compile time.
    fn build_table(&mut self) -> Result {
        // Clear the table on failure, to indicate that the table isn't initialised.
        let mut table = ScopeGuard::new_with_data(&mut self.id_table, |t| t.clear());

        table.try_reserve_exact(T::ID_TABLE.len() + 1)?;
        for (i, id) in T::ID_TABLE.iter().enumerate() {
            table.try_push(MaybeUninit::new(T::to_raw_id(i, id)))?;
        }
        table.try_push(MaybeUninit::zeroed())?;
        table.dismiss();
        Ok(())
    }
}

impl<T: DriverOps> Default for Registration<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: DriverOps> Drop for Registration<T> {
    fn drop(&mut self) {
        if self.is_registered {
            // SAFETY: This path only runs if a previous call to `T::register` completed
            // successfully.
            unsafe { T::unregister(self.concrete_reg.get()) };
        }
    }
}

/// Custom code within device removal.
pub trait DeviceRemoval {
    /// Cleans resources up when the device is removed.
    ///
    /// This is called when a device is removed and offers implementers the chance to run some code
    /// that cleans state up.
    fn device_remove(&self);
}

/// A kernel module that only registers the given driver on init.
///
/// This is a helper struct to make it easier to define single-functionality modules, in this case,
/// modules that offer a single driver.
pub struct Module<T: DriverOps> {
    _driver: Pin<Box<Registration<T>>>,
}

impl<T: DriverOps> KernelModule for Module<T> {
    fn init(name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        Ok(Self {
            _driver: Registration::new_pinned(name)?,
        })
    }
}

/// Declares a kernel module that exposes a single driver.
///
/// It is meant to be used as a helper by other subsystems so they can more easily expose their own
/// macros.
#[macro_export]
macro_rules! module_driver {
    (<$gen_type:ident>, $driver_ops:ty, { type: $type:ty, $($f:tt)* }) => {
        type Ops<$gen_type> = $driver_ops;
        type ModuleType = $crate::driver::Module<Ops<$type>>;
        $crate::prelude::module! {
            type: ModuleType,
            $($f)*
        }
    }
}
