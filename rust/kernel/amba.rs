// SPDX-License-Identifier: GPL-2.0

//! Amba devices drivers.
//!
//! C header: [`include/linux/amba/bus.h`](../../../../include/linux/amba/bus.h)

use crate::{
    bindings, c_types, device, driver, error::from_kernel_result, io_mem::Resource, power,
    str::CStr, to_result, types::PointerWrapper, Error, Result,
};
use core::{marker::PhantomData, ops::Deref};

/// A registration of an amba driver.
pub type Registration<T> = driver::Registration<Adapter<T>>;

/// Id of an Amba device.
pub struct DeviceId<T = ()> {
    /// Device id.
    pub id: u32,

    /// Mask that identifies which bits are valid in the device id.
    pub mask: u32,

    /// Context data to be associated with the device id. This is carried over to [`Driver::probe`]
    /// so that drivers can encode any information they may need then.
    pub data: T,
}

/// An amba driver.
pub trait Driver
where
    <Self::Data as Deref>::Target: driver::DeviceRemoval,
{
    /// Data stored on device by driver.
    type Data: PointerWrapper + Send + Sync + Deref;

    /// The type that implements the power-management operations.
    ///
    /// The default is a type that implements no power-management operations. Drivers that do
    /// implement them need to specify the type (commonly [`Self`]).
    type PowerOps: power::Operations<Data = Self::Data> = power::NoOperations<Self::Data>;

    /// The type holding information about each device id supported by the driver.
    type IdInfo: 'static = ();

    /// The table of device ids supported by the drivers.
    const ID_TABLE: &'static [DeviceId<Self::IdInfo>];

    /// Probes for the device with the given id.
    fn probe(dev: &mut Device, id: &DeviceId<Self::IdInfo>) -> Result<Self::Data>;

    /// Cleans any resources up that are associated with the device.
    ///
    /// This is called when the driver is detached from the device.
    fn remove(_data: &Self::Data) {}
}

/// An adapter for the registration of Amba drivers.
pub struct Adapter<T: Driver>(PhantomData<T>)
where
    <T::Data as Deref>::Target: driver::DeviceRemoval;

impl<T: Driver> driver::DriverOps for Adapter<T>
where
    <T::Data as Deref>::Target: driver::DeviceRemoval,
{
    type RegType = bindings::amba_driver;
    type RawIdType = bindings::amba_id;
    type IdType = DeviceId<T::IdInfo>;
    const ID_TABLE: &'static [Self::IdType] = T::ID_TABLE;

    unsafe fn register(
        reg: *mut bindings::amba_driver,
        name: &'static CStr,
        id_table: *const bindings::amba_id,
    ) -> Result {
        // SAFETY: By the safety requirements of this function (defined in the trait defintion),
        // `reg` is non-null and valid.
        let amba = unsafe { &mut *reg };
        amba.drv.name = name.as_char_ptr();
        amba.id_table = id_table;
        amba.probe = Some(probe_callback::<T>);
        amba.remove = Some(remove_callback::<T>);
        if cfg!(CONFIG_PM) {
            // SAFETY: `probe_callback` sets the driver data after calling `T::Data::into_pointer`,
            // and we guarantee that `T::Data` is the same as `T::PowerOps::Data` by a constraint
            // in the type declaration.
            amba.drv.pm = unsafe { power::OpsTable::<T::PowerOps>::build() };
        }
        // SAFETY: By the safety requirements of this function, `reg` is valid and fully
        // initialised.
        to_result(|| unsafe { bindings::amba_driver_register(reg) })
    }

    unsafe fn unregister(reg: *mut bindings::amba_driver) {
        // SAFETY: By the safety requirements of this function (defined in the trait definition),
        // `reg` was passed (and updated) by a previous successful call to `amba_driver_register`.
        unsafe { bindings::amba_driver_unregister(reg) };
    }

    fn to_raw_id(index: usize, id: &Self::IdType) -> Self::RawIdType {
        bindings::amba_id {
            id: id.id,
            mask: id.mask,
            data: index as _,
        }
    }
}

unsafe extern "C" fn probe_callback<T: Driver>(
    adev: *mut bindings::amba_device,
    aid: *const bindings::amba_id,
) -> c_types::c_int
where
    <T::Data as Deref>::Target: driver::DeviceRemoval,
{
    from_kernel_result! {
        // SAFETY: `adev` is valid by the contract with the C code. `dev` is alive only for the
        // duration of this call, so it is guaranteed to remain alive for the lifetime of `dev`.
        let mut dev = unsafe { Device::from_ptr(adev) };
        // SAFETY: `aid` is valid by the requirements the contract with the C code.
        let index = unsafe { (*aid).data } as usize;
        if index >= T::ID_TABLE.len() {
            return Err(Error::ENXIO);
        }
        let data = T::probe(&mut dev, &T::ID_TABLE[index])?;
        let ptr = T::Data::into_pointer(data);
        // SAFETY: `adev` is valid for write by the contract with the C code.
        unsafe { bindings::amba_set_drvdata(adev, ptr as _) };
        Ok(0)
    }
}

unsafe extern "C" fn remove_callback<T: Driver>(adev: *mut bindings::amba_device)
where
    <T::Data as Deref>::Target: driver::DeviceRemoval,
{
    // SAFETY: `adev` is valid by the contract with the C code.
    let ptr = unsafe { bindings::amba_get_drvdata(adev) };
    // SAFETY: The value returned by `amba_get_drvdata` was stored by a previous call to
    // `amba_set_drvdata` in `probe_callback` above; the value comes from a call to
    // `T::Data::into_pointer`.
    let data = unsafe { T::Data::from_pointer(ptr) };
    T::remove(&data);
    <<T::Data as Deref>::Target as driver::DeviceRemoval>::device_remove(data.deref());
}

/// An Amba device.
///
/// # Invariants
///
/// The field `ptr` is non-null and valid for the lifetime of the object.
pub struct Device {
    ptr: *mut bindings::amba_device,
    res: Option<Resource>,
}

impl Device {
    /// Creates a new device from the given pointer.
    ///
    /// # Safety
    ///
    /// `ptr` must be non-null and valid. It must remain valid for the lifetime of the returned
    /// instance.
    unsafe fn from_ptr(ptr: *mut bindings::amba_device) -> Self {
        // SAFETY: The safety requirements of the function ensure that `ptr` is valid.
        let dev = unsafe { &mut *ptr };
        // INVARIANT: The safety requirements of the function ensure the lifetime invariant.
        Self {
            ptr,
            res: Resource::new(dev.res.start, dev.res.end),
        }
    }

    /// Returns the io mem resource associated with the device, if there is one.
    ///
    /// Ownership of the resource is transferred to the caller, so subsequent calls to this
    /// function will return [`None`].
    pub fn take_resource(&mut self) -> Option<Resource> {
        self.res.take()
    }

    /// Returns the index-th irq associated with the device, if one exists.
    pub fn irq(&self, index: usize) -> Option<u32> {
        // SAFETY: By the type invariants, `self.ptr` is valid for read.
        let dev = unsafe { &*self.ptr };
        if index >= dev.irq.len() || dev.irq[index] == 0 {
            None
        } else {
            Some(dev.irq[index])
        }
    }
}

// SAFETY: The device returned by `raw_device` is the raw Amba device.
unsafe impl device::RawDevice for Device {
    fn raw_device(&self) -> *mut bindings::device {
        // SAFETY: By the type invariants, we know that `self.ptr` is non-null and valid.
        unsafe { &mut (*self.ptr).dev }
    }
}

/// Declares a kernel module that exposes a single amba driver.
///
/// # Examples
///
/// ```ignore
/// # use kernel::prelude::*;
/// # use kernel::{amba, declare_amba_id_table, module_amba_driver};
/// #
/// # struct State;
/// # impl kernel::driver::DeviceRemoval for State {
/// #   fn device_remove(&self) {}
/// # }
/// struct MyDriver;
/// impl amba::Driver for MyDriver {
///     // [...]
/// #   type Data = kernel::sync::Ref<State>;
/// #   fn probe(dev: &mut amba::Device, id: &amba::DeviceId<Self::IdInfo>) -> Result<Self::Data> {
/// #     todo!()
/// #   }
/// #   declare_amba_id_table! [
/// #       { id: 0x00041061, mask: 0x000fffff, data: () },
/// #   ];
/// }
///
/// module_amba_driver! {
///     type: MyDriver,
///     name: b"module_name",
///     author: b"Author name",
///     license: b"GPL v2",
/// }
/// ```
#[macro_export]
macro_rules! module_amba_driver {
    ($($f:tt)*) => {
        $crate::module_driver!(<T>, $crate::amba::Adapter<T>, { $($f)* });
    };
}

/// Declares the id table for amba devices.
///
/// # Examples
///
/// ```
/// # use kernel::prelude::*;
/// # use kernel::{amba, declare_amba_id_table};
/// #
/// # struct State;
/// # impl kernel::driver::DeviceRemoval for State {
/// #   fn device_remove(&self) {}
/// # }
/// # struct Sample;
/// # impl kernel::amba::Driver for Sample {
/// #   type Data = kernel::sync::Ref<State>;
/// #   fn probe(dev: &mut amba::Device, id: &amba::DeviceId<Self::IdInfo>) -> Result<Self::Data> {
/// #     todo!()
/// #   }
///     declare_amba_id_table! [
///         { id: 0x00041061, mask: 0x000fffff, data: () },
///     ];
/// # }
/// ```
#[macro_export]
macro_rules! declare_amba_id_table {
    ($({$($entry:tt)*},)*) => {
        const ID_TABLE: &'static [$crate::amba::DeviceId<Self::IdInfo>] = &[
            $( $crate::amba::DeviceId { $($entry)* },)*
        ];
    };

    // Cover case without a trailing comma.
    ($(($($entry:tt)*)),*) => {
        $crate::declare_amba_id_table!{ $({$($entry)*},)*}
    }
}
