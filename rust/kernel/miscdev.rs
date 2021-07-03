// SPDX-License-Identifier: GPL-2.0

//! Miscellaneous devices.
//!
//! C header: [`include/linux/miscdevice.h`](../../../../include/linux/miscdevice.h)
//!
//! Reference: <https://www.kernel.org/doc/html/latest/driver-api/misc_devices.html>

use crate::bindings;
use crate::error::{Error, Result};
use crate::file_operations::{FileOpenAdapter, FileOperations, FileOperationsVtable};
use crate::{str::CStr, KernelModule, ThisModule};
use alloc::boxed::Box;
use core::marker::PhantomPinned;
use core::{mem::MaybeUninit, pin::Pin};

/// A registration of a miscellaneous device.
///
/// # Invariants
///
/// `Context` is always initialised when `registered` is `true`, and not initialised otherwise.
pub struct Registration<T: FileOperations> {
    registered: bool,
    mdev: bindings::miscdevice,
    _pin: PhantomPinned,

    /// Context initialised on construction and made available to all file instances on
    /// [`FileOperations::open`].
    open_data: MaybeUninit<T::OpenData>,
}

impl<T: FileOperations> Registration<T> {
    /// Creates a new [`Registration`] but does not register it yet.
    ///
    /// It is allowed to move.
    pub fn new() -> Self {
        // INVARIANT: `registered` is `false` and `open_data` is not initialised.
        Self {
            registered: false,
            mdev: bindings::miscdevice::default(),
            _pin: PhantomPinned,
            open_data: MaybeUninit::uninit(),
        }
    }

    /// Registers a miscellaneous device.
    ///
    /// Returns a pinned heap-allocated representation of the registration.
    pub fn new_pinned(
        name: &'static CStr,
        minor: Option<i32>,
        open_data: T::OpenData,
    ) -> Result<Pin<Box<Self>>> {
        let mut r = Pin::from(Box::try_new(Self::new())?);
        r.as_mut().register(name, minor, open_data)?;
        Ok(r)
    }

    /// Registers a miscellaneous device with the rest of the kernel.
    ///
    /// It must be pinned because the memory block that represents the registration is
    /// self-referential. If a minor is not given, the kernel allocates a new one if possible.
    pub fn register(
        self: Pin<&mut Self>,
        name: &'static CStr,
        minor: Option<i32>,
        open_data: T::OpenData,
    ) -> Result {
        // SAFETY: We must ensure that we never move out of `this`.
        let this = unsafe { self.get_unchecked_mut() };
        if this.registered {
            // Already registered.
            return Err(Error::EINVAL);
        }

        // SAFETY: The adapter is compatible with `misc_register`.
        this.mdev.fops = unsafe { FileOperationsVtable::<Self, T>::build() };
        this.mdev.name = name.as_char_ptr();
        this.mdev.minor = minor.unwrap_or(bindings::MISC_DYNAMIC_MINOR as i32);

        // We write to `open_data` here because as soon as `misc_register` succeeds, the file can be
        // opened, so we need `open_data` configured ahead of time.
        //
        // INVARIANT: `registered` is set to `true`, but `open_data` is also initialised.
        this.registered = true;
        this.open_data.write(open_data);

        let ret = unsafe { bindings::misc_register(&mut this.mdev) };
        if ret < 0 {
            // INVARIANT: `registered` is set back to `false` and the `open_data` is destructued.
            this.registered = false;
            // SAFETY: `open_data` was initialised a few lines above.
            unsafe { this.open_data.assume_init_drop() };
            return Err(Error::from_kernel_errno(ret));
        }

        Ok(())
    }
}

impl<T: FileOperations> Default for Registration<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: FileOperations> FileOpenAdapter<T::OpenData> for Registration<T> {
    unsafe fn convert(
        _inode: *mut bindings::inode,
        file: *mut bindings::file,
    ) -> *const T::OpenData {
        // SAFETY: the caller must guarantee that `file` is valid.
        let reg = crate::container_of!(unsafe { (*file).private_data }, Self, mdev);

        // SAFETY: This function is only called while the misc device is still registered, so the
        // registration must be valid. Additionally, the type invariants guarantee that while the
        // miscdev is registered, `open_data` is initialised.
        unsafe { (*reg).open_data.as_ptr() }
    }
}

// SAFETY: The only method is `register()`, which requires a (pinned) mutable `Registration`, so it
// is safe to pass `&Registration` to multiple threads because it offers no interior mutability.
unsafe impl<T: FileOperations> Sync for Registration<T> {}

// SAFETY: All functions work from any thread. So as long as the `Registration::open_data` is
// `Send`, so is `Registration<T>`.
unsafe impl<T: FileOperations> Send for Registration<T> where T::OpenData: Send {}

impl<T: FileOperations> Drop for Registration<T> {
    /// Removes the registration from the kernel if it has completed successfully before.
    fn drop(&mut self) {
        if self.registered {
            // SAFETY: `registered` being `true` indicates that a previous call to  `misc_register`
            // succeeded.
            unsafe { bindings::misc_deregister(&mut self.mdev) };

            // SAFETY: The type invariant guarantees that `open_data` is initialised when
            // `registered` is `true`.
            unsafe { self.open_data.assume_init_drop() };
        }
    }
}

/// Kernel module that exposes a single miscdev device implemented by `T`.
pub struct Module<T: FileOperations<OpenData = ()>> {
    _dev: Pin<Box<Registration<T>>>,
}

impl<T: FileOperations<OpenData = ()>> KernelModule for Module<T> {
    fn init(name: &'static CStr, _module: &'static ThisModule) -> Result<Self> {
        Ok(Self {
            _dev: Registration::new_pinned(name, None, ())?,
        })
    }
}

/// Declares a kernel module that exposes a single misc device.
///
/// The `type` argument should be a type which implements the [`FileOpener`] trait. Also accepts
/// various forms of kernel metadata.
///
/// C header: [`include/linux/moduleparam.h`](../../../include/linux/moduleparam.h)
///
/// [`FileOpener`]: ../kernel/file_operations/trait.FileOpener.html
///
/// # Examples
///
/// ```ignore
/// use kernel::prelude::*;
///
/// module_misc_device! {
///     type: MyFile,
///     name: b"my_miscdev_kernel_module",
///     author: b"Rust for Linux Contributors",
///     description: b"My very own misc device kernel module!",
///     license: b"GPL v2",
/// }
///
/// #[derive(Default)]
/// struct MyFile;
///
/// impl kernel::file_operations::FileOperations for MyFile {
///     kernel::declare_file_operations!();
/// }
/// ```
#[macro_export]
macro_rules! module_misc_device {
    (type: $type:ty, $($f:tt)*) => {
        type ModuleType = kernel::miscdev::Module<$type>;
        module! {
            type: ModuleType,
            $($f)*
        }
    }
}
