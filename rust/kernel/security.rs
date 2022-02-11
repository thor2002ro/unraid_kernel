// SPDX-License-Identifier: GPL-2.0

//! Linux Security Modules (LSM).
//!
//! C header: [`include/linux/security.h`](../../../../include/linux/security.h).

use crate::{bindings, cred::Credential, file::File, to_result, Result};

/// Calls the security modules to determine if the given task can become the manager of a binder
/// context.
pub fn binder_set_context_mgr(mgr: &Credential) -> Result {
    // SAFETY: By the `Credential` invariants, `mgr.ptr` is valid.
    to_result(|| unsafe { bindings::security_binder_set_context_mgr(mgr.ptr) })
}

/// Calls the security modules to determine if binder transactions are allowed from task `from` to
/// task `to`.
pub fn binder_transaction(from: &Credential, to: &Credential) -> Result {
    // SAFETY: By the `Credential` invariants, `from.ptr` and `to.ptr` are valid.
    to_result(|| unsafe { bindings::security_binder_transaction(from.ptr, to.ptr) })
}

/// Calls the security modules to determine if task `from` is allowed to send binder objects
/// (owned by itself or other processes) to task `to` through a binder transaction.
pub fn binder_transfer_binder(from: &Credential, to: &Credential) -> Result {
    // SAFETY: By the `Credential` invariants, `from.ptr` and `to.ptr` are valid.
    to_result(|| unsafe { bindings::security_binder_transfer_binder(from.ptr, to.ptr) })
}

/// Calls the security modules to determine if task `from` is allowed to send the given file to
/// task `to` (which would get its own file descriptor) through a binder transaction.
pub fn binder_transfer_file(from: &Credential, to: &Credential, file: &File) -> Result {
    // SAFETY: By the `Credential` invariants, `from.ptr` and `to.ptr` are valid. Similarly, by the
    // `File` invariants, `file.ptr` is also valid.
    to_result(|| unsafe { bindings::security_binder_transfer_file(from.ptr, to.ptr, file.ptr) })
}
