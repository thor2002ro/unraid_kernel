// SPDX-License-Identifier: GPL-2.0

//! Rust platform device driver sample.

use kernel::{module_platform_driver, of, platform, prelude::*};

module_platform_driver! {
    type: Driver,
    name: b"rust_platform",
    license: b"GPL v2",
}

struct Driver;
impl platform::Driver for Driver {
    kernel::define_of_id_table! {(), [
        (of::DeviceId::Compatible(b"rust,sample"), None),
    ]}

    fn probe(_dev: &mut platform::Device, _id_info: Option<&Self::IdInfo>) -> Result {
        Ok(())
    }
}
