//Copyright 2020 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A dbus proxy for speaking with secret service's `Item` Interface.

use zbus;
use zbus_macros::dbus_proxy;
use zvariant::{Dict, ObjectPath};

/// This will derive ItemInterfaceProxy
#[dbus_proxy(
    interface = "org.freedesktop.Secret.Item",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets",
)]
trait ItemInterface {
    /// returns `Prompt` ObjectPath
    /// TODO check with zbus maintaineres if ObjectPath should be allowed as result
    fn delete(&self) -> zbus::Result<String>;

    /// returns `Secret`
    fn get_secret(&self, session: ObjectPath) -> zbus::Result<Vec<u8>>;

    fn set_secret(&self, secret: &[u8]) -> zbus::Result<()>;

    // Looks like the Dict has to be transformed into HashMap<String, String> in separate step?
    #[dbus_proxy(property)]
    fn attributes(&self) -> zbus::fdo::Result<Dict>;

    #[dbus_proxy(property)]
    fn set_attributes(&self, attributes: Dict) -> zbus::fdo::Result<()>;

    #[dbus_proxy(property)]
    fn label(&self) -> zbus::fdo::Result<String>;

    #[dbus_proxy(property)]
    fn set_label(&self, new_label: &str) -> zbus::fdo::Result<()>;

    #[dbus_proxy(property)]
    fn created(&self) -> zbus::fdo::Result<u64>;

    #[dbus_proxy(property)]
    fn modified(&self) -> zbus::fdo::Result<u64>;
}
