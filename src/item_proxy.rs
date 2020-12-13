//Copyright 2020 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A dbus proxy for speaking with secret service's `Item` Interface.

use serde::{Deserialize, Serialize};
use zbus;
use zbus_macros::dbus_proxy;
use zvariant::{Dict, ObjectPath, OwnedObjectPath};
use zvariant_derive::Type;

/// This will derive ItemInterfaceProxy
#[dbus_proxy(
    interface = "org.freedesktop.Secret.Item",
)]
trait ItemInterface {
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;

    /// returns `Secret`
    fn get_secret(&self, session: ObjectPath) -> zbus::Result<SecretStruct>;

    fn set_secret(&self, secret: SecretStruct) -> zbus::Result<()>;

    #[dbus_proxy(property)]
    fn locked(&self) -> zbus::fdo::Result<bool>;

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

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct SecretStruct {
    pub(crate) session: OwnedObjectPath,
    pub(crate) parameters: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) content_type: String,
}
