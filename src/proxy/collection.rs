//Copyright 2022 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A dbus proxy for speaking with secret service's `Collection` Interface.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zbus::{
    dbus_proxy,
    zvariant::{ObjectPath, OwnedObjectPath, Type, Value},
};

use super::SecretStruct;

/// A dbus proxy for speaking with secret service's `Collection` Interface.
///
/// This will derive CollectionProxy
///
/// Note that `Value` in the method signatures corresponds to `VARIANT` dbus type.
#[dbus_proxy(
    interface = "org.freedesktop.Secret.Collection",
    default_service = "org.freedesktop.Secret.Collection"
)]
trait Collection {
    /// Returns prompt: ObjectPath
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;

    fn search_items(&self, attributes: HashMap<&str, &str>) -> zbus::Result<Vec<OwnedObjectPath>>;

    fn create_item(
        &self,
        properties: HashMap<&str, Value<'_>>,
        secret: SecretStruct,
        replace: bool,
    ) -> zbus::Result<CreateItemResult>;

    #[dbus_proxy(property)]
    fn items(&self) -> zbus::fdo::Result<Vec<ObjectPath<'_>>>;

    #[dbus_proxy(property)]
    fn label(&self) -> zbus::fdo::Result<String>;

    #[dbus_proxy(property)]
    fn set_label(&self, new_label: &str) -> zbus::fdo::Result<()>;

    #[dbus_proxy(property)]
    fn locked(&self) -> zbus::fdo::Result<bool>;

    #[dbus_proxy(property)]
    fn created(&self) -> zbus::fdo::Result<u64>;

    #[dbus_proxy(property)]
    fn modified(&self) -> zbus::fdo::Result<u64>;
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct CreateItemResult {
    pub(crate) item: OwnedObjectPath,
    pub(crate) prompt: OwnedObjectPath,
}
