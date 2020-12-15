//Copyright 2020 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A dbus proxy for speaking with secret service's `Service` Interface.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use zbus;
use zbus_macros::dbus_proxy;
use zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zvariant_derive::Type;

use super::SecretStruct;

/// A dbus proxy for speaking with secret service's `Service` Interface.
///
/// This will derive ServiceInterfaceProxy
///
/// Note that `Value` in the method signatures corresponds to `VARIANT` dbus type.
#[dbus_proxy(
    interface = "org.freedesktop.Secret.Service",
)]
trait ServiceInterface {
    fn open_session(&self, algorithm: &str, input: Value) -> zbus::Result<OpenSessionResult>;

    fn create_collection(&self, properties: HashMap<String, Value>, alias: &str) -> zbus::Result<CreateCollectionResult>;

    fn search_items(&self, attributes: HashMap<String, String>) -> zbus::Result<SearchItemsResult>;

    fn unlock(&self, objects: Vec<ObjectPath>) -> zbus::Result<UnlockResult>;

    fn lock(&self, objects: Vec<ObjectPath>) -> zbus::Result<LockResult>;

    fn get_secrets(&self, objects: Vec<ObjectPath>) -> zbus::Result<HashMap<OwnedObjectPath, SecretStruct>>;

    /// Returns collection
    fn read_alias(&self, name: &str) -> zbus::Result<OwnedObjectPath>;

    fn set_alias(&self, name: &str, collection: ObjectPath) -> zbus::Result<()>;

    /// Returns collections
    // TODO Not sure why ObjectPath would be allowed but OwnedObjectPath would not be? Should Owned
    // be preferred here?
    #[dbus_proxy(property)]
    fn collections(&self) -> zbus::fdo::Result<Vec<ObjectPath>>;
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct OpenSessionResult {
    pub(crate) output: OwnedValue,
    pub(crate) result: OwnedObjectPath,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct CreateCollectionResult {
    pub(crate) collection: OwnedObjectPath,
    pub(crate) prompt: OwnedObjectPath,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct SearchItemsResult {
    pub(crate) unlocked: Vec<OwnedObjectPath>,
    pub(crate) locked: Vec<OwnedObjectPath>,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct UnlockResult {
    pub(crate) unlocked: Vec<OwnedObjectPath>,
    pub(crate) prompt: OwnedObjectPath,
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct LockResult {
    pub(crate) locked: Vec<OwnedObjectPath>,
    pub(crate) prompt: OwnedObjectPath,
}
