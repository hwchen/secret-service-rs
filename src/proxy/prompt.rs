//Copyright 2020 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A dbus proxy for speaking with secret service's `Prompt` Interface.

use serde::{Deserialize, Serialize};
use zbus;
use zbus_macros::dbus_proxy;
use zvariant::OwnedValue;
use zvariant_derive::Type;

/// A dbus proxy for speaking with secret service's `Prompt` Interface.
///
/// This will derive PromptInterfaceProxy
///
/// Note that `Value` in the method signatures corresponds to `VARIANT` dbus type.
#[dbus_proxy(
    interface = "org.freedesktop.Secret.Prompt",
)]
trait PromptInterface {
    fn prompt(&self, window_id: &str) -> zbus::Result<()>;

    fn dismiss(&self) -> zbus::Result<()>;
}

#[derive(Debug, Serialize, Deserialize, Type)]
pub struct CompletedSignal {
    pub(crate) dismissed: bool,
    pub(crate) result: OwnedValue,
}
