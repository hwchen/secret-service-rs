//Copyright 2020 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A dbus proxy for speaking with secret service's `Session` Interface.

use zbus_macros::dbus_proxy;

/// A dbus proxy for speaking with secret service's `Session` Interface.
///
/// This will derive SessionProxy
///
/// Note that `Value` in the method signatures corresponds to `VARIANT` dbus type.
#[dbus_proxy(interface = "org.freedesktop.Secret.Session")]
trait Session {
    fn close(&self) -> zbus::Result<()>;
}
