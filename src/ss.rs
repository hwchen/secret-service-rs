//Copyright 2016 lazy-static.rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// Definitions for secret service interactions

// DBus Name
pub const SS_DBUS_NAME: &'static str = "org.freedesktop.secrets";

// Item Properties
pub const SS_ITEM_LABEL: &'static str = "org.freedesktop.Secret.Item.Label";
pub const SS_ITEM_ATTRIBUTES: &'static str = "org.freedesktop.Secret.Item.Attributes";

// Algorithm Names
pub const ALGORITHM_PLAIN: &'static str = "plain";
pub const ALGORITHM_DH: &'static str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

