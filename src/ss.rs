//Copyright 2016 lazy-static.rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// Definitions for secret service interactions
// Similar to 'define.py' in secretstorage, except with error handling
// in separate error module

// DBus Name
pub const SS_DBUS_NAME: &'static str            = "org.freedesktop.secrets";

// DBus Object paths
pub const SS_PATH: &'static str            = "/org/freedesktop/secrets";
pub const DEFAULT_COLLECTION: &'static str = "/org/freedesktop/secrets/aliases/default";
pub const SESSION_COLLECTION: &'static str = "/org/freedesktop/secrets/collection/session";

// DBu Interfaces
pub const SS_INTERFACE_SERVICE: &'static str      = "org.freedesktop.Secret.Service";
pub const SS_INTERFACE_COLLECTION: &'static str   = "org.freedesktop.Secret.Collection";
pub const SS_INTERFACE_ITEM: &'static str         = "org.freedesktop.Secret.Item";
pub const SS_INTERFACE_SESSION: &'static str      = "org.freedesktop.Secret.Session";
pub const SS_INTERFACE_PROMPT: &'static str       = "org.freedesktop.Secret.Prompt";

// Item Properties
pub const SS_ITEM_LABEL: &'static str = "org.freedesktop.Secret.Item.Label";
pub const SS_ITEM_ATTRIBUTES: &'static str = "org.freedesktop.Secret.Item.Attributes";

// Algorithm Names
pub const ALGORITHM_PLAIN: &'static str = "plain";
pub const ALGORITHM_DH: &'static str    = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

