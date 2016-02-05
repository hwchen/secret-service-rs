//Copyright 2016 lazy-static.rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// implement custom errors from DBus Error to Secret Service Error

// See Hyper

// DBus errors
const DBUS_UNKNOWN_METHOD: &'static str  = "org.freedesktop.DBus.Error.UnknownMethod";
const DBUS_ACCESS_DENIED: &'static str   = "org.freedesktop.DBus.Error.AccessDenied";
const DBUS_SERVICE_UNKNOWN: &'static str = "org.freedesktop.DBus.Error.ServiceUnknown";
const DBUS_EXEC_FAILED: &'static str     = "org.freedesktop.DBus.Error.Spawn.ExecFailed";
const DBUS_NO_REPLY: &'static str        = "org.freedesktop.DBus.Error.NoReply";
const DBUS_NOT_SUPPORTED: &'static str   = "org.freedesktop.DBus.Error.NotSupported";
const DBUS_NO_SUCH_OBJECT: &'static str  = "org.freedesktop.Secret.Error.NoSuchObject";
