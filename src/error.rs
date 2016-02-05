//Copyright 2016 lazy-static.rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// See Hyper for example?

// implement custom errors
//
// Classes of errors:
// - Dbus (IO, validation)
// - crypto
// - parsing dbus output (dbus returns unrecognizable output). Sometimes it's
//     for if the index exists in the results vector, sometimes it's for whether
//     the value being parsed at that index is the right type. Along these lines
//     I'm currently using unwrap() for converting types, should these also return
//     Result?
//
//     Almost all custom errors are of this type. It's mostly an internal error,
//     unexpected behavior indicates something very wrong, so should it panic? Or
//     is it still better to bubble up?
// - locked (currently custom dbus error)
// - prompt dismissed (not an error?) (currently custom dbus error)


// DBus errors (from secretstorage)
// Want to convert DBus errors to SecretService Error?
const DBUS_UNKNOWN_METHOD: &'static str  = "org.freedesktop.DBus.Error.UnknownMethod";
const DBUS_ACCESS_DENIED: &'static str   = "org.freedesktop.DBus.Error.AccessDenied";
const DBUS_SERVICE_UNKNOWN: &'static str = "org.freedesktop.DBus.Error.ServiceUnknown";
const DBUS_EXEC_FAILED: &'static str     = "org.freedesktop.DBus.Error.Spawn.ExecFailed";
const DBUS_NO_REPLY: &'static str        = "org.freedesktop.DBus.Error.NoReply";
const DBUS_NOT_SUPPORTED: &'static str   = "org.freedesktop.DBus.Error.NotSupported";
const DBUS_NO_SUCH_OBJECT: &'static str  = "org.freedesktop.Secret.Error.NoSuchObject";

