//Copyright 2016 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

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

use std::{error, fmt};

/// Result type often returned from methods that have Error.
/// Fns in this library return ::Result<T> when using this alias.
pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Crypto(String),
    Zbus(zbus::Error),
    ZbusMsg(zbus::MessageError),
    ZbusFdo(zbus::fdo::Error),
    Zvariant(zvariant::Error),
    Locked,
    NoResult,
    Parse,
    Prompt,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt:: Result {
        match *self {
            // crypto error does not implement Display
            Error::Crypto(_) => write!(f, "Crypto error: Invalid Length or Padding"),
            Error::Zbus(ref err) => write!(f, "zbus error: {}", err),
            Error::ZbusMsg(ref err) => write!(f, "zbus message error: {}", err),
            Error::ZbusFdo(ref err) => write!(f, "zbus fdo error: {}", err),
            Error::Zvariant(ref err) => write!(f, "zbus fdo error: {}", err),
            Error::Locked => write!(f, "SS Error: object locked"),
            Error::NoResult => write!(f, "SS error: result not returned from SS API"),
            Error::Parse => write!(f, "SS error: could not parse Dbus output"),
            Error::Prompt => write!(f, "SS error: prompt dismissed"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::Zbus(ref err) => Some(err),
            Error::ZbusMsg(ref err) => Some(err),
            Error::ZbusFdo(ref err) => Some(err),
            Error::Zvariant(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<block_modes::BlockModeError> for Error {
    fn from(_err: block_modes::BlockModeError) -> Error {
        Error::Crypto("Block mode error".into())
    }
}

impl From<block_modes::InvalidKeyIvLength> for Error {
    fn from(_err: block_modes::InvalidKeyIvLength) -> Error {
        Error::Crypto("Invalid Key Iv Lengt".into())
    }
}

impl From<zbus::Error> for Error {
    fn from(err: zbus::Error) -> Error {
        Error::Zbus(err)
    }
}

impl From<zbus::fdo::Error> for Error {
    fn from(err: zbus::fdo::Error) -> Error {
        Error::ZbusFdo(err)
    }
}

impl From<zvariant::Error> for Error {
    fn from(err: zvariant::Error) -> Error {
        Error::Zvariant(err)
    }
}

impl From<zbus::MessageError> for Error {
    fn from(err: zbus::MessageError) -> Error {
        Error::ZbusMsg(err)
    }
}
