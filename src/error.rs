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

use std::error;
use std::fmt;
use zbus;

/// Result type often returned from methods that have SsError.
/// Fns in this library return ::Result<T> when using this alias.
// (This pattern is something I saw in hyper)
pub type Result<T> = ::std::result::Result<T, SsError>;

#[derive(Debug)]
pub enum SsError {
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

impl fmt::Display for SsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt:: Result {
        match *self {
            // crypto error does not implement Display
            SsError::Crypto(_) => write!(f, "Crypto error: Invalid Length or Padding"),
            SsError::Zbus(ref err) => write!(f, "zbus error: {}", err),
            SsError::ZbusMsg(ref err) => write!(f, "zbus message error: {}", err),
            SsError::ZbusFdo(ref err) => write!(f, "zbus fdo error: {}", err),
            SsError::Zvariant(ref err) => write!(f, "zbus fdo error: {}", err),
            SsError::Locked => write!(f, "SS Error: object locked"),
            SsError::NoResult => write!(f, "SS error: result not returned from SS API"),
            SsError::Parse => write!(f, "SS error: could not parse Dbus output"),
            SsError::Prompt => write!(f, "SS error: prompt dismissed"),
        }
    }
}

impl error::Error for SsError {
    fn description(&self) -> &str {
        match *self {
            SsError::Crypto(_) => "crypto: Invalid Length or Padding",
            SsError::Zbus(ref err) => err.description(),
            SsError::ZbusMsg(ref err) => err.description(),
            SsError::ZbusFdo(ref err) => err.description(),
            SsError::Zvariant(ref err) => err.description(),
            SsError::Locked => "Object locked",
            SsError::NoResult => "Result not returned from SS API",
            SsError::Parse => "Error parsing Dbus output",
            SsError::Prompt => "Prompt Dismissed",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            SsError::Zbus(ref err) => Some(err),
            SsError::ZbusMsg(ref err) => Some(err),
            SsError::ZbusFdo(ref err) => Some(err),
            SsError::Zvariant(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<block_modes::BlockModeError> for SsError {
    fn from(_err: block_modes::BlockModeError) -> SsError {
        SsError::Crypto("Block mode error".into())
    }
}

impl From<block_modes::InvalidKeyIvLength> for SsError {
    fn from(_err: block_modes::InvalidKeyIvLength) -> SsError {
        SsError::Crypto("Invalid Key Iv Lengt".into())
    }
}

impl From<zbus::Error> for SsError {
    fn from(err: zbus::Error) -> SsError {
        SsError::Zbus(err)
    }
}

impl From<zbus::fdo::Error> for SsError {
    fn from(err: zbus::fdo::Error) -> SsError {
        SsError::ZbusFdo(err)
    }
}

impl From<zvariant::Error> for SsError {
    fn from(err: zvariant::Error) -> SsError {
        SsError::Zvariant(err)
    }
}

impl From<zbus::MessageError> for SsError {
    fn from(err: zbus::MessageError) -> SsError {
        SsError::ZbusMsg(err)
    }
}
