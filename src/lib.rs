//Copyright 2016 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// requires ldbus dev library
// on ubuntu, libdbus-1-dev

// TODO: refactoring
//
// map_err() for inner() instead of unwrap()
// return errors early.
// factor out handling mapping paths to Item
// Remove all matches for option and result!
// properly return path for delete actions?
// Move similar methods to common interface: locking, attributes, del, label?
// Reorg imports, format function params to be consistent
// Refactor to make str and String function params consistent
// Abstract prompts for creating items. Can I abstract other prompts? in all tests, make sure that check for structs
// Change all MessageItems initialization to use MessageItem::from()
// TODO: Could factor out some fns into utils: lock/unlock, more prompts.
// TODO: Util also contains format_secret, but this may be moved to ss_crypto.
//
//! # Secret Service libary
//!
//! This library implements a rust interface to the Secret Service API which is implemented
//! in Linux.
//!
//! ## About Secret Service API
//! http://standards.freedesktop.org/secret-service/
//!
//! Secret Service provides a secure place to store secrets.
//! Gnome keyring and KWallet implement the Secret Service API.
//!
//! ## Basic Usage
//! ```
//! extern crate secret_service;
//! use secret_service::SecretService;
//! use secret_service::EncryptionType;
//!
//! # fn main() {
//!
//! // initialize secret service (dbus connection and encryption session)
//! let ss = SecretService::new(EncryptionType::Dh).unwrap();
//!
//! // get default collection
//! let collection = ss.get_default_collection().unwrap();
//!
//! //create new item
//! collection.create_item(
//!     "test_label", // label
//!     vec![("test", "test_value")], // properties
//!     b"test_secret", //secret
//!     false, // replace item with same attributes
//!     "text/plain" // secret content type
//! ).unwrap();
//!
//! // search items by properties
//! let search_items = ss.search_items(
//!     vec![("test", "test_value")]
//! ).unwrap();
//!
//! let item = search_items.get(0).unwrap();
//!
//! // retrieve secret from item
//! let secret = item.get_secret().unwrap();
//! assert_eq!(secret, b"test_secret");
//!
//! // delete item (deletes the dbus object, not the struct instance)
//! item.delete().unwrap()
//! # }
//! ```
//!
//! ## Overview of this library:
//! ### Entry point
//! The entry point for this library is the `SecretService` struct. A new instance of
//! `SecretService` will initialize the dbus connection and negotiate an encryption session.
//!
//! ```
//! # use secret_service::SecretService;
//! # use secret_service::EncryptionType;
//! SecretService::new(EncryptionType::Plain).unwrap();
//! ```
//! or
//!
//! ```
//! # use secret_service::SecretService;
//! # use secret_service::EncryptionType;
//! SecretService::new(EncryptionType::Dh).unwrap();
//! ```
//!
//! EncryptionType::Dh requires the `gmp` feature to be enabled in Cargo.toml, which is the default.
//! This requires `libgmp` to be available.
//!
//! When the `gmp` feature is disabled by disabling the default features in Cargo.toml,
//! EncryptionType::Plain will be the only one available.
//!
//! Once the SecretService struct is initialized, it can be used to navigate to a collection.
//! Items can also be directly searched for without getting a collection first.
//!
//! ### Collections and Items
//! The Secret Service API organizes secrets into collections, and holds each secret
//! in an item.
//!
//! Items consist of a label, attributes, and the secret. The most common way to find
//! an item is a search by attributes.
//!
//! While it's possible to create new collections, most users will simply create items
//! within the default collection.
//!
//! ### Actions overview
//! The most common supported actions are `create`, `get`, `search`, and `delete` for
//! `Collections` and `Items`. For more specifics and exact method names, please see 
//! each struct's documentation.
//!
//! In addition, `set` and `get` actions are available for secrets contained in an `Item`.
//!
//! ### Errors
//! This library provides a custom `SsError`. `dbus` and `rust-crypto` crate errors
//! are converted into `SsError`s.
//!
//! Types of errors:
//!
//! - dbus
//! - crypto
//! - parsing dbus output
//! - no result, if dbus gives back result but doesn't contain expected parameter
//! - locked, if an object path is locked
//! - prompt dismissed, if action requires prompt but the prompt is dismissed
//!
//! ### Crypto
//! Specifics in SecretService API Draft Proposal:
//! http://standards.freedesktop.org/secret-service/
//!
//! In this library, the encryption negotiation and key exchange is carried
//! out in the `session` module, and encryption/decryption is done in the
//! `ss_crypto` module.
//
// The other modules: util, error, ss_crypto, ss, provide supporting functions.
//
// Util currently has interfaces (dbus method namespace) to make it easier to call methods.
// Util contains function to execute prompts (used in many collection and item methods, like
// delete)
//
// error is for custom SS errors.
// ss_crypto handles encryption and decryption (along with, to some extent, Session)
// ss provides some constants which are paths for dbus interaction, and some other strings.
//

extern crate aes;
extern crate block_modes;
extern crate dbus;
extern crate hkdf;
#[macro_use]
extern crate lazy_static;
extern crate num;
extern crate rand;
extern crate sha2;

mod collection;
mod error;
mod item;
mod session;
mod ss;
mod ss_crypto;
mod util;

pub use collection::Collection;
pub use error::{Result, SsError};
pub use item::Item;
use util::{Interface, exec_prompt};
use session::Session;
pub use session::EncryptionType;
use ss::{
    SS_DBUS_NAME,
    SS_INTERFACE_SERVICE,
    SS_PATH,
};

use dbus::{
    BusName,
    BusType,
    Connection,
    MessageItem,
    Path,
};
use dbus::Interface as InterfaceName;
use dbus::MessageItem::{
    Array,
    DictEntry,
    ObjectPath,
    Str,
    Variant,
};
use std::rc::Rc;

/// Secret Service Struct.
///
/// This the main entry point for usage of the library.
///
/// Creating a new SecretService will also initialize dbus
/// and negotiate a new cryptographic session
/// (`EncryptionType::Plain` or `EncryptionType::Dh`, when the `gmp` feature is enabled)
///
// Interfaces are the dbus namespace for methods
#[derive(Debug)]
pub struct SecretService {
    bus: Rc<Connection>,
    session: Session,
    service_interface: Interface,
}

impl SecretService {
    /// Create a new `SecretService` instance
    ///
    /// # Example
    /// 
    /// ```
    /// # use secret_service::SecretService;
    /// # use secret_service::EncryptionType;
    /// let ss = SecretService::new(EncryptionType::Dh).unwrap();
    /// ```
    pub fn new(encryption: EncryptionType) -> ::Result<Self> {
        Self::new_with_dbus_name(encryption, SS_DBUS_NAME)
    }

    /// Create a new `SecretService` instance with Dbus name
    ///
    /// # Example
    /// 
    /// ```
    /// # use secret_service::SecretService;
    /// # use secret_service::EncryptionType;
    /// let ss = SecretService::new_with_dbus_name(EncryptionType::Dh, "org.freedesktop.secrets").unwrap();
    /// ```
    pub fn new_with_dbus_name(encryption: EncryptionType, dbus_name: &str) -> ::Result<Self> {
        let bus = Rc::new(Connection::get_private(BusType::Session)?);
        let session = Session::new(bus.clone(), encryption)?;
        let service_interface = Interface::new(
            bus.clone(),
            BusName::new(dbus_name).unwrap(),
            Path::new(SS_PATH).unwrap(),
            InterfaceName::new(SS_INTERFACE_SERVICE).unwrap()
        );

        Ok(SecretService {
            bus: bus.clone(),
            session,
            service_interface,
        })
    }

    /// Get all collections
    pub fn get_all_collections(&self) -> ::Result<Vec<Collection>> {
        let res = self.service_interface.get_props("Collections")?;
        let collections: &Vec<_> = res.inner().unwrap();
        Ok(collections.iter().map(|object_path| {
            let path: &Path = object_path.inner().unwrap();
            Collection::new(
                self.bus.clone(),
                &self.session,
                path.clone()
            )
        }).collect::<Vec<_>>())
    }

    /// Get collection by alias.
    /// Most common would be the `default` alias, but there
    /// is also a specific method for getting the collection
    /// by default aliasl
    pub fn get_collection_by_alias(&self, alias: &str) -> ::Result<Collection>{
        let name = Str(alias.to_owned());

        let res = self.service_interface.method("ReadAlias", vec![name])?;
        if let ObjectPath(ref path) = res[0] {
            if &**path == "/" {
                Err(SsError::NoResult)
            } else {
                Ok(Collection::new(
                    self.bus.clone(),
                    &self.session,
                    path.clone()
                ))
            }
        } else {
            Err(SsError::Parse)
        }

    }

    /// Get default collection.
    /// (The collection whos alias is `default`)
    pub fn get_default_collection(&self) -> ::Result<Collection> {
        self.get_collection_by_alias("default")
    }

    /// Get any collection.
    /// First tries `default` collection, then `session`
    /// collection, then the first collection when it 
    /// gets all collections.
    pub fn get_any_collection(&self) -> ::Result<Collection> {
        // default first, then session, then first

        self.get_default_collection()
            .or_else(|_| {
                self.get_collection_by_alias("session")
            }).or_else(|_| {
                let collections = self.get_all_collections()?;
                collections
                    .get(0)
                    .ok_or(SsError::NoResult)
                    .map(|collection| collection.clone())
            })
    }

    /// Creates a new collection with a label and an alias.
    pub fn create_collection(&self, label: &str, alias: &str) -> ::Result<Collection> {
        // Set up dbus args
        let label = DictEntry(
            Box::new(Str("org.freedesktop.Secret.Collection.Label".to_owned())),
            Box::new(Variant(Box::new(Str(label.to_owned()))))
        );
        let label_type_sig = label.type_sig();
        let properties = Array(vec![label], label_type_sig);
        let alias = Str(alias.to_owned());

        // Call the dbus method
        let res = self.service_interface.method("CreateCollection", vec![properties, alias])?;

        // parse the result
        let collection_path: Path = {
            // Get path of created object
            let created_object_path = res
                .get(0)
                .ok_or(SsError::NoResult)?;
            let created_path: &Path = created_object_path.inner().unwrap();

            // Check if that path is "/", if so should execute a prompt
            if &**created_path == "/" {
                let prompt_object_path = res
                    .get(1)
                    .ok_or(SsError::NoResult)?;
                let prompt_path: &Path = prompt_object_path.inner().unwrap();

                // Exec prompt and parse result
                let var_obj_path = exec_prompt(self.bus.clone(), prompt_path.clone())?;
                let obj_path: &MessageItem = var_obj_path.inner().unwrap();
                let path: &Path = obj_path.inner().unwrap();
                path.clone()
            } else {
                // if not, just return created path
                created_path.clone()
            }
        };

        Ok(Collection::new(
            self.bus.clone(),
            &self.session,
            collection_path.clone()
        ))
    }

    /// Searches all items by attributes
    pub fn search_items(&self, attributes: Vec<(&str, &str)>) -> ::Result<Vec<Item>> {
        // Build dbus args
        let attr_dict_entries: Vec<_> = attributes.iter().map(|&(key, value)| {
            let dict_entry = (Str(key.to_owned()), Str(value.to_owned()));
            MessageItem::from(dict_entry)
        }).collect();
        let attr_type_sig = DictEntry(
            Box::new(Str("".to_owned())),
            Box::new(Str("".to_owned()))
        ).type_sig();
        let attr_dbus_dict = Array(
            attr_dict_entries,
            attr_type_sig
        );

        // Method call to SearchItem
        let res = self.service_interface.method("SearchItems", vec![attr_dbus_dict])?;

        // The result is unlocked and unlocked items.
        // Currently, I just concatenate and return all.
        let mut unlocked = match res.get(0) {
            Some(ref array) => {
                match **array {
                    Array(ref v, _) => v.clone(),
                    _ => Vec::new(),
                }
            }
            _ => Vec::new(),
        };
        let locked = match res.get(1) {
            Some(ref array) => {
                match **array {
                    Array(ref v, _) => v.clone(),
                    _ => Vec::new(),
                }
            }
            _ => Vec::new(),
        };
        unlocked.extend(locked);
        let items = unlocked;

        // Map the array of item pahts to array of Item
        Ok(items.iter().map(|item_path| {
            // extract path from objectPath
            let path: &Path = item_path.inner().unwrap();

            Item::new(
                self.bus.clone(),
                &self.session,
                path.clone()
            )
        }).collect::<Vec<_>>())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use dbus::Path;

    #[test]
    fn should_create_secret_service() {
        SecretService::new(EncryptionType::Plain).unwrap();
    }

    #[test]
    fn should_get_all_collections() {
        // Assumes that there will always be a default
        // collection
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collections = ss.get_all_collections().unwrap();
        assert!(collections.len() >= 1);
        println!("{:?}", collections);
        println!("# of collections {:?}", collections.len());
        //assert!(false);
    }

    #[test]
    fn should_get_collection_by_alias() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        ss.get_collection_by_alias("session").unwrap();
    }

    #[test]
    fn should_return_error_if_collection_doesnt_exist() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();

        match ss.get_collection_by_alias("definitely_defintely_does_not_exist") {
            Err(SsError::NoResult) => println!("worked"),
            _ => panic!(),
        }
    }

    #[test]
    fn should_get_default_collection() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        ss.get_default_collection().unwrap();
    }

    #[test]
    fn should_get_any_collection() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let _ = ss.get_any_collection().unwrap();
    }

    #[test]
    #[ignore]
    fn should_create_and_delete_collection() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let test_collection = ss.create_collection("Test", "").unwrap();
        println!("{:?}", test_collection);
        assert_eq!(
            test_collection.collection_path,
            Path::new("/org/freedesktop/secrets/collection/Test").unwrap()
        );
        test_collection.delete().unwrap();
    }

    #[test]
    fn should_search_items() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();

        // Create an item
        let item = collection.create_item(
            "test",
            vec![("test_attribute_in_ss", "test_value")],
            b"test_secret",
            false,
            "text/plain"
        ).unwrap();

        // handle empty vec search
        ss.search_items(Vec::new()).unwrap();

        // handle no result
        let bad_search = ss.search_items(vec![("test".into(), "test".into())]).unwrap();
        assert_eq!(bad_search.len(), 0);

        // handle correct search for item and compare
        let search_item = ss.search_items(
            vec![("test_attribute_in_ss", "test_value")]
        ).unwrap();

        assert_eq!(
            item.item_path,
            search_item[0].item_path
        );
        item.delete().unwrap();
    }
}
