//Copyright 2016 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

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
//! use std::collections::HashMap;
//!
//! # fn main() {
//!
//! // initialize secret service (dbus connection and encryption session)
//! let ss = SecretService::new(EncryptionType::Dh).unwrap();
//!
//! // get default collection
//! let collection = ss.get_default_collection().unwrap();
//!
//! let mut properties = HashMap::new();
//! properties.insert("test", "test_value");
//!
//! //create new item
//! collection.create_item(
//!     "test_label", // label
//!     properties,
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
extern crate hkdf;
#[macro_use]
extern crate lazy_static;
extern crate num;
extern crate rand;
extern crate serde;
extern crate sha2;
extern crate zbus;
extern crate zbus_macros;
extern crate zvariant;
extern crate zvariant_derive;

mod collection;
mod error;
mod item;
mod proxy;
mod session;
mod ss;
mod ss_crypto;
mod util;

pub use collection::Collection;
pub use error::{Result, SsError};
pub use item::Item;
use proxy::service::ServiceProxy;
use util::exec_prompt;
use session::Session;
pub use session::EncryptionType;
use ss::SS_ITEM_LABEL;

use std::collections::HashMap;
use std::convert::TryInto;
use zvariant::{ObjectPath,Value};

/// Secret Service Struct.
///
/// This the main entry point for usage of the library.
///
/// Creating a new SecretService will also initialize dbus
/// and negotiate a new cryptographic session
/// (`EncryptionType::Plain` or `EncryptionType::Dh`)
///
pub struct SecretService<'a> {
    conn: zbus::Connection,
    session: Session,
    service_proxy: ServiceProxy<'a>,
}

impl<'a> SecretService<'a> {
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
        let conn = zbus::Connection::new_session()?;
        let service_proxy = ServiceProxy::new(&conn)?;
        let session = Session::new(&service_proxy, encryption)?;

        Ok(SecretService {
            conn,
            session,
            service_proxy,
        })
    }

    /// Get all collections
    pub fn get_all_collections(&self) -> ::Result<Vec<Collection>> {
        let collections = self.service_proxy.collections()?;
        Ok(collections.into_iter().map(|object_path| {
            Collection::new(
                self.conn.clone(),
                &self.session,
                &self.service_proxy,
                object_path.into(),
            )
        }).collect::<Result<Vec<_>>>()?)
    }

    /// Get collection by alias.
    /// Most common would be the `default` alias, but there
    /// is also a specific method for getting the collection
    /// by default aliasl
    pub fn get_collection_by_alias(&self, alias: &str) -> ::Result<Collection>{
        let object_path = self.service_proxy.read_alias(alias)?;

        if object_path.as_str() == "/" {
            Err(SsError::NoResult)
        } else {
            Ok(Collection::new(
                self.conn.clone(),
                &self.session,
                &self.service_proxy,
                object_path,
            )?)
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
                let mut collections = self.get_all_collections()?;
                if collections.is_empty() {
                    Err(SsError::NoResult)
                } else {
                    Ok(collections.swap_remove(0))
                }
            })
    }

    /// Creates a new collection with a label and an alias.
    pub fn create_collection(&self, label: &str, alias: &str) -> ::Result<Collection> {
        let mut properties: HashMap<&str, Value> = HashMap::new();
        properties.insert(SS_ITEM_LABEL, label.into());

        let created_collection = self.service_proxy.create_collection(
            properties,
            alias,
        )?;

        // This prompt handling is practically identical to create_collection
        let collection_path: ObjectPath = {
            // Get path of created object
            let created_path = created_collection.collection;

            // Check if that path is "/", if so should execute a prompt
            if created_path.as_str() == "/" {
                let prompt_path = created_collection.prompt;

                // Exec prompt and parse result
                let prompt_res = exec_prompt(self.conn.clone(), &prompt_path)?;
                prompt_res.try_into()?
            } else {
                // if not, just return created path
                created_path.into()
            }
        };

        Ok(Collection::new(
            self.conn.clone(),
            &self.session,
            &self.service_proxy,
            collection_path.into(),
        )?)
    }

    /// Searches all items by attributes
    pub fn search_items(&self, attributes: Vec<(&str, &str)>) -> ::Result<Vec<Item>> {
        let items = self.service_proxy.search_items(attributes.into_iter().collect())?;

        // map array of item paths to Item
        let res = items.locked.into_iter().chain(items.unlocked.into_iter())
            .map(|item_path| {
                Item::new(
                    self.conn.clone(),
                    &self.session,
                    &self.service_proxy,
                    item_path,
                )
            })
            .collect::<Result<_>>()?;

        Ok(res)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::convert::TryFrom;
    use zvariant::ObjectPath;

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
        //println!("{:?}", collections);
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
        //println!("{:?}", test_collection);
        assert_eq!(
            ObjectPath::from(test_collection.collection_path.clone()),
            ObjectPath::try_from("/org/freedesktop/secrets/collection/Test").unwrap()
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
            vec![("test_attribute_in_ss", "test_value")].into_iter().collect(),
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
