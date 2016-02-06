#![allow(dead_code)]
//Copyright 2016 lazy-static.rs Developers
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
// Abstract prompts for creating items. Can I abstract other prompts?
// in all tests, make sure that check for structs
// Change all MessageItems initialization to use MessageItem::from()
//
// ********************** Secret Service libary ************************
//
// This library implements a rust interface to the Secret Service API which is implemented
// in Linux.
//
// http://standards.freedesktop.org/secret-service/
//
// Secret Service provides a secure place to store secrets.
// Gnome keyring and KWallet implement the Secret Service API.
//
// Short roadmap of this library:
//
// SecretService struct is in this module, it's the entry point for the library.
// It initializes dbus and negotiates an encryption session.
// From SecretService struct, you can create and search for collections, and search
// for items. Each of those methods will return a Collection or Item struct, which
// you can use to perform similar actions (searching, creating, deleting, etc.)
//
// Searching can be done by attributes and labels. Some common attributes to set are
// Label, the callin app, etc.
//
// For the Item struct, there is the additional fact that you can set and get a secret
// value (in bytes).
//
// The other modules: util, error, ss_crypto, ss, provide supporting functions.
//
// Util currently has interfaces (dbus method namespace) to make it easier to call methods.
// Util contains function to execute prompts (used in many collection and item methods, like
// delete)
// TODO: Could factor out some fns into utils: lock/unlock, more prompts.
// TODO: Util also contains format_secret, but this may be moved to ss_crypto.
// error is for custom SS errors.
// ss_crypto handles encryption and decryption (along with, to some extent, Session)
// ss provides some constants which are paths for dbus interaction, and some other strings.
//
// High-level crypto notes in ss_crypto. Specifics in SecretService API Draft Proposal:
// http://standards.freedesktop.org/secret-service/

extern crate crypto;
extern crate dbus;
extern crate gmp;
extern crate num;
extern crate rand;

pub mod collection;
pub mod error;
pub mod item;
pub mod session;
mod ss;
mod ss_crypto;
mod util;

use collection::Collection;
use error::SsError;
use item::Item;
use util::{Interface, exec_prompt};
use session::Session;
use session::EncryptionType;
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

// Secret Service Struct
// This the main entry point for usage of the library.
// Creating a new SecretService will also initialize dbus
// and negotiate a new cryptographic session (plain or crypto)
//
// Interfaces are the dbus namespace for methods
#[derive(Debug)]
pub struct SecretService {
    bus: Rc<Connection>,
    session: Session,
    service_interface: Interface,
}

impl SecretService {
    pub fn new(encryption: EncryptionType) -> Result<Self, SsError> {
        let bus = Rc::new(try!(Connection::get_private(BusType::Session)));
        let session = try!(Session::new(bus.clone(), encryption));
        let service_interface = Interface::new(
            bus.clone(),
            BusName::new(SS_DBUS_NAME).unwrap(),
            Path::new(SS_PATH).unwrap(),
            InterfaceName::new(SS_INTERFACE_SERVICE).unwrap()
        );

        Ok(SecretService {
            bus: bus.clone(),
            session: session,
            service_interface: service_interface,
        })
    }

    pub fn get_all_collections(&self) -> Result<Vec<Collection>, SsError> {
        let res = try!(self.service_interface.get_props("Collections"));
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

    pub fn get_collection_by_alias(&self, alias: &str) -> Result<Collection, SsError>{
        let name = Str(alias.to_owned());

        let res = try!(self.service_interface.method("ReadAlias", vec![name]));
        if let ObjectPath(ref path) = res[0] {
            Ok(Collection::new(
                self.bus.clone(),
                &self.session,
                path.clone()
            ))
        } else {
            Err(SsError::Parse)
        }

    }

    pub fn get_default_collection(&self) -> Result<Collection, SsError> {
        self.get_collection_by_alias("default")
    }

    pub fn get_any_collection(&self) -> Result<Collection, SsError> {
        // default first, then session, then first

        self.get_default_collection()
            .or_else(|_| {
                self.get_collection_by_alias("session")
            }).or_else(|_| {
                let collections = try!(self.get_all_collections());
                collections
                    .get(0)
                    .ok_or(SsError::NoResult)
                    .map(|collection| collection.clone())
            })
    }

    pub fn create_collection(&self, label: &str, alias: &str) -> Result<Collection, SsError> {
        // Set up dbus args
        let label = DictEntry(
            Box::new(Str("org.freedesktop.Secret.Collection.Label".to_owned())),
            Box::new(Variant(Box::new(Str(label.to_owned()))))
        );
        let label_type_sig = label.type_sig();
        let properties = Array(vec![label], label_type_sig);
        let alias = Str(alias.to_owned());

        // Call the dbus method
        let res = try!(self.service_interface.method("CreateCollection", vec![properties, alias]));

        // parse the result
        let collection_path: Path = {
            // Get path of created object
            let created_object_path = try!(res
                .get(0)
                .ok_or(SsError::NoResult)
            );
            let created_path: &Path = created_object_path.inner().unwrap();

            // Check if that path is "/", if so should execute a prompt
            if &**created_path == "/" {
                let prompt_object_path = try!(res
                    .get(1)
                    .ok_or(SsError::NoResult)
                );
                let prompt_path: &Path = prompt_object_path.inner().unwrap();

                // Exec prompt and parse result
                let var_obj_path = try!(exec_prompt(self.bus.clone(), prompt_path.clone()));
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

    pub fn search_items(&self, attributes: Vec<(&str, &str)>) -> Result<Vec<Item>, SsError> {
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
        let res = try!(self.service_interface.method("SearchItems", vec![attr_dbus_dict]));

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
    use session::EncryptionType;
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
