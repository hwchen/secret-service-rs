#![feature(box_patterns)]
#![allow(dead_code)]
// requires ldbus dev library
// on ubuntu, libdbus-1-dev
//
// check hyper and mio to see if passing bus connection
// is the best architecture, or if connection should be
// an attribute of secretservice, which should spawn
// new collections directly and pass a reference to the bus.
// (I like the second better, seems more consistent).
//
// Tried passing bus Connection using & and lifetimes, but Connection
// didn't live long enough if in two nested structs.
// Rc imposes some cost, is it ok? Or overkill? or inappropriate?

// TODO:
// Item struct and API
// Reorg imports, format function params to be consistent
// Then check that all functions return Collection or Item instead
// of Path or MessageItem
// Also change createItem to take label and attributes instad of props
// then Items/crypto
// Refactor Dict
// Refactor to make str and String function params consistent
// Redo tests now that full range of api is implemented
// Return using map when possible instead of matching
// Abstract prompts for creating items. Can I abstract other prompts?

extern crate crypto;
extern crate dbus;
extern crate rand;

pub mod collection;
pub mod error;
pub mod item;
mod util;
mod ss;
mod session;

use std::rc::Rc;

use collection::Collection;
use util::{Interface, exec_prompt};
use session::Session;
use ss::{
    SS_DBUS_NAME,
    SS_INTERFACE_SERVICE,
    SS_PATH,
};

use dbus::{
    BusName,
    BusType,
    Connection,
    Error,
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

// Secret Service Struct

#[derive(Debug)]
pub struct SecretService {
    bus: Rc<Connection>,
    session: Session,
    service_interface: Interface,
}

impl SecretService {
    pub fn new() -> Result<Self, dbus::Error> {
        let bus = Rc::new(try!(Connection::get_private(BusType::Session)));
        let session = try!(Session::new(&bus));
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

    pub fn get_all_collections(&self) -> Result<Vec<Collection>, Error> {
        let mut collections = Vec::new();
        if let Array(ref items, _) = try!(self.service_interface.get_props("Collections")) {
            for item in items {
                if let ObjectPath(ref path) = *item {
                    collections.push(Collection::new(
                        self.bus.clone(),
                        &self.session,
                        path.clone()
                    ));
                }
            }
        }
        Ok(collections)
    }

    pub fn get_collection_by_alias(&self, alias: &str) -> Result<Collection, Error>{
        let name = Str(alias.to_owned());

        let res = try!(self.service_interface.method("ReadAlias", vec![name]));
        if let ObjectPath(ref path) = res[0] {
            Ok(Collection::new(
                self.bus.clone(),
                &self.session,
                path.clone()
            ))
        } else {
            Err(Error::new_custom("SSError", "Didn't return an object path"))
        }

    }

    pub fn get_default_collection(&self) -> Result<Collection, Error> {
        self.get_collection_by_alias("default")
    }

    pub fn get_any_collection(&self) -> Result<Collection, Error> {
        // default first, then session, then first

        self.get_default_collection()
            .or_else(|_| {
                self.get_collection_by_alias("session")
            }).or_else(|_| {
                match try!(self.get_all_collections()).get(0) {
                    Some(collection) => Ok(collection.clone()),
                    _ => Err(Error::new_custom("SSError", "No collections found")),
                }
            })
    }

    // TODO: Eventually should return the collection
    // doesn't work?
    pub fn create_collection(&self, label: &str, alias: &str) -> Result<Path, Error> {
        println!("hit");
        let label = DictEntry(
            Box::new(Str("org.freedesktop.Secret.Collection.Label".to_owned())),
            Box::new(Variant(Box::new(Str(label.to_owned()))))
        );
        let label_type_sig = label.type_sig();
        let properties = Array(vec![label], label_type_sig);
        let alias = Str(alias.to_owned());

        let res = try!(self.service_interface.method("CreateCollection", vec![properties, alias]));
        println!("hit1");
        println!("{:?}", res);
        // check if prompt is needed
        if let Some(&ObjectPath(ref created_path)) = res.get(0) {
            if &**created_path == "/" {
                if let Some(&ObjectPath(ref path)) = res.get(1) {
                    let obj_path = try!(exec_prompt(self.bus.clone(), path.clone()));
                    println!("obj_path {:?}", obj_path);
                    // Have to use box syntax
                    if let Variant(box ObjectPath(ref path)) = obj_path {
                        return Ok(path.clone());
                    }
                }
            } else {
                // returning the first path.
                return Ok(created_path.clone());
            }
        }
        println!("hit4");
        // If for some reason the patterns don't match, return error
        Err(Error::new_custom("SSError", "Could not create Collection"))
    }

    pub fn search_items(&self) {
        unimplemented!();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn should_create_secret_service() {
        SecretService::new().unwrap();
    }

    #[test]
    fn should_get_all_collections() {
        // Assumes that there will always be a default
        // collection
        let ss = SecretService::new().unwrap();
        let collections = ss.get_all_collections().unwrap();
        assert!(collections.len() >= 1);
        println!("{:?}", collections);
        println!("# of collections {:?}", collections.len());
        //assert!(false);
    }

    #[test]
    fn should_get_collection_by_alias() {
        let ss = SecretService::new().unwrap();
        let _ = ss.get_collection_by_alias("session");
    }

    #[test]
    fn should_get_default_collection() {
        let ss = SecretService::new().unwrap();
        let _ = ss.get_default_collection();
    }

    #[test]
    fn should_get_any_collection() {
        let ss = SecretService::new().unwrap();
        let _ = ss.get_any_collection().unwrap();
    }

    #[test]
    #[ignore]
    fn should_create_collection() {
        assert!(false);
        let ss = SecretService::new().unwrap();
        // Shoul also return object path eventually
        let test_collection = ss.create_collection("Test", "").unwrap();
        println!("{:?}", test_collection);
    }

    #[test]
    fn should_search_all_items() {
        let ss = SecretService::new().unwrap();
        let _ = ss.search_items();
    }
}
