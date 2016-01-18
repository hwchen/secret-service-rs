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
// Plan is to implement all dbus and session basics first
// (definitions for ss, session, util, error)
// Then finally implement Colletion and Item on top

// Consider abstracting bus_get_object?
//
// Tried passing bus Connection using & and lifetimes, but Connection
// didn't live long enough if in two nested structs.
// Rc imposes some cost, is it ok? Or overkill? or inappropriate?

// Monday: Implement Collection struct
// add items
// And then crypto
// create_collection needs to implement prompt to work
extern crate crypto;
extern crate dbus;
extern crate rand;

mod collection;
mod util;
mod ss;
mod session;
pub mod error;

use std::rc::Rc;

use collection::Collection;
use util::Interface;
use session::Session;
use ss::{
    DEFAULT_COLLECTION,
    SESSION_COLLECTION,
    SS_DBUS_NAME,
    SS_INTERFACE_COLLECTION,
    SS_INTERFACE_SERVICE,
    SS_INTERFACE_PROMPT,
    SS_PATH,
};

use dbus::{
    BusName,
    BusType,
    Connection,
    Error,
    Message,
    Path,
    Props,
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

    pub fn create_collection(&self, label: &str, alias: &str) {
        unimplemented!();
        let label = DictEntry(
            Box::new(Str("org.freedesktop.Secret.Collection.Label".to_owned())),
            Box::new(Variant(Box::new(Str(label.to_owned()))))
        );
        let label_type_sig = label.type_sig();
        let properties = Array(vec![label], label_type_sig);
        let alias = Str(alias.to_owned());

        let res = self.service_interface.method("CreateCollection", vec![properties, alias]);

        println!("{:?}", res);
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
    }

    #[test]
    fn should_get_collection_by_alias() {
        let ss = SecretService::new().unwrap();
        let collection = ss.get_collection_by_alias("session");
    }

    #[test]
    fn should_get_default_collection() {
        let ss = SecretService::new().unwrap();
        let default = ss.get_default_collection();
    }

    #[test]
    fn should_get_any_collection() {
        let ss = SecretService::new().unwrap();
        let collection = ss.get_any_collection().unwrap();
        println!("{:?}", collection);
        assert!(false);
    }

    #[test]
    fn should_create_default_collection() {
        let ss = SecretService::new().unwrap();
        ss.create_collection("Default", "default");
    }
}
