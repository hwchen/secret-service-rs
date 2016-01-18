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
    bus: Connection,
    session: Session,
}

impl SecretService {
    pub fn new() -> Result<Self, dbus::Error> {
        let bus = try!(Connection::get_private(BusType::Session));
        let session = try!(Session::new(&bus));

        Ok(SecretService {
            bus: bus,
            session: session,
        })
    }

    pub fn read_all_collections(&self) {
        let props = Props::new(
            &self.bus,
            SS_DBUS_NAME,
            SS_PATH,
            SS_INTERFACE_SERVICE,
            2000
        );

        let items = props.get("Collections").unwrap();
        println!("{:?}", items);
    }

    // switch unwraps to try
    pub fn get_default_collection(&self) {
        let collection_interface = Interface::new(
            &self.bus,
            BusName::new(SS_DBUS_NAME).unwrap(),
            Path::new(DEFAULT_COLLECTION).unwrap(),
            InterfaceName::new(SS_INTERFACE_COLLECTION).unwrap()
        );

        let items = collection_interface.get_props("Items").unwrap();
        println!("{:?}", items);
    }

    pub fn get_session_collection(&self) {
        let collection_interface = Interface::new(
            &self.bus,
            BusName::new(SS_DBUS_NAME).unwrap(),
            Path::new(SESSION_COLLECTION).unwrap(),
            InterfaceName::new(SS_INTERFACE_COLLECTION).unwrap()
        );

        let items = collection_interface.get_props("Items").unwrap();
        println!("{:?}", items);
    }

    pub fn create_collection(&self, label: &str, alias: &str) {
        let label = DictEntry(
            Box::new(Str("org.freedesktop.Secret.Collection.Label".to_owned())),
            Box::new(Variant(Box::new(Str(label.to_owned()))))
        );
        let label_type_sig = label.type_sig();
        let properties = Array(vec![label], label_type_sig);
        let alias = Str(alias.to_owned());
        let service_interface = Interface::new(
            &self.bus,
            BusName::new(SS_DBUS_NAME).unwrap(),
            Path::new(SS_PATH).unwrap(),
            InterfaceName::new(SS_INTERFACE_SERVICE).unwrap()
        );

        let items = service_interface.method("CreateCollection", vec![properties, alias]);

        println!("{:?}", items);

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
    fn should_read_all_collections() {
        let ss = SecretService::new().unwrap();
        ss.read_all_collections();
    }


    #[test]
    fn should_get_default_collection() {
        let ss = SecretService::new().unwrap();
        ss.get_default_collection();
    }

    #[test]
    fn should_get_session_collection() {
        let ss = SecretService::new().unwrap();
        ss.get_session_collection();
        assert!(false);
    }

    #[test]
    fn should_create_default_collection() {
        let ss = SecretService::new().unwrap();
        ss.create_collection("Default", "default");
        assert!(false);
    }
}
