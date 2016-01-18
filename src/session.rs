// In pythons secretstorage, this is dhcrypto.py
//
// This module implements Secret Service Session,
// including crypto
//
// rand to get integer with 1024 random bits

//use crypto::digest::Digest;
//use crypto::sha2::Sha256;

use ss::{
    SS_DBUS_NAME,
    SS_PATH,
    SS_INTERFACE_SERVICE,
    ALGORITHM_PLAIN,
};

use dbus::{
    Connection,
    Message,
    Path,
    Error,
};
use dbus::MessageItem::{
    Variant,
    Str,
    ObjectPath,
};

#[derive(Debug)]
pub struct Session {
    object_path: Path,
    server_public_key: Option<Vec<u8>>,
    aes_key: Option<Vec<u8>>,
    encrypted: bool,
    my_private_key: Vec<u8>,
    my_public_key: Vec<u8>,
}

impl Session {
    pub fn new(bus: &Connection) -> Result<Self, Error> {
        // Forming message, should not fail unless bug
        // Currenty just doing plain
        let m = Message::new_method_call(
            SS_DBUS_NAME,
            SS_PATH,
            SS_INTERFACE_SERVICE,
            "OpenSession"
        ).unwrap()
        .append(Str(ALGORITHM_PLAIN.to_owned()))
        // this argument should be input for algorithm
        .append(Variant(Box::new(Str("".to_owned()))));

        let r = try!(bus.send_with_reply_and_block(m, 2000));

        let items = r.get_items();

        // check session output
        match items.get(0) {
            Some(o) if *o == Variant(Box::new(Str("".to_owned()))) => (),
            Some(_) => {
                return Err(Error::new_custom("SSError", "Error negotiating algorithm"));
            },
            _ => {
                return Err(Error::new_custom("SSError",  "Error: no output fromOpenSession"));
            },
        };

        let object_path = match items.get(1) {
            Some(&ObjectPath(ref path)) => path.clone(),
            _ => {
                return Err(Error::new_custom("SSError",  "Error: no output fromOpenSession"));
            },
        };

        Ok(Session {
            object_path: object_path,
            server_public_key: None,
            aes_key: None,
            encrypted: false,
            my_private_key: vec![],
            my_public_key: vec![],
        })
    }

//    pub fn set_server_public_key(&mut self, server_public_key: &[u8]) {
//        ()
//    }
//
//    pub fn set_object_path(&mut self, object_path: ObjectPath) {
//        self.object_path = object_path;
//    }
}

#[cfg(test)]
mod test {
    use super::*;
    use dbus::{Connection, BusType};

    #[test]
    fn should_create_plain_session() {
        let bus = Connection::get_private(BusType::Session).unwrap();
        Session::new(&bus).unwrap();
    }
}
