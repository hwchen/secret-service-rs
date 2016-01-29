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
    MessageItem,
    Path,
    Error,
};
use dbus::MessageItem::{
    Variant,
    Str,
};
use std::rc::Rc;

// helper enum
#[derive(Debug, PartialEq)]
pub enum EncryptionType {
    Plain,
    Dh,
}

#[derive(Debug)]
pub struct Session {
    // TODO: Should session store encryption? As bool or EncryptionType? also getter/setter
    pub object_path: Path,
    server_public_key: Option<Vec<u8>>,
    aes_key: Option<Vec<u8>>,
    encrypted: bool,
    my_private_key: Vec<u8>,
    my_public_key: Vec<u8>,
}

impl Session {
    pub fn new(bus: Rc<Connection>, encryption: EncryptionType) -> Result<Self, Error> {
        // Forming message, should not fail unless bug
        let m = match encryption {
            EncryptionType::Plain => {
                Message::new_method_call(
                    SS_DBUS_NAME,
                    SS_PATH,
                    SS_INTERFACE_SERVICE,
                    "OpenSession"
                ).unwrap()
                .append(Str(ALGORITHM_PLAIN.to_owned()))
                // this argument should be input for algorithm
                .append(Variant(Box::new(Str("".to_owned()))))
            },
            EncryptionType::Dh => {
                // TODO: Change this to encrypted!
                Message::new_method_call(
                    SS_DBUS_NAME,
                    SS_PATH,
                    SS_INTERFACE_SERVICE,
                    "OpenSession"
                ).unwrap()
                .append(Str(ALGORITHM_PLAIN.to_owned()))
                // this argument should be input for algorithm
                .append(Variant(Box::new(Str("".to_owned()))))
            },
        };

        let r = try!(bus.send_with_reply_and_block(m, 2000));
        let items = r.get_items();

        // check session output
        // Should this always be a Variant String?
        let session_output_dbus = try!(items
            .get(0)
            .ok_or(Error::new_custom("SSError",  "Error: no output from OpenSession"))
        );
        let session_output_variant_dbus: &MessageItem = session_output_dbus.inner().unwrap();

        let session_output = if encryption == EncryptionType::Plain {
            // plain encryption negotiation should result in empty string
            match session_output_variant_dbus.inner::<&str>().unwrap() {
                "" => vec![],
                _ => return Err(Error::new_custom("SSError", "Error negotiating algorithm")),
            }
        } else {
            // If not plain, Variant should be a vector of bytes
            let session_output_array_dbus: &Vec<_> = session_output_variant_dbus
                .inner()
                .expect("SSError, Algorithm negotiation expected Array");

            session_output_array_dbus
                .iter()
                .map(|byte_dbus| byte_dbus.inner::<u8>().unwrap())
                .collect::<Vec<_>>()
        };

        println!("{:?}", session_output);

        // get session path
        let object_path_dbus = try!(items
            .get(1)
            .ok_or(Error::new_custom("SSError",  "Error: no output from OpenSession"))
        );
        let object_path: &Path = object_path_dbus.inner().unwrap();


        Ok(Session {
            object_path: object_path.clone(),
            server_public_key: None,
            aes_key: None,
            encrypted: false,
            my_private_key: vec![],
            my_public_key: vec![],
        })
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
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
    use std::rc::Rc;
    use super::*;
    use dbus::{Connection, BusType};

    #[test]
    fn should_create_plain_session() {
        let bus = Connection::get_private(BusType::Session).unwrap();
        let session = Session::new(Rc::new(bus), EncryptionType::Plain).unwrap();
        assert!(!session.is_encrypted());
    }

    #[test]
    fn should_create_encrypted_session() {
        let bus = Connection::get_private(BusType::Session).unwrap();
        let session = Session::new(Rc::new(bus), EncryptionType::Dh).unwrap();
        assert!(session.is_encrypted());
    }
}
