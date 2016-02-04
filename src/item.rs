use session::Session;
use ss::{
    SS_DBUS_NAME,
    SS_INTERFACE_ITEM,
    SS_INTERFACE_SERVICE,
    SS_PATH,
};
use ss_crypto::decrypt;
use util::{
    exec_prompt,
    format_secret,
    Interface,
};

use dbus::{
    BusName,
    Connection,
    Error,
    MessageItem,
    Path,
};
use dbus::MessageItem::{
    Array,
    ObjectPath,
    Str,
};
use dbus::Interface as InterfaceName;
use std::rc::Rc;

// Helper enum
enum LockAction {
    Lock,
    Unlock,
}

#[derive(Debug)]
pub struct Item<'a> {
    // TODO: Implement method for path?
    bus: Rc<Connection>,
    session: &'a Session,
    pub item_path: Path,
    item_interface: Interface,
    service_interface: Interface,
}

impl<'a> Item<'a> {
    pub fn new(bus: Rc<Connection>,
               session: &'a Session,
               item_path: Path
               ) -> Self {
        let item_interface = Interface::new(
            bus.clone(),
            BusName::new(SS_DBUS_NAME).unwrap(),
            item_path.clone(),
            InterfaceName::new(SS_INTERFACE_ITEM).unwrap()
        );
        let service_interface = Interface::new(
            bus.clone(),
            BusName::new(SS_DBUS_NAME).unwrap(),
            Path::new(SS_PATH).unwrap(),
            InterfaceName::new(SS_INTERFACE_SERVICE).unwrap()
        );
        Item {
            bus: bus,
            session: session,
            item_path: item_path,
            item_interface: item_interface,
            service_interface: service_interface,
        }
    }

    pub fn is_locked(&self) -> Result<bool, Error> {
        self.item_interface.get_props("Locked")
            .map(|locked| {
                locked.inner().unwrap()
            })
    }

    pub fn ensure_unlocked(&self) -> Result<(), Error> {
        match try!(self.is_locked()) {
            false => Ok(()),
            true => Err(Error::new_custom("SSError", "Item is locked")),
        }
    }

    //Helper function for locking and unlocking
    fn lock_or_unlock(&self, lock_action: LockAction) -> Result<(), Error> {
        let objects = MessageItem::new_array(
            vec![ObjectPath(self.item_path.clone())]
        ).unwrap();

        let lock_action_str = match lock_action {
            LockAction::Lock => "Lock",
            LockAction::Unlock => "Unlock",
        };

        let res = try!(self.service_interface.method(lock_action_str, vec![objects]));
        //println!("Locking or unlocking paths: {:?}", res);
        if let Some(&Array(ref unlocked, _)) = res.get(0) {
            if unlocked.len() == 0 {
                if let Some(&ObjectPath(ref path)) = res.get(1) {
                    try!(exec_prompt(self.bus.clone(), path.clone()));
                }
            }
        }
        Ok(())
    }

    pub fn unlock(&self) -> Result<(), Error> {
        self.lock_or_unlock(LockAction::Unlock)
    }

    pub fn lock(&self) -> Result<(), Error> {
        println!("locked!");
        self.lock_or_unlock(LockAction::Lock)
    }

    pub fn get_attributes(&self) -> Result<Vec<(String, String)>, Error> {
        let res = try!(self.item_interface.get_props("Attributes"));

        if let Array(attributes, _) = res {
            return Ok(attributes.iter().map(|ref dict_entry| {
                let entry: (&MessageItem, &MessageItem) = dict_entry.inner().unwrap();
                let key: &String = entry.0.inner().unwrap();
                let value: &String= entry.1.inner().unwrap();
                (key.clone(), value.clone())
            }).collect::<Vec<(String, String)>>())
        } else {
            Err(Error::new_custom("SSError", "Could not get attributes"))
        }
    }

    // Probably best example of creating dict
    pub fn set_attributes(&self, attributes: Vec<(&str, &str)>) -> Result<(), Error> {
        if !attributes.is_empty() {
            let attributes_dict_entries: Vec<_> = attributes.iter().map(|&(ref key, ref value)| {
                let dict_entry = (
                    MessageItem::from(*key),
                    MessageItem::from(*value)
                );
                MessageItem::from(dict_entry)
            }).collect();
            let attributes_dict = MessageItem::new_array(attributes_dict_entries).unwrap();
            self.item_interface.set_props("Attributes", attributes_dict)
        } else {
            Ok(())
        }
    }

    pub fn get_label(&self) -> Result<String, Error> {
        let label = try!(self.item_interface.get_props("Label"));
        if let Str(label_str) = label {
            Ok(label_str)
        } else {
            Err(Error::new_custom("SSError", "Could not get label"))
        }
    }

    pub fn set_label(&self, new_label: &str) -> Result<(), Error> {
        self.item_interface.set_props("Label", Str(new_label.to_owned()))
    }

    pub fn delete(&self) -> Result<(), Error> {
        //Because of ensure_unlocked, no prompt is really necessary
        //basically,you must explicitly unlock first
        try!(self.ensure_unlocked());
        let prompt = try!(self.item_interface.method("Delete", vec![]));

        if let Some(&ObjectPath(ref prompt_path)) = prompt.get(0) {
            if &**prompt_path != "/" {
                    let del_res = try!(exec_prompt(self.bus.clone(), prompt_path.clone()));
                    println!("{:?}", del_res);
                    return Ok(());
            } else {
                return Ok(());
            }
        }
        // If for some reason the patterns don't match, return error
        Err(Error::new_custom("SSError", "Could not delete Item"))
    }

    pub fn get_secret(&self) -> Result<Vec<u8>, Error> {
        let session = MessageItem::from(self.session.object_path.clone());
        let res = try!(self.item_interface.method("GetSecret", vec![session]));
        // No secret would be a bug, so try!
        let secret_struct = try!(res.get(0).ok_or(Error::new_custom("SSError", "No Secret Found")));

        // parse out secret

        // get "secret" field out of secret struct
        // secret should always be index 2
        let secret_vec: &Vec<_> = secret_struct.inner().unwrap();
        let secret_dbus = try!(secret_vec
            .get(2)
            .ok_or(Error::new_custom("SSError", "No Secret Found"))
        );

        // get array of dbus bytes
        let secret_bytes_dbus: &Vec<_> = secret_dbus.inner().unwrap();

        // map dbus bytes to u8
        let secret: Vec<_> = secret_bytes_dbus.iter().map(|byte| byte.inner::<u8>().unwrap()).collect();

        if !self.session.is_encrypted() {
            Ok(secret)
        } else {
            // get "param" (aes_iv) field out of secret struct
            // param should always be index 1
            let aes_iv_dbus = try!(secret_vec
                .get(1)
                .ok_or(Error::new_custom("SSError", "No Secret Found"))
            );
            // get array of dbus bytes
            let aes_iv_bytes_dbus: &Vec<_> = aes_iv_dbus.inner().unwrap();
            // map dbus bytes to u8
            let aes_iv: Vec<_> = aes_iv_bytes_dbus.iter().map(|byte| byte.inner::<u8>().unwrap()).collect();

            // decrypt
            let decrypted_secret = decrypt(&secret[..], &self.session.get_aes_key()[..], &aes_iv[..]).unwrap();
            Ok(decrypted_secret)
        }
    }

    pub fn get_secret_content_type(&self) -> Result<String, Error> {
        let session = MessageItem::from(self.session.object_path.clone());
        let res = try!(self.item_interface.method("GetSecret", vec![session]));
        // No secret content type would be a bug, so try!
        let secret_struct = try!(res.get(0).ok_or(Error::new_custom("SSError", "No Secret Found")));

        // parse out secret content type

        // get "content type" field out of secret struct
        // content type should always be index 3
        let secret_vec: &Vec<_> = secret_struct.inner().unwrap();
        let content_type_dbus = try!(secret_vec
            .get(3)
            .ok_or(Error::new_custom("SSError", "No Secret Found"))
        );

        // Get value out of DBus value
        let content_type: &String = content_type_dbus.inner().unwrap();

        Ok(content_type.clone())
    }

    pub fn set_secret(&self, secret: &[u8], content_type: &str) -> Result<(), Error> {
        let secret_struct = format_secret(&self.session, secret, content_type);
        self.item_interface.method("SetSecret", vec![secret_struct]).map(|_| ())
    }

    pub fn get_created(&self) -> Result<u64, Error> {
        self.item_interface.get_props("Created")
            .map(|locked| {
                locked.inner::<u64>().unwrap()
            })
    }

    pub fn get_modified(&self) -> Result<u64, Error> {
        self.item_interface.get_props("Modified")
            .map(|locked| {
                locked.inner::<u64>().unwrap()
            })
    }
}

impl<'a> Eq for Item<'a> {}
impl<'a> PartialEq for Item<'a> {
    fn eq(&self, other: &Item) -> bool {
        self.item_path == other.item_path &&
        self.get_attributes().unwrap() == other.get_attributes().unwrap()
    }
}

#[cfg(test)]
mod test{
    use session::EncryptionType;
    use super::super::*;

    #[test]
    fn should_create_and_delete_item() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain" // content_type
        ).unwrap();
        let _ = item.item_path.clone(); // to prepare for future drop for delete?
        item.delete().unwrap();
        // Random operation to prove that path no longer exists
        match item.get_label() {
            Ok(_) => panic!(),
            Err(_) => (),
        }
    }

    #[test]
    fn should_check_if_item_locked() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain" // content_type
        ).unwrap();
        item.is_locked().unwrap();
        item.delete().unwrap();
    }

    #[test]
    #[ignore]
    fn should_lock_and_unlock() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain" // content_type
        ).unwrap();
        let locked = item.is_locked().unwrap();
        if locked {
            item.unlock().unwrap();
            item.ensure_unlocked().unwrap();
            assert!(!item.is_locked().unwrap());
            item.lock().unwrap();
            assert!(item.is_locked().unwrap());
        } else {
            item.lock().unwrap();
            assert!(item.is_locked().unwrap());
            item.unlock().unwrap();
            item.ensure_unlocked().unwrap();
            assert!(!item.is_locked().unwrap());
        }
        item.delete().unwrap();
    }

    #[test]
    fn should_get_and_set_item_label() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain" // content_type
        ).unwrap();

        // Set label to test and check
        item.set_label("Tester").unwrap();
        let label = item.get_label().unwrap();
        assert_eq!(label, "Tester");
        println!("{:?}", label);
        item.delete().unwrap();
        //assert!(false);
    }

    #[test]
    fn should_create_with_item_attributes() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            vec![("test_attributes_in_item", "test")],
            b"test",
            false, // replace
            "text/plain" // content_type
        ).unwrap();
        let attributes = item.get_attributes().unwrap();
        assert_eq!(attributes, vec![("test_attributes_in_item".into(), "test".into())]);
        println!("Attributes: {:?}", attributes);
        item.delete().unwrap();
        //assert!(false);
    }

    #[test]
    fn should_get_and_set_item_attributes() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain" // content_type
        ).unwrap();
        // Also test empty array handling
        item.set_attributes(vec![]).unwrap();
        item.set_attributes(vec![("test_attributes_in_item_get", "test")]).unwrap();
        let attributes = item.get_attributes().unwrap();
        println!("Attributes: {:?}", attributes);
        assert_eq!(attributes, vec![("test_attributes_in_item_get".into(), "test".into())]);
        item.delete().unwrap();
        //assert!(false);
    }
    #[test]
    fn should_get_modified_created_props() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain" // content_type
        ).unwrap();
        item.set_label("Tester").unwrap();
        let created = item.get_created().unwrap();
        let modified = item.get_modified().unwrap();
        println!("Created {:?}, Modified {:?}", created, modified);
        item.delete().unwrap();
        //assert!(false);
    }

    #[test]
    fn should_create_and_get_secret() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain" // content_type
        ).unwrap();
        let secret = item.get_secret().unwrap();
        item.delete().unwrap();
        assert_eq!(secret, b"test");
    }

    #[test]
    fn should_get_secret_content_type() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain" // content_type, defaults to text/plain
        ).unwrap();
        let content_type = item.get_secret_content_type().unwrap();
        item.delete().unwrap();
        assert_eq!(content_type, "text/plain".to_owned());
    }

    #[test]
    fn should_set_secret() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain" // content_type
        ).unwrap();
        item.set_secret(b"new_test", "text/plain").unwrap();
        let secret = item.get_secret().unwrap();
        item.delete().unwrap();
        assert_eq!(secret, b"new_test");
    }

    #[test]
    fn should_create_encrypted_item() {
        let ss = SecretService::new(EncryptionType::Dh).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test_encrypted",
            false, // replace
            "text/plain" // content_type
        ).expect("Error on item creation");
        let secret = item.get_secret().unwrap();
        item.delete().unwrap();
        assert_eq!(secret, b"test_encrypted");
    }
}

