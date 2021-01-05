//Copyright 2016 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::error::{Error, Result};
use crate::proxy::item::ItemProxy;
use crate::proxy::service::ServiceProxy;
use crate::session::Session;
use crate::ss::SS_DBUS_NAME;
use crate::ss_crypto::decrypt;
use crate::util::{
    exec_prompt,
    format_secret,
    lock_or_unlock,
    LockAction,
};

use std::collections::HashMap;
use zvariant::OwnedObjectPath;

pub struct Item<'a> {
    conn: zbus::Connection,
    session: &'a Session,
    pub item_path: OwnedObjectPath,
    item_proxy: ItemProxy<'a>,
    service_proxy: &'a ServiceProxy<'a>,
}

impl<'a> Item<'a> {
    pub(crate) fn new(
        conn: zbus::Connection,
        session: &'a Session,
        service_proxy: &'a ServiceProxy<'a>,
        item_path: OwnedObjectPath,
        ) -> Result<Self>
    {
        let item_proxy = ItemProxy::new_for_owned(
            conn.clone(),
            SS_DBUS_NAME.to_owned(),
            item_path.to_string(),
            )?;
        Ok(Item {
            conn,
            session,
            item_path,
            item_proxy,
            service_proxy,
        })
    }

    pub fn is_locked(&self) -> Result<bool> {
        Ok(self.item_proxy.locked()?)
    }

    pub fn ensure_unlocked(&self) -> Result<()> {
        if self.is_locked()? {
            Err(Error::Locked)
        } else {
            Ok(())
        }
    }

    pub fn unlock(&self) -> Result<()> {
        lock_or_unlock(
            self.conn.clone(),
            &self.service_proxy,
            &self.item_path,
            LockAction::Unlock,
        )
    }

    pub fn lock(&self) -> Result<()> {
        lock_or_unlock(
            self.conn.clone(),
            &self.service_proxy,
            &self.item_path,
            LockAction::Lock,
        )
    }

    pub fn get_attributes(&self) -> Result<HashMap<String, String>> {
        Ok(self.item_proxy.attributes()?)
    }

    pub fn set_attributes(&self, attributes: HashMap<&str, &str>) -> Result<()> {
        Ok(self.item_proxy.set_attributes(attributes)?)
    }

    pub fn get_label(&self) -> Result<String> {
        Ok(self.item_proxy.label()?)
    }

    pub fn set_label(&self, new_label: &str) -> Result<()> {
        Ok(self.item_proxy.set_label(new_label)?)
    }

    /// Deletes dbus object, but struct instance still exists (current implementation)
    pub fn delete(&self) -> Result<()> {
        // ensure_unlocked handles prompt for unlocking if necessary
        self.ensure_unlocked()?;
        let prompt_path = self.item_proxy.delete()?;

        // "/" means no prompt necessary
        if prompt_path.as_str() != "/" {
            exec_prompt(self.conn.clone(), &prompt_path)?;
        }

        Ok(())
    }

    pub fn get_secret(&self) -> Result<Vec<u8>> {
        let secret_struct = self.item_proxy.get_secret(&self.session.object_path)?;
        let secret = secret_struct.value;

        if !self.session.is_encrypted() {
            Ok(secret)
        } else {
            // get "param" (aes_iv) field out of secret struct
            let aes_iv = secret_struct.parameters;

            // decrypt
            let decrypted_secret = decrypt(&secret[..], &self.session.get_aes_key()[..], &aes_iv[..]).unwrap();

            Ok(decrypted_secret)
        }
    }

    pub fn get_secret_content_type(&self) -> Result<String> {
        let secret_struct = self.item_proxy.get_secret(&self.session.object_path)?;
        let content_type = secret_struct.content_type;

        Ok(content_type)
    }

    pub fn set_secret(&self, secret: &[u8], content_type: &str) -> Result<()> {
        let secret_struct = format_secret(&self.session, secret, content_type)?;
        Ok(self.item_proxy.set_secret(secret_struct)?)
    }

    pub fn get_created(&self) -> Result<u64> {
        Ok(self.item_proxy.created()?)
    }

    pub fn get_modified(&self) -> Result<u64> {
        Ok(self.item_proxy.modified()?)
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
    use super::super::*;

    #[test]
    fn should_create_and_delete_item() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            HashMap::new(),
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
            HashMap::new(),
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
            HashMap::new(),
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
            HashMap::new(),
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
            vec![("test_attributes_in_item", "test")].into_iter().collect(),
            b"test",
            false, // replace
            "text/plain" // content_type
        ).unwrap();
        let attributes = item.get_attributes().unwrap();
        assert_eq!(attributes, vec![("test_attributes_in_item".into(), "test".into())].into_iter().collect());
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
            HashMap::new(),
            b"test",
            false, // replace
            "text/plain" // content_type
        ).unwrap();
        // Also test empty array handling
        item.set_attributes(HashMap::new()).unwrap();
        item.set_attributes(vec![("test_attributes_in_item_get", "test")].into_iter().collect()).unwrap();
        let attributes = item.get_attributes().unwrap();
        println!("Attributes: {:?}", attributes);
        assert_eq!(attributes, vec![("test_attributes_in_item_get".into(), "test".into())].into_iter().collect());
        item.delete().unwrap();
        //assert!(false);
    }
    #[test]
    fn should_get_modified_created_props() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            HashMap::new(),
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
            HashMap::new(),
            b"test",
            false, // replace
            "text/plain" // content_type
        ).unwrap();
        let secret = item.get_secret().unwrap();
        item.delete().unwrap();
        assert_eq!(secret, b"test");
    }

    #[test]
    fn should_create_and_get_secret_encrypted() {
        let ss = SecretService::new(EncryptionType::Dh).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            HashMap::new(),
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
            HashMap::new(),
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
            HashMap::new(),
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
            HashMap::new(),
            b"test_encrypted",
            false, // replace
            "text/plain" // content_type
        ).expect("Error on item creation");
        let secret = item.get_secret().unwrap();
        item.delete().unwrap();
        assert_eq!(secret, b"test_encrypted");
    }

    #[test]
    fn should_create_encrypted_item_from_empty_secret() {
        //empty string
        let ss = SecretService::new(EncryptionType::Dh).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            HashMap::new(),
            b"",
            false, // replace
            "text/plain" // content_type
        ).expect("Error on item creation");
        let secret = item.get_secret().unwrap();
        item.delete().unwrap();
        assert_eq!(secret, b"");
    }

    #[test]
    fn should_get_encrypted_secret_across_dbus_connections() {
        {
            let ss = SecretService::new(EncryptionType::Dh).unwrap();
            let collection = ss.get_default_collection().unwrap();
            let item = collection.create_item(
                "Test",
                vec![("test_attributes_in_item_encrypt", "test")].into_iter().collect(),
                b"test_encrypted",
                false, // replace
                "text/plain" // content_type
            ).expect("Error on item creation");
            let secret = item.get_secret().unwrap();
            assert_eq!(secret, b"test_encrypted");
        }
        {
            let ss = SecretService::new(EncryptionType::Dh).unwrap();
            let collection = ss.get_default_collection().unwrap();
            let search_item = collection.search_items(
                vec![("test_attributes_in_item_encrypt", "test")].into_iter().collect()
            ).unwrap();
            let item = search_item.get(0).unwrap().clone();
            assert_eq!(item.get_secret().unwrap(), b"test_encrypted");
            item.delete().unwrap();
        }
    }
}

