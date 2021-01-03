//Copyright 2016 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use error::SsError;
use item::Item;
use proxy::collection::CollectionProxy;
use proxy::service::ServiceProxy;
use session::Session;
use ss::{
    SS_DBUS_NAME,
    SS_ITEM_LABEL,
    SS_ITEM_ATTRIBUTES,
};
use util::{
    exec_prompt,
    format_secret,
    lock_or_unlock,
    LockAction,
};

use std::collections::HashMap;
use std::convert::TryInto;
use zvariant::{Dict, ObjectPath, OwnedObjectPath, Value};

// Collection struct.
// Should always be created from the SecretService entry point,
// whether through a new collection or a collection search
pub struct Collection<'a> {
    conn: zbus::Connection,
    session: &'a Session,
    pub collection_path: OwnedObjectPath,
    collection_interface: CollectionProxy<'a>,
    service_interface: &'a ServiceProxy<'a>,
}

impl<'a> Collection<'a> {
    pub fn new(
        conn: zbus::Connection,
        session: &'a Session,
        service_interface: &'a ServiceProxy,
        collection_path: OwnedObjectPath,
        ) -> Self
    {
        let collection_interface = CollectionProxy::new_for_owned(
            conn.clone(),
            SS_DBUS_NAME.to_owned(),
            collection_path.to_string(),
            )
            .unwrap();
        Collection {
            conn: conn.clone(),
            session,
            collection_path,
            collection_interface,
            service_interface,
        }
    }

    pub fn is_locked(&self) -> ::Result<bool> {
        Ok(self.collection_interface.locked()?)
    }

    pub fn ensure_unlocked(&self) -> ::Result<()> {
        if self.is_locked()? {
            Err(SsError::Locked)
        } else {
            Ok(())
        }
    }

    pub fn unlock(&self) -> ::Result<()> {
        lock_or_unlock(
            self.conn.clone(),
            &self.service_interface,
            &self.collection_path,
            LockAction::Unlock,
        )
    }

    pub fn lock(&self) -> ::Result<()> {
        lock_or_unlock(
            self.conn.clone(),
            &self.service_interface,
            &self.collection_path,
            LockAction::Lock,
        )
    }

    /// Deletes dbus object, but struct instance still exists (current implementation)
    pub fn delete(&self) -> ::Result<()> {
        //Because of ensure_unlocked, no prompt is really necessary
        //basically,you must explicitly unlock first
        self.ensure_unlocked()?;
        let prompt_path = self.collection_interface.delete()?;

        if prompt_path.as_str() != "/" {
                exec_prompt(self.conn.clone(), &prompt_path)?;
        } else {
            return Ok(());
        }
        // If for some reason the patterns don't match, return error
        Err(SsError::Parse)
    }

    pub fn get_all_items(&self) -> ::Result<Vec<Item>> {
        let items = self.collection_interface.items()?;

        // map array of item paths to Item
        let res = items.into_iter()
            .map(|item_path| {
                Item::new(
                    self.conn.clone(),
                    &self.session,
                    &self.service_interface,
                    item_path.into(),
                )
            })
            .collect();

        Ok(res)
    }

    pub fn search_items(&self, attributes: Vec<(&str, &str)>) -> ::Result<Vec<Item>> {
        let items = self.collection_interface.search_items(attributes.into_iter().collect())?;

        // map array of item paths to Item
        let res = items.into_iter()
            .map(|item_path| {
                Item::new(
                    self.conn.clone(),
                    &self.session,
                    &self.service_interface,
                    item_path.into(),
                )
            })
            .collect();

        Ok(res)
    }

    pub fn get_label(&self) -> ::Result<String> {
        Ok(self.collection_interface.label()?)
    }

    pub fn set_label(&self, new_label: &str) -> ::Result<()> {
        Ok(self.collection_interface.set_label(new_label)?)
    }

    pub fn create_item(
        &self,
        label: &str,
        attributes:Vec<(&str, &str)>,
        secret: &[u8],
        replace: bool,
        content_type: &str,
        ) -> ::Result<Item>
    {
        let secret_struct = format_secret(&self.session, secret, content_type)?;

        let mut properties: HashMap<&str, Value> = HashMap::new();
        // TODO from Vec<(_,_)> directly to Dict?
        let attributes: HashMap<&str, &str> = attributes.into_iter().collect();
        let attributes: Dict = attributes.into();

        properties.insert(SS_ITEM_LABEL, label.into());
        properties.insert(SS_ITEM_ATTRIBUTES, attributes.into());

        let created_item = self.collection_interface.create_item(
            properties,
            secret_struct.inner,
            replace,
        )?;

        // This prompt handling is practically identical to create_collection
        let item_path: ObjectPath = {
            // Get path of created object
            let created_path = created_item.item;

            // Check if that path is "/", if so should execute a prompt
            if created_path.as_str() == "/" {
                let prompt_path = created_item.prompt;

                // Exec prompt and parse result
                let prompt_res = exec_prompt(self.conn.clone(), &prompt_path)?;
                prompt_res.try_into()?
            } else {
                // if not, just return created path
                created_path.into()
            }
        };

        Ok(Item::new(
            self.conn.clone(),
            &self.session,
            &self.service_interface,
            item_path.into(),
        ))
    }
}

#[cfg(test)]
mod test{
    use super::super::*;

    #[test]
    fn should_create_collection_struct() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let _ = ss.get_default_collection().unwrap();
        // tested under SecretService struct
    }

    #[test]
    fn should_check_if_collection_locked() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let _ = collection.is_locked().unwrap();
    }

    #[test]
    #[ignore] // should unignore this test this manually, otherwise will constantly prompt during tests.
    fn should_lock_and_unlock() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let locked = collection.is_locked().unwrap();
        if locked {
            collection.unlock().unwrap();
            collection.ensure_unlocked().unwrap();
            assert!(!collection.is_locked().unwrap());
            collection.lock().unwrap();
            assert!(collection.is_locked().unwrap());
        } else {
            collection.lock().unwrap();
            assert!(collection.is_locked().unwrap());
            collection.unlock().unwrap();
            collection.ensure_unlocked().unwrap();
            assert!(!collection.is_locked().unwrap());
        }
    }

    #[test]
    #[ignore]
    fn should_delete_collection() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collections = ss.get_all_collections().unwrap();
        //println!("collections before delete {:?}", collections);
        println!("# collections before delete {:?}", collections.len());
        for collection in collections {
            let collection_path = &*collection.collection_path;
            if collection_path.contains("Test") {
                println!("Contains Test: {:?}", collection_path);
                collection.unlock().unwrap();
                collection.delete().unwrap();
            }
        }
        //double check after
        let collections = ss.get_all_collections().unwrap();
        //println!("collections after delete {:?}", collections);
        println!("# collections after delete {:?}", collections.len());
        assert!(false);
    }

    #[test]
    fn should_get_all_items() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        collection.get_all_items().unwrap();
        //println!("{:?}", items);
    }

    #[test]
    fn should_search_items() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();

        // Create an item
        let item = collection.create_item(
            "test",
            vec![("test_attributes_in_collection", "test")],
            b"test_secret",
            false,
            "text/plain"
        ).unwrap();

        // handle empty vec search
        collection.search_items(Vec::new()).unwrap();

        // handle no result
        let bad_search = collection.search_items(vec![("test_bad".into(), "test".into())]).unwrap();
        assert_eq!(bad_search.len(), 0);

        // handle correct search for item and compare
        let search_item = collection.search_items(
            vec![("test_attributes_in_collection", "test")]
        ).unwrap();

        assert_eq!(
            item.item_path,
            search_item[0].item_path
        );
        item.delete().unwrap();
    }

    #[test]
    #[ignore]
    fn should_get_and_set_collection_label() {
        let ss = SecretService::new(EncryptionType::Plain).unwrap();
        let collection = ss.get_default_collection().unwrap();
        let label = collection.get_label().unwrap();
        assert_eq!(label, "Login");
        println!("{:?}", label);

        // Set label to test and check
        collection.unlock().unwrap();
        collection.set_label("Test").unwrap();
        let label = collection.get_label().unwrap();
        assert_eq!(label, "Test");
        println!("{:?}", label);

        // Reset label to original and test
        collection.unlock().unwrap();
        collection.set_label("Login").unwrap();
        let label = collection.get_label().unwrap();
        assert_eq!(label, "Login");
        println!("{:?}", label);

        collection.lock().unwrap();
        //assert!(false);
    }

    #[test]
    fn should_create_item() {
        ()
        // See item module
        // for creation of new item
    }

}

