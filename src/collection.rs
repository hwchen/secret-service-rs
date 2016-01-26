use std::rc::Rc;

use item::Item;
use session::Session;
use ss::{
    SS_DBUS_NAME,
    SS_INTERFACE_COLLECTION,
    SS_INTERFACE_SERVICE,
    SS_ITEM_LABEL,
    SS_ITEM_ATTRIBUTES,
    SS_PATH,
};
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
use dbus::Interface as InterfaceName;
use dbus::MessageItem::{
    Array,
    Bool,
    DictEntry,
    ObjectPath,
    Str,
    Variant,
};

// Helper enum
enum LockAction {
    Lock,
    Unlock,
}

#[derive(Debug, Clone)]
pub struct Collection<'a> {
    bus: Rc<Connection>,
    session: &'a Session,
    pub collection_path: Path,
    collection_interface: Interface,
    service_interface: Interface,
}

impl<'a> Collection<'a> {
    pub fn new(bus: Rc<Connection>, session: &'a Session, collection_path: Path) -> Self {
        let collection_interface = Interface::new(
            bus.clone(),
            BusName::new(SS_DBUS_NAME).unwrap(),
            collection_path.clone(),
            InterfaceName::new(SS_INTERFACE_COLLECTION).unwrap()
        );
        let service_interface = Interface::new(
            bus.clone(),
            BusName::new(SS_DBUS_NAME).unwrap(),
            Path::new(SS_PATH).unwrap(),
            InterfaceName::new(SS_INTERFACE_SERVICE).unwrap()
        );
        Collection {
            bus: bus,
            session: session,
            collection_path: collection_path,
            collection_interface: collection_interface,
            service_interface: service_interface,
        }
    }

    pub fn is_locked(&self) -> Result<bool, Error> {
        self.collection_interface.get_props("Locked")
            .map(|locked| {
                locked.inner().unwrap()
            })
    }

    pub fn ensure_unlocked(&self) -> Result<(), Error> {
        match try!(self.is_locked()) {
            false => Ok(()),
            true => Err(Error::new_custom("SSError", "Collection is locked")),
        }
    }

    //Helper function for locking and unlocking
    fn lock_or_unlock(&self, lock_action: LockAction) -> Result<(), Error> {
        let objects = MessageItem::new_array(
            vec![ObjectPath(self.collection_path.clone())]
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

    pub fn delete(&self) -> Result<(), Error> {
        //Because of ensure_unlocked, no prompt is really necessary
        //basically,you must explicitly unlock first
        try!(self.ensure_unlocked());
        let prompt = try!(self.collection_interface.method("Delete", vec![]));

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
        Err(Error::new_custom("SSError", "Could not delete Collection"))
    }

    pub fn get_all_items(&self) -> Result<Vec<Item>, Error> {
        let items = try!(self.collection_interface.get_props("Items"));
        if let Array(item_array, _) = items {
            Ok(item_array.iter().filter_map(|ref item| {
                match **item {
                    ObjectPath(ref path) => {
                        Some(Item::new(
                            self.bus.clone(),
                            self.session.clone(),
                            path.clone()
                        ))
                    },
                    _ => None,
                }
            }).collect::<Vec<_>>()
            )
        } else {
            Err(Error::new_custom("SSError", "Could not get items"))
        }
    }

    pub fn search_items(&self, attributes: Vec<(String, String)>) -> Result<Vec<Item>, Error> {
        let attr_as_dict_entries: Vec<_> = attributes
            .iter()
            .map(|&(ref key, ref value)| {
                DictEntry(
                    Box::new(Str((*key).to_owned())),
                    Box::new(Str((*value).to_owned()))
                )
            }).collect();
        let attr_type_sig = DictEntry(
            Box::new(Str("".to_owned())),
            Box::new(Str("".to_owned()))
        ).type_sig();
        let attr_dbus_dict = Array(
            attr_as_dict_entries,
            attr_type_sig
        );

        // Method call to SearchItem
        let items = try!(self.collection_interface.method("SearchItems", vec![attr_dbus_dict]));
        if let &Array(ref item_array, _) = items.get(0).unwrap() {
            Ok(item_array.iter().filter_map(|ref item| {
                match **item {
                    ObjectPath(ref path) => {
                        Some(Item::new(
                            self.bus.clone(),
                            self.session.clone(),
                            path.clone()
                        ))
                    },
                    _ => None,
                }
            }).collect::<Vec<_>>()
            )
        } else {
            Err(Error::new_custom("SSError", "Could not get items"))
        }
    }

    pub fn get_label(&self) -> Result<String, Error> {
        let label = try!(self.collection_interface.get_props("Label"));
        if let Str(label_str) = label {
            Ok(label_str)
        } else {
            Err(Error::new_custom("SSError", "Could not get label"))
        }
    }

    pub fn set_label(&self, new_label: &str) -> Result<(), Error> {
        self.collection_interface.set_props("Label", Str(new_label.to_owned()))
    }

    pub fn create_item(&self,
                       label: &str,
                       attributes:Vec<(&str, &str)>,
                       secret: &[u8],
                       replace: bool,
                       content_type: &str,
                       ) -> Result<Item, Error> {

        let secret_struct = format_secret(&self.session, secret, content_type);

        // build dbus dict

        // label
        let label_dbus = DictEntry(
            Box::new(Str(SS_ITEM_LABEL.to_owned())),
            Box::new(Variant(Box::new(Str(label.to_owned()))))
        );

        // initializing properties vector, preparing to push
        // attributes if available
        let mut properties = vec![label_dbus];

        // attributes dict
        if !attributes.is_empty() {
            let attributes_dbus: Vec<_> = attributes
                .iter()
                .map(|&(ref key, ref value)| {
                    DictEntry(
                        Box::new(Str((*key).to_owned())),
                        Box::new(Str((*value).to_owned()))
                    )
                }).collect();
            let attributes_dbus_dict = MessageItem::new_array(attributes_dbus).unwrap();
            let attributes_dict_entry = DictEntry(
                Box::new(Str(SS_ITEM_ATTRIBUTES.to_owned())),
                Box::new(Variant(Box::new(attributes_dbus_dict)))
            );
            properties.push(attributes_dict_entry);
        }

        // properties dict (label and attributes)
        let properties_dbus_dict = MessageItem::new_array(properties).unwrap();
        //TODO: remove this line: println!("{:?}", properties_dbus_dict);

        // Method call to CreateItem
        let res = try!(self.collection_interface.method("CreateItem", vec![
            properties_dbus_dict,
            secret_struct,
            Bool(replace)
        ]));

        // handle prompt if necessary
        // So far just cut and paste below, make sure to check
        if let Some(&ObjectPath(ref created_path)) = res.get(0) {
            if &**created_path == "/" {
                if let Some(&ObjectPath(ref path)) = res.get(1) {
                    let obj_path = try!(exec_prompt(self.bus.clone(), path.clone()));
                    println!("obj_path {:?}", obj_path);
                    // Have to use box syntax
                    if let Variant(box ObjectPath(ref path)) = obj_path {
                        return Ok(Item::new(
                            self.bus.clone(),
                            self.session.clone(),
                            path.clone()
                        ));
                    }
                }
            } else {
                // returning the first path.
                return Ok(Item::new(
                    self.bus.clone(),
                    self.session.clone(),
                    created_path.clone()
                ));
            }
        }
        // If for some reason the patterns don't match, return error
        Err(Error::new_custom("SSError", "Could not create Item"))
    }
}

#[cfg(test)]
mod test{
    use super::super::*;

    #[test]
    fn should_create_collection_struct() {
        let ss = SecretService::new().unwrap();
        let _ = ss.get_default_collection().unwrap();
        // tested under SecretService struct
    }

    #[test]
    fn should_check_if_collection_locked() {
        let ss = SecretService::new().unwrap();
        let collection = ss.get_default_collection().unwrap();
        let _ = collection.is_locked().unwrap();
    }

    #[test]
    #[ignore]
    fn should_lock_and_unlock() {
        let ss = SecretService::new().unwrap();
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
        let ss = SecretService::new().unwrap();
        let collections = ss.get_all_collections().unwrap();
        println!("collections before delete {:?}", collections);
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
        println!("collections after delete {:?}", collections);
        println!("# collections after delete {:?}", collections.len());
        assert!(false);
    }

    #[test]
    fn should_get_all_items() {
        let ss = SecretService::new().unwrap();
        let collection = ss.get_default_collection().unwrap();
        let items = collection.get_all_items().unwrap();
        println!("{:?}", items);
    }

    #[test]
    fn should_search_items() {
        let ss = SecretService::new().unwrap();
        let collection = ss.get_default_collection().unwrap();
        let items = collection.search_items(Vec::new()).unwrap();
        println!("{:?}", items);
        //assert!(false);
    }

    #[test]
    #[ignore]
    fn should_get_and_set_collection_label() {
        let ss = SecretService::new().unwrap();
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

