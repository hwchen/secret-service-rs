use std::rc::Rc;

use session::Session;
use ss::{
    SS_DBUS_NAME,
    SS_INTERFACE_COLLECTION,
    SS_INTERFACE_SERVICE,
    SS_PATH,
};
use util::{Interface, exec_prompt};

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
    ObjectPath,
    Str,
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
        println!("Locking paths: {:?}", res);
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

    pub fn get_all_items(&self) -> Result<Vec<MessageItem>, Error> {
        let items = try!(self.collection_interface.get_props("Items"));
        if let Array(item_array, _) = items {
            Ok(item_array)
        } else {
            Err(Error::new_custom("SSError", "Could not get items"))
        }
    }

    pub fn search_items() {
        unimplemented!();
    }

    pub fn get_label(&self) -> Result<String, Error> {
        let label = try!(self.collection_interface.get_props("Label"));
        if let Str(label_str) = label {
            Ok(label_str)
        } else {
            Err(Error::new_custom("SSError", "Could not get label"))
        }
    }

    pub fn set_label(&self) -> Result<String, Error> {
        // wait to finish create_collection to make it easier to test
        unimplemented!();
    }

    pub fn create_item(&self) {
        unimplemented!()
    }
}

#[cfg(test)]
mod test{
    use std::str;
    use super::*;
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
        let items = collection.get_all_items();
        println!("{:?}", items);
    }

    #[test]
    fn should_get_collection_label() {
        let ss = SecretService::new().unwrap();
        let collection = ss.get_default_collection().unwrap();
        let label = collection.get_label().unwrap();
        assert_eq!(label, "Login");
        println!("{:?}", label);
    }

}

