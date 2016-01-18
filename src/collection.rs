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
    collection_path: Path,
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
        println!("{:?}", res);
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
        self.lock_or_unlock(LockAction::Lock)
    }

    pub fn delete(&self) -> Result<(), Error> {
        try!(self.ensure_unlocked());
        try!(self.collection_interface.method("Delete", vec![]));
        Ok(())
    }
}

#[cfg(test)]
mod test{
    use super::*;
    use super::super::*;

    #[test]
    fn should_create_Collection() {
        let ss = SecretService::new().unwrap();
        let _ = ss.get_default_collection().unwrap();
        // tested under SecretService struct
    }

    #[test]
    fn should_check_if_collection_locked() {
        let ss = SecretService::new().unwrap();
        let collection = ss.get_default_collection().unwrap();
        let locked = collection.is_locked().unwrap();
    }

    #[test]
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
    fn should_delete_collection() {
        assert!(false);
    }
}
// for items
//        let collection_interface = Interface::new(
//            self.bus.clone(),
//            BusName::new(SS_DBUS_NAME).unwrap(),
//            Path::new(DEFAULT_COLLECTION).unwrap(),
//            InterfaceName::new(SS_INTERFACE_COLLECTION).unwrap()
//        );
//
//        let items = try!(collection_interface.get_props("Items"));
//        println!("{:?}", items);
