use std::rc::Rc;

use session::Session;
use ss::{
    SS_DBUS_NAME,
    SS_INTERFACE_ITEM,
    SS_INTERFACE_SERVICE,
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
use dbus::MessageItem::{
    Array,
    ObjectPath,
    Str,
};
use dbus::Interface as InterfaceName;

// Helper enum
enum LockAction {
    Lock,
    Unlock,
}

#[derive(Debug)]
pub struct Item<'a> {
    bus: Rc<Connection>,
    session: &'a Session,
    item_path: Path,
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
        let mut res = Vec::new();
        res.push((String::new(), String::new()));
        Ok(res)
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

    pub fn get_secret() -> Result<Vec<u8>, Error> {
        unimplemented!();
    }

    pub fn get_secret_content_type() -> Result<String, Error> {
        unimplemented!();
    }

    pub fn set_secret() -> Result<(), Error> {
        unimplemented!();
    }

    pub fn get_created() -> Result<usize, Error> {
        unimplemented!();
    }

    pub fn get_modified() -> Result<usize, Error> {
        unimplemented!();
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
        let ss = SecretService::new().unwrap();
        let collection = ss.get_default_collection().unwrap();
        let items_len_before = collection.get_all_items().unwrap().len();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain; charset=utf8" // content_type
        ).unwrap();
        println!("Created Item: {:?}", item);
        item.delete().unwrap();
        let items_len_after = collection.get_all_items().unwrap().len();
        assert!(items_len_before == items_len_after);
        //assert!(false);
    }

    #[test]
    fn should_check_if_item_locked() {
        let ss = SecretService::new().unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain; charset=utf8" // content_type
        ).unwrap();
        item.is_locked().unwrap();
        item.delete().unwrap();
    }

    #[test]
    #[ignore]
    fn should_lock_and_unlock() {
        let ss = SecretService::new().unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain; charset=utf8" // content_type
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
        let ss = SecretService::new().unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            Vec::new(),
            b"test",
            false, // replace
            "text/plain; charset=utf8" // content_type
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
    fn should_create_get_and_set_item_attributes() {
        let ss = SecretService::new().unwrap();
        let collection = ss.get_default_collection().unwrap();
        let item = collection.create_item(
            "Test",
            vec![("one", "one")],
            b"test",
            false, // replace
            "text/plain; charset=utf8" // content_type
        ).unwrap();
        let attributes = item.get_attributes().unwrap();
        println!("Attributes: {:?}", attributes);
        assert!(false);
    }
}

