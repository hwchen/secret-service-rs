// Will contain utils if necessary?
//
//
// open session (will be done in session.rs)
//
// format secret goes in its own struct
//
// exec_prompt, could belong here? 
//
// unlock_objects, more likely under SecretService
//
// to_unicode, don't need!

use std::rc::Rc;
use ss::{
    DEFAULT_COLLECTION,
    SESSION_COLLECTION,
    SS_DBUS_NAME,
    SS_INTERFACE_COLLECTION,
    SS_INTERFACE_ITEM,
    SS_INTERFACE_SERVICE,
    SS_INTERFACE_PROMPT,
    SS_PATH,
};


use dbus::{
    BusName,
    Connection,
    Error,
    Message,
    MessageItem,
    Path,
    Props,
};
use dbus::Interface as InterfaceName;

#[derive(Debug)]
pub struct Interface {
    bus: Rc<Connection>,
    name: BusName,
    path: Path,
    interface: InterfaceName,
}

impl Interface {
    pub fn new(bus: Rc<Connection>,
               name: BusName,
               path: Path,
               interface: InterfaceName) -> Self {

        Interface {
            bus: bus,
            name: name,
            path: path,
            interface: interface,
        }
    }

    pub fn method(&self,
                  method_name: &str,
                  args: Vec<MessageItem>) -> Result<Vec<MessageItem>, Error> {
        let mut m = Message::new_method_call(
            self.name.clone(),
            self.path.clone(),
            self.interface.clone(),
            method_name,
        ).unwrap();

        m.append_items(&args);

        // could use and_then?
        let r = try!(self.bus.send_with_reply_and_block(m, 2000));

        Ok(r.get_items())
    }

    pub fn get_props(&self, props: &str) -> Result<MessageItem, Error> {
        let p = Props::new(
            &self.bus,
            self.name.clone(),
            self.path.clone(),
            self.interface.clone(),
            2000
        );

        p.get(props)
    }
}

