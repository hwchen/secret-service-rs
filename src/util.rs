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

use session::Session;
use ss::{
    SS_DBUS_NAME,
    SS_INTERFACE_PROMPT,
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
use dbus::ConnectionItem::Signal;
use dbus::Interface as InterfaceName;
use dbus::MessageItem::{
    Array,
    Bool,
    Byte,
    ObjectPath,
    Str,
    Struct,
};

#[derive(Debug, Clone)]
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

    pub fn get_props(&self, prop_name: &str) -> Result<MessageItem, Error> {
        let p = Props::new(
            &self.bus,
            self.name.clone(),
            self.path.clone(),
            self.interface.clone(),
            2000
        );

        p.get(prop_name)
    }

    pub fn set_props(&self, prop_name: &str, value: MessageItem) -> Result<(), Error> {
        let p = Props::new(
            &self.bus,
            self.name.clone(),
            self.path.clone(),
            self.interface.clone(),
            2000
        );

        p.set(prop_name, value)
    }
}

pub fn format_secret(session: &Session,
                     secret: &[u8],
                     content_type: &str
                    ) -> MessageItem {

    // just Plain for now
    let object_path = ObjectPath(session.object_path.clone());
    let parameters = Array(vec![], Byte(0u8).type_sig());
    let value_array: Vec<_> = secret.iter().map(|&byte| Byte(byte)).collect();
    let value_dbus = Array(value_array, Byte(0u8).type_sig());
    let content_type = Str(content_type.to_owned());

    Struct(vec![
        object_path,
        parameters,
        value_dbus,
        content_type
        ])
}

pub fn exec_prompt(bus: Rc<Connection>, prompt: Path) -> Result<MessageItem, Error> {
    let prompt_interface = Interface::new(
        bus.clone(),
        BusName::new(SS_DBUS_NAME).unwrap(),
        prompt,
        InterfaceName::new(SS_INTERFACE_PROMPT).unwrap()
    );
    try!(prompt_interface.method("Prompt", vec![Str("".to_owned())]));

    // check to see if prompt is dismissed or accepted
    // TODO: Find a better way to do this.
    // Also, should I return the paths in the result?
    for event in bus.iter(5000) {
        match event {
            Signal(message) => {
                //println!("Incoming Signal {:?}", message);
                let items = message.get_items();
                if let Some(&Bool(dismissed)) = items.get(0) {
                    //println!("Was prompt dismissed? {:?}", dismissed);
                    if dismissed {
                        return Err(Error::new_custom("SSError", "Prompt was dismissed"));
                    }
                }
                if let Some(&ref result) = items.get(1) {
                    return Ok(result.clone());
                }
            },
            _ => (),
        }
    }
    Err(Error::new_custom("SSError", "Prompt was dismissed"))
}

