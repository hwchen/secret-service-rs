use std::rc::Rc;

use session::Session;
use ss::{
    SS_DBUS_NAME,
    SS_INTERFACE_ITEM,
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
    Path,
};
use dbus::Interface as InterfaceName;

struct Item<'a> {
    bus: Rc<Connection>,
    session: &'a Session,
    item_path: Path,
    item_interface: Interface,
    //service_interface: Interface,
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
        Item {
            bus: bus,
            session: session,
            item_path: item_path,
            item_interface: item_interface,
        }
    }
}
