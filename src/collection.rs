use std::rc::Rc;
use session::Session;
use ss;
use dbus::{Connection, Path};


#[derive(Debug, Clone)]
pub struct Collection<'a> {
    bus: Rc<Connection>,
    session: &'a Session,
    collection_path: Path,
}

impl<'a> Collection<'a> {
    pub fn new(bus: Rc<Connection>, session: &'a Session, collection_path: Path) -> Self {
        Collection {
            bus: bus,
            session: session,
            collection_path: collection_path,
        }
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
