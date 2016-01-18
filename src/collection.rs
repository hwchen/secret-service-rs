
use session::Session;
use ss;
use dbus::{Connection, Path};


struct Collection<'a> {
    bus: &'a Connection,
    session: &'a Session,
    collection_path: Path,
}

impl<'a> Collection<'a> {
    pub fn new(bus: &'a Connection, session: &'a Session, collection_path: Path) -> Self {
        Collection {
            bus: bus,
            session: session,
            collection_path: collection_path,
        }
    }
}
