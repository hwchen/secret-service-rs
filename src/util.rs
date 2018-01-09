//Copyright 2016 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// Contains helpers for:
//   exec_prompt
//   interfaces
//   formatting secrets
//
//   Consider: What else should be in here? Should
//   formatting secrets be in crypto? Should interfaces
//   have their own module?

use error::SsError;
use session::Session;
use ss::{
    SS_DBUS_NAME,
    SS_INTERFACE_PROMPT,
};
use ss_crypto::encrypt;

use dbus::{
    BusName,
    Connection,
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
use ring::rand::{SecureRandom, SystemRandom};
use std::rc::Rc;

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
                  args: Vec<MessageItem>) -> ::Result<Vec<MessageItem>> {
        // Should never fail, so unwrap
        let mut m = Message::new_method_call(
            self.name.clone(),
            self.path.clone(),
            self.interface.clone(),
            method_name)
            .unwrap();

        m.append_items(&args);

        // could use and_then?
        let r = try!(self.bus.send_with_reply_and_block(m, 2000));

        Ok(r.get_items())
    }

    pub fn get_props(&self, prop_name: &str) -> ::Result<MessageItem> {
        let p = Props::new(
            &self.bus,
            self.name.clone(),
            self.path.clone(),
            self.interface.clone(),
            2000
        );

        Ok(try!(p.get(prop_name)))
    }

    pub fn set_props(&self, prop_name: &str, value: MessageItem) -> ::Result<()> {
        let p = Props::new(
            &self.bus,
            self.name.clone(),
            self.path.clone(),
            self.interface.clone(),
            2000
        );

        Ok(try!(p.set(prop_name, value)))
    }
}

pub fn format_secret(session: &Session,
                     secret: &[u8],
                     content_type: &str
                    ) -> ::Result<MessageItem> {

    if session.is_encrypted() {
        let mut aes_iv = [0; 16];
        {
            let rng = SystemRandom::new();
            rng.fill(&mut aes_iv).unwrap();
        }
        let encrypted_secret = try!(encrypt(secret, &session.get_aes_key()[..], &aes_iv));

        // Construct secret struct
        // (These are all straight conversions, can't fail.
        let object_path = ObjectPath(session.object_path.clone());
        let parameters = MessageItem::from(&aes_iv[..]);
        // Construct an array, even if it's empty
        let value_dbus = MessageItem::from(&encrypted_secret[..]);
        let content_type = Str(content_type.to_owned());

        Ok(Struct(vec![
            object_path,
            parameters,
            value_dbus,
            content_type
        ]))

    } else {
        // just Plain for now
        let object_path = ObjectPath(session.object_path.clone());
        let parameters = Array(vec![], Byte(0u8).type_sig());
        let value_dbus = MessageItem::from(secret);
        let content_type = Str(content_type.to_owned());

        Ok(Struct(vec![
            object_path,
            parameters,
            value_dbus,
            content_type
        ]))
    }
}

pub fn exec_prompt(bus: Rc<Connection>, prompt: Path) -> ::Result<MessageItem> {
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
        if let Signal(message) =  event {
            //println!("Incoming Signal {:?}", message);
            let items = message.get_items();
            if let Some(&Bool(dismissed)) = items.get(0) {
                //println!("Was prompt dismissed? {:?}", dismissed);
                if dismissed {
                    return Err(SsError::Prompt);
                }
            }
            if let Some(&ref result) = items.get(1) {
                return Ok(result.clone());
            }
        }
    }
    Err(SsError::Prompt)
}

