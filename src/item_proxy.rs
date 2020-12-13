//Copyright 2020 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A dbus proxy for speaking with secret service's `Item` Interface.

use zbus_macros::dbus_proxy;

/// This will derive ItemInterfaceProxy
#[dbus_proxy(
    interface = "org.freedesktop.Secret.Item",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets",
)]
trait ItemInterface {
    fn get_attributes(&self) -> ::Result<Vec<(String, String)>> {
        let res = self.item_interface.get_props("Attributes")?;

        if let Array(attributes, _) = res {
            return Ok(attributes.iter().map(|ref dict_entry| {
                let entry: (&MessageItem, &MessageItem) = dict_entry.inner().unwrap();
                let key: &String = entry.0.inner().unwrap();
                let value: &String= entry.1.inner().unwrap();
                (key.clone(), value.clone())
            }).collect::<Vec<(String, String)>>())
        } else {
            Err(SsError::Parse)
        }
    }

    // Probably best example of creating dict
    fn set_attributes(&self, attributes: Vec<(&str, &str)>) -> ::Result<()> {
        if !attributes.is_empty() {
            let attributes_dict_entries: Vec<_> = attributes.iter().map(|&(ref key, ref value)| {
                let dict_entry = (
                    MessageItem::from(*key),
                    MessageItem::from(*value)
                );
                MessageItem::from(dict_entry)
            }).collect();
            let attributes_dict = MessageItem::new_array(attributes_dict_entries).unwrap();
            self.item_interface.set_props("Attributes", attributes_dict)
        } else {
            Ok(())
        }
    }

    fn get_label(&self) -> ::Result<String> {
        let label = self.item_interface.get_props("Label")?;
        if let Str(label_str) = label {
            Ok(label_str)
        } else {
            Err(SsError::Parse)
        }
    }

    fn set_label(&self, new_label: &str) -> ::Result<()> {
        self.item_interface.set_props("Label", Str(new_label.to_owned()))
    }

    /// Deletes dbus object, but struct instance still exists (current implementation)
    fn delete(&self) -> ::Result<()> {
        //Because of ensure_unlocked, no prompt is really necessary
        //basically,you must explicitly unlock first
        self.ensure_unlocked()?;
        let prompt = self.item_interface.method("Delete", vec![])?;

        if let Some(&ObjectPath(ref prompt_path)) = prompt.get(0) {
            if &**prompt_path != "/" {
                    let del_res = exec_prompt(self.bus.clone(), prompt_path.clone())?;
                    println!("{:?}", del_res);
                    return Ok(());
            } else {
                return Ok(());
            }
        }
        // If for some reason the patterns don't match, return error
        Err(SsError::Parse)
    }

    fn get_secret(&self) -> ::Result<Vec<u8>> {
        let session = MessageItem::from(self.session.object_path.clone());
        let res = self.item_interface.method("GetSecret", vec![session])?;
        // No secret would be an error, so try! instead of option
        let secret_struct = res
            .get(0)
            .ok_or(SsError::NoResult)?;

        // parse out secret

        // get "secret" field out of secret struct
        // secret should always be index 2
        let secret_vec: &Vec<_> = secret_struct.inner().unwrap();
        let secret_dbus = secret_vec
            .get(2)
            .ok_or(SsError::NoResult)?;

        // get array of dbus bytes
        let secret_bytes_dbus: &Vec<_> = secret_dbus.inner().unwrap();

        // map dbus bytes to u8
        let secret: Vec<_> = secret_bytes_dbus.iter().map(|byte| byte.inner::<u8>().unwrap()).collect();

        if !self.session.is_encrypted() {
            Ok(secret)
        } else {
            // get "param" (aes_iv) field out of secret struct
            // param should always be index 1
            let aes_iv_dbus = secret_vec
                .get(1)
                .ok_or(SsError::NoResult)?;
            // get array of dbus bytes
            let aes_iv_bytes_dbus: &Vec<_> = aes_iv_dbus.inner().unwrap();
            // map dbus bytes to u8
            let aes_iv: Vec<_> = aes_iv_bytes_dbus.iter().map(|byte| byte.inner::<u8>().unwrap()).collect();

            // decrypt
            let decrypted_secret = decrypt(&secret[..], &self.session.get_aes_key()[..], &aes_iv[..]).unwrap();
            Ok(decrypted_secret)
        }
    }

    fn get_secret_content_type(&self) -> ::Result<String> {
        let session = MessageItem::from(self.session.object_path.clone());
        let res = self.item_interface.method("GetSecret", vec![session])?;
        // No secret content type would be a bug, so try!
        let secret_struct = res
            .get(0)
            .ok_or(SsError::NoResult)?;

        // parse out secret content type

        // get "content type" field out of secret struct
        // content type should always be index 3
        let secret_vec: &Vec<_> = secret_struct.inner().unwrap();
        let content_type_dbus = secret_vec
            .get(3)
            .ok_or(SsError::NoResult)?;

        // Get value out of DBus value
        let content_type: &String = content_type_dbus.inner().unwrap();

        Ok(content_type.clone())
    }

    fn set_secret(&self, secret: &[u8], content_type: &str) -> ::Result<()> {
        let secret_struct = format_secret(&self.session, secret, content_type)?;
        self.item_interface.method("SetSecret", vec![secret_struct]).map(|_| ())
    }

    fn get_created(&self) -> ::Result<u64> {
        self.item_interface.get_props("Created")
            .map(|locked| {
                locked.inner::<u64>().unwrap()
            })
    }

    fn get_modified(&self) -> ::Result<u64> {
        self.item_interface.get_props("Modified")
            .map(|locked| {
                locked.inner::<u64>().unwrap()
            })
    }
}
