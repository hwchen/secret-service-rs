//Copyright 2016 lazy-static.rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// key exchange and crypto for session:
// 1. Before session negotiation (openSession), set private key and public key using DH method.
// 2. In session negotiation, send public key.
// 3. As result of session negotiation, get object path for session, which (I think
//      it means that it uses the same server public key to create an aes key which is used
//      to decode the encoded secret using the aes seed that's sent with the secret).
// 4. As result of session negotition, get server public key.
// 5. Use server public key, my private key, to set an aes key using HKDF.
// 6. Format Secret: aes iv is random seed, in secret struct it's the parameter (Array(Byte))
// 7. Format Secret: encode the secret value for the value field in secret struct. 
//      This encoding uses the aes_key from the associated Session.

use ss::{
    SS_DBUS_NAME,
    SS_PATH,
    SS_INTERFACE_SERVICE,
    ALGORITHM_PLAIN,
    ALGORITHM_DH,
};

use crypto::sha2::Sha256;
use crypto::hkdf::{hkdf_extract, hkdf_expand};
use dbus::{
    Connection,
    Message,
    MessageItem,
    Path,
    Error,
};
use dbus::MessageItem::{
    Str,
    Variant,
};
use gmp::mpz::Mpz;
use num::bigint::BigUint;
use rand::{Rng, OsRng};
use std::rc::Rc;

// for key exchange
const DH_PRIME_1024_BYTES: [u8; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
];

#[derive(Debug, PartialEq)]
pub enum EncryptionType {
    Plain,
    Dh,
}

#[derive(Debug)]
pub struct Session {
    // TODO: Should session store encryption? As bool or EncryptionType? also getter/setter
    pub object_path: Path,
    encrypted: bool,
    server_public_key: Option<Vec<u8>>,
    aes_key: Option<Vec<u8>>,
    my_private_key: Option<Vec<u8>>,
    my_public_key: Option<Vec<u8>>,
}

// Think about how to break this function up? It's 134 lines.
// Could have a function for plain, and one for encrypted.
// Encryption could probably have a good chunk factored out.
// setting aes key could be put into ss_crypto
// Or factor out some common parts to helper functions?
impl Session {
    pub fn new(bus: Rc<Connection>, encryption: EncryptionType) -> Result<Self, Error> {
        match encryption {
            EncryptionType::Plain => {
                let m = Message::new_method_call(
                    SS_DBUS_NAME,
                    SS_PATH,
                    SS_INTERFACE_SERVICE,
                    "OpenSession"
                ).unwrap()
                .append(Str(ALGORITHM_PLAIN.to_owned()))
                // this argument should be input for algorithm
                .append(Variant(Box::new(Str("".to_owned()))));

                // Call to session
                let r = try!(bus.send_with_reply_and_block(m, 2000));
                let items = r.get_items();

                // Get session output
                let session_output_dbus = try!(items
                    .get(0)
                    .ok_or(Error::new_custom("SSError",  "Error: no output from OpenSession"))
                );
                let session_output_variant_dbus: &MessageItem = session_output_dbus.inner().unwrap();

                // check session output is str
                session_output_variant_dbus.inner::<&str>().unwrap();

                // get session path
                let object_path_dbus = try!(items
                    .get(1)
                    .ok_or(Error::new_custom("SSError", "Error: no output from OpenSession"))
                );
                let object_path: &Path = object_path_dbus.inner().unwrap();

                return Ok(Session {
                    object_path: object_path.clone(),
                    encrypted: false,
                    server_public_key: None,
                    aes_key: None,
                    my_private_key: None,
                    my_public_key: None,
                });
            },
            EncryptionType::Dh => {
                // crypto: create private and public key, send public key
                // requires some finagling to get pow() for bigints
                // mpz is multiple precision integer type for gmp
                let mut rng = OsRng::new().unwrap();
                let mut private_key_bytes = [0;128];
                rng.fill_bytes(&mut private_key_bytes);

                let private_key_mpz = bytes_to_mpz(&private_key_bytes).unwrap();
                let two: Mpz = From::<u32>::from(2);
                let dh_prime_mpz = bytes_to_mpz(&DH_PRIME_1024_BYTES).unwrap();
                let public_key_mpz = two.powm(&private_key_mpz, &dh_prime_mpz);

                let public_key_bytes = mpz_to_bytes(public_key_mpz);
                let public_key_bytes_dbus: Vec<_> = public_key_bytes
                    .iter()
                    .map(|&byte| { MessageItem::from(byte) })
                    .collect();

                // Method call to negotiate encrypted session
                let m = Message::new_method_call(
                    SS_DBUS_NAME,
                    SS_PATH,
                    SS_INTERFACE_SERVICE,
                    "OpenSession"
                ).unwrap()
                .append(Str(ALGORITHM_DH.to_owned()))
                .append(Variant(Box::new(MessageItem::new_array(public_key_bytes_dbus).unwrap())));

                // Call to session
                let r = try!(bus.send_with_reply_and_block(m, 2000));
                let items = r.get_items();

                // Get session output (which is the server public key when using encryption)
                let session_output_dbus = try!(items
                    .get(0)
                    .ok_or(Error::new_custom("SSError",  "Error: no output from OpenSession"))
                );
                let session_output_variant_dbus: &MessageItem = session_output_dbus.inner().unwrap();

                // Since encrypted Variant should be a vector of bytes
                let session_output_array_dbus: &Vec<_> = session_output_variant_dbus
                    .inner()
                    .expect("SSError, Algorithm negotiation expected Array");

                let server_public_key: Vec<_> = session_output_array_dbus
                    .iter()
                    .map(|byte_dbus| byte_dbus.inner::<u8>().unwrap())
                    .collect();

                // Set aes key from server key
                // TODO: Don't store keys except for aes?
                let server_public_key_mpz = bytes_to_mpz(&server_public_key[..]).unwrap();
                let common_secret_mpz = server_public_key_mpz.powm(&private_key_mpz, &dh_prime_mpz);
                let mut common_secret = mpz_to_bytes(common_secret_mpz);

                let mut common_secret_padded = vec![0; (128 - common_secret.len())];
                //inefficient, but ok for now
                common_secret_padded.append(&mut common_secret);

                let salt = [0u8;32]; // Why not just empty vector?

                let hasher = Sha256::new();
                let mut pseudorandom_key = [0;32];
                let mut output_block = [0;32];

                hkdf_extract(hasher, &salt, &common_secret_padded[..], &mut pseudorandom_key);
                hkdf_expand(hasher, &pseudorandom_key, &[], &mut output_block);

                let aes_key = output_block[0..16].to_vec();

                // get session path to store
                let object_path_dbus = try!(items
                    .get(1)
                    .ok_or(Error::new_custom("SSError",  "Error: no output from OpenSession"))
                );
                let object_path: &Path = object_path_dbus.inner().unwrap();

                return Ok(Session {
                    object_path: object_path.clone(),
                    encrypted: true,
                    server_public_key: Some(server_public_key),
                    aes_key: Some(aes_key),
                    my_private_key: Some(private_key_bytes.to_vec()),
                    my_public_key: Some(public_key_bytes.to_vec()),
                });
            },
        }

    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn get_aes_key(&self) -> Vec<u8> {
        self.aes_key.clone().unwrap()
    }
}

fn bytes_to_mpz(n: &[u8]) -> Result<Mpz, ()> {
    let bigint = BigUint::from_bytes_be(n);
    let bigint_str = bigint.to_str_radix(10);
    Mpz::from_str_radix(&bigint_str, 10)
}

fn mpz_to_bytes(mpz: Mpz) -> Vec<u8> {
    let bigint_str = mpz.to_str_radix(10);
    let bigint = bigint_str.parse::<BigUint>().unwrap(); //TODO: turn this into a try or option?
    bigint.to_bytes_be()
}

#[cfg(test)]
mod test {
    use std::rc::Rc;
    use super::*;
    use super::{bytes_to_mpz, mpz_to_bytes};
    use dbus::{Connection, BusType};

    #[test]
    fn should_create_plain_session() {
        let bus = Connection::get_private(BusType::Session).unwrap();
        let session = Session::new(Rc::new(bus), EncryptionType::Plain).unwrap();
        assert!(!session.is_encrypted());
    }

    #[test]
    fn should_create_encrypted_session() {
        let bus = Connection::get_private(BusType::Session).unwrap();
        let session = Session::new(Rc::new(bus), EncryptionType::Dh).unwrap();
        assert!(session.is_encrypted());
        println!("{:?}", session);
        //assert!(false);
    }

    #[test]
    fn should_convert_bytes_to_mpz() {
        assert_eq!(bytes_to_mpz(&[1u8, 1]).unwrap(), From::<u32>::from(257));
        assert_eq!(mpz_to_bytes(From::<u32>::from(257)), &[1u8, 1]);
    }
}
