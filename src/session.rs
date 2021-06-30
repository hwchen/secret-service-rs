//Copyright 2016 secret-service-rs Developers
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

use crate::error::Result;
use crate::proxy::service::ServiceProxyBlocking;
use crate::ss::{ALGORITHM_DH, ALGORITHM_PLAIN};

use hkdf::Hkdf;
use lazy_static::lazy_static;
use num::{
    bigint::BigUint,
    integer::Integer,
    traits::{One, Zero},
    FromPrimitive,
};
use rand::{rngs::OsRng, Rng};
use sha2::Sha256;
use std::convert::TryInto;
use zvariant::OwnedObjectPath;

use std::ops::{Mul, Rem, Shr};

// for key exchange
lazy_static! {
    pub static ref DH_GENERATOR: BigUint = BigUint::from_u64(0x2).unwrap();
    pub static ref DH_PRIME: BigUint = BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2,
        0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67,
        0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E,
        0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5,
        0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF,
        0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE,
        0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ]);
}

#[derive(Debug, PartialEq)]
pub enum EncryptionType {
    Plain,
    Dh,
}

#[derive(Debug)]
pub struct Session {
    pub object_path: OwnedObjectPath,
    encrypted: bool,
    #[allow(dead_code)]
    server_public_key: Option<Vec<u8>>,
    aes_key: Option<Vec<u8>>,
    #[allow(dead_code)]
    my_private_key: Option<Vec<u8>>,
    #[allow(dead_code)]
    my_public_key: Option<Vec<u8>>,
}

impl Session {
    pub fn new(service_proxy: &ServiceProxyBlocking, encryption: EncryptionType) -> Result<Self> {
        match encryption {
            EncryptionType::Plain => {
                let session = service_proxy.open_session(ALGORITHM_PLAIN, "".into())?;
                let session_path = session.result;

                Ok(Session {
                    object_path: session_path,
                    encrypted: false,
                    server_public_key: None,
                    aes_key: None,
                    my_private_key: None,
                    my_public_key: None,
                })
            }
            EncryptionType::Dh => {
                // crypto: create private and public key, send public key
                // requires some finagling to get pow() for bigints
                let mut rng = OsRng {};
                let mut private_key_bytes = [0; 128];
                rng.fill(&mut private_key_bytes);

                let private_key = BigUint::from_bytes_be(&private_key_bytes);
                let public_key = powm(&DH_GENERATOR, &private_key, &DH_PRIME);

                let public_key_bytes = public_key.to_bytes_be();

                let session =
                    service_proxy.open_session(ALGORITHM_DH, public_key_bytes.as_slice().into())?;
                let server_public_key: Vec<_> = session.output.try_into()?;
                let session_path = session.result;

                // Set aes key from server key
                let server_public_key = BigUint::from_bytes_be(&server_public_key);
                let server_public_key_bytes = server_public_key.to_bytes_be();
                let common_secret = powm(&server_public_key, &private_key, &DH_PRIME);

                let mut common_secret_bytes = common_secret.to_bytes_be();
                let mut common_secret_padded = vec![0; 128 - common_secret_bytes.len()];
                //inefficient, but ok for now
                common_secret_padded.append(&mut common_secret_bytes);

                // hkdf

                // input_keying_material
                let ikm = common_secret_padded;
                let salt = None;
                let info = [];

                // output keying material
                let mut okm = [0; 16];

                let (_, hk) = Hkdf::<Sha256>::extract(salt, &ikm);
                hk.expand(&info, &mut okm)
                    .expect("hkdf expand should never fail");

                let aes_key = okm.to_vec();

                Ok(Session {
                    object_path: session_path,
                    encrypted: true,
                    server_public_key: Some(server_public_key_bytes),
                    aes_key: Some(aes_key),
                    my_private_key: Some(private_key_bytes.to_vec()),
                    my_public_key: Some(public_key_bytes.to_vec()),
                })
            }
        }
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn get_aes_key(&self) -> Vec<u8> {
        self.aes_key.clone().unwrap()
    }
}

/// from https://github.com/plietar/librespot/blob/master/core/src/util/mod.rs#L53
fn powm(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    let mut base = base.clone();
    let mut exp = exp.clone();
    let mut result: BigUint = One::one();

    while !exp.is_zero() {
        if exp.is_odd() {
            result = result.mul(&base).rem(modulus);
        }
        exp = exp.shr(1);
        base = (&base).mul(&base).rem(modulus);
    }

    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn should_create_plain_session() {
        let conn = zbus::blocking::Connection::session().unwrap();
        let service_proxy = ServiceProxyBlocking::new(&conn).unwrap();
        let session = Session::new(&service_proxy, EncryptionType::Plain).unwrap();
        assert!(!session.is_encrypted());
    }

    #[test]
    fn should_create_encrypted_session() {
        let conn = zbus::blocking::Connection::session().unwrap();
        let service_proxy = ServiceProxyBlocking::new(&conn).unwrap();
        let session = Session::new(&service_proxy, EncryptionType::Dh).unwrap();
        assert!(session.is_encrypted());
    }
}
