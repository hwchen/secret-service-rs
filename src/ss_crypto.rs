//Copyright 2016 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// Contains encryption and decryption using aes.
// Could also contain setting aes key

use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

use crate::error::Result;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes128Cbc::new_from_slices(key, iv)?;
    let cipher_text = cipher.encrypt_vec(data);

    Ok(cipher_text)
}

pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes128Cbc::new_from_slices(key, iv)?;
    let decrypted = cipher.decrypt_vec(encrypted_data)?;

    Ok(decrypted)
}
