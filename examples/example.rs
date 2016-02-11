//Copyright 2016 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

extern crate secret_service;

use secret_service::SecretService;
use secret_service::EncryptionType;
use std::str;

fn main() {
    // Initialize secret service
    let ss = SecretService::new(EncryptionType::Plain).unwrap();

    // navigate to default collection
    let collection = ss.get_default_collection().unwrap();

    //create new item
    let new_item = collection.create_item(
        "test_label", // label
        vec![("test", "test_value")], // properties
        b"test_secret", //secret
        false, // replace item with same attributes
        "text/plain" // secret content type
    ).unwrap();

    println!("New Item: {:?}", new_item);

    // search items by properties
    let search_items = ss.search_items(
        vec![("test", "test_value")]
    ).unwrap();

    println!("Searched Item: {:?}", search_items);

    let item = search_items.get(0).unwrap();

    // retrieve secret from item
    let secret = item.get_secret().unwrap();
    println!("Retrieved secret: {:?}", str::from_utf8(&secret).unwrap());
    assert_eq!(secret, b"test_secret");
    //item.delete().unwrap();
}
