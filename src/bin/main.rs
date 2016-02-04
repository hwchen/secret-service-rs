extern crate secret_service;

use secret_service::SecretService;
use secret_service::session::EncryptionType;

fn main() {
    let ss = SecretService::new(EncryptionType::Plain).unwrap();
    let collection = ss.get_default_collection().unwrap();
    let items = collection.get_all_items().unwrap();
    let items_count = items.len();
    println!("Count before: {:?}", items.len());
    if items_count > 0 {
        for item in items {
            item.delete().unwrap();
        }
    }
    let items = collection.get_all_items().unwrap();
    println!("Count after: {:?}", items.len());

    // delete Test collections
    let collections = ss.get_all_collections().unwrap();
    for collection in collections {
        if collection.get_label().unwrap() == "Test" {
            println!("{:?}", collection.collection_path);
            collection.delete().unwrap();
        }
    }
}
