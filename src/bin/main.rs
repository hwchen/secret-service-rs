extern crate secret_service;

use secret_service::SecretService;

fn main() {
    let ss = SecretService::new().unwrap();
    println!("{:?}", ss.test_message());
}
