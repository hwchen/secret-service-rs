# Secret Service

Secret Service Rust library.

Interfaces with the Linux Secret Service API through dbus.

This library is feature complete but still in *experimental* stage.

### Documentation

[Get Docs!](https://hwchen.github.io/secret-service-rs/secret_service/)

### Basic Usage

Requires dbus and gmp development libraries installed (see [Advanced](#advanced) section if you need to disable gmp).

On ubuntu, requires libdbus-1-dev and libgmp-dev.

In Cargo.toml:

```
[dependencies]
secret-service = "0.2.0"
```

If you have `cargo-extras` installed, can replace above step with the command at the prompt in your project directory:

```
$ cargo add secret-service
```

In source code (below example is for --bin, not --lib)

```rust
extern crate secret_service;
use secret_service::SecretService;
use secret_service::EncryptionType;

fn main() {

    // initialize secret service (dbus connection and encryption session)
    let ss = SecretService::new(EncryptionType::Dh).unwrap();

    // get default collection
    let collection = ss.get_default_collection().unwrap();

    //create new item
    collection.create_item(
        "test_label", // label
        vec![("test", "test_value")], // properties
        b"test_secret", //secret
        false, // replace item with same attributes
        "text/plain" // secret content type
    ).unwrap();

    // search items by properties
    let search_items = ss.search_items(
        vec![("test", "test_value")]
    ).unwrap();

    let item = search_items.get(0).unwrap();

    // retrieve secret from item
    let secret = item.get_secret().unwrap();
    assert_eq!(secret, b"test_secret");

    // delete item (deletes the dbus object, not the struct instance)
    item.delete().unwrap()
}
```

### Functionality

- SecretService: initialize dbus, create plain/encrypted session.
- Collections: create, delete, search.
- Items: create, delete, search, get/set secret.

### Advanced

It is possible to disable the dependency on `libgmp` by disabling the default
features in your `Cargo.toml` file:

    [dependencies]
    secret-service = { version = "^0.4", default-features = false }

 
**Note**: this will build the library without support for creating encrypted connections 
to `dbus`, `EncryptionType::Dh` will be unavailable. 

In many cases this is OK, as `dbus` encryption is primarily intended to prevent secrets
from being swapped to disk. 

Use `EncryptionType::Plain` when `gmp` is disabled.

### Todo

- use `map_err(|_| SsError::Parse)` for `inner()`? can't `try!` because `inner()` doesn't return an Error type in the Result. Or just `unwrap()`?
- some refactoring (a list is in lib.rs)
- clear failed tests? (there is no "after" currently)
- move tests to integration tests?
- Should/can struct instances be deleted when dbus object is deleted?

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
  
