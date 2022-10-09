# Secret Service

Secret Service Rust library.

Interfaces with the Linux Secret Service API through dbus.

### Versioning
This library is feature complete, has stabilized its API for the most part. However, as this
crate is almost soley reliable on the `zbus` crate, we try and match major version releases
with theirs to handle breaking changes and move with the wider `zbus` ecosystem.

### Documentation

[Get Docs!](https://docs.rs/secret-service/)

### Basic Usage

Does not require dbus library! Pure Rust!
(On ubuntu, this was libdbus-1-dev when building, and libdbus-1-3 when running)

In Cargo.toml:

```
[dependencies]
secret-service = "2.0.0"
```

Or, you can add this project with `cargo add`:

```
$ cargo add secret-service
```

In source code (below example is for --bin, not --lib). This example uses `tokio` as
the async runtime.

```rust
use secret_service::SecretService;
use secret_service::EncryptionType;
use std::{collections::HashMap, error::Error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // initialize secret service (dbus connection and encryption session)
    let ss = SecretService::connect(EncryptionType::Dh).await?;

    // get default collection
    let collection = ss.get_default_collection().await?;

    // create new item
    collection.create_item(
        "test_label", // label
        HashMap::from([("test", "test_value")]), // properties
        b"test_secret", // secret
        false, // replace item with same attributes
        "text/plain" // secret content type
    ).await?;

    // search items by properties
    let search_items = ss.search_items(
        HashMap::from([("test", "test_value")])
    ).await?;

    let item = search_items.unlocked.get(0).ok_or("Not found!")?;

    // retrieve secret from item
    let secret = item.get_secret().await?;
    assert_eq!(secret, b"test_secret");

    // delete item (deletes the dbus object, not the struct instance)
    item.delete().await?;
    Ok(())
}
```

### Functionality

- SecretService: initialize dbus, create plain/encrypted session.
- Collections: create, delete, search.
- Items: create, delete, search, get/set secret.

### Changelog
See [the changelog file](./CHANGELOG.md)

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
