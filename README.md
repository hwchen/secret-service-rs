# Secret Service

Secret Service Rust library.

Interfaces with the Linux Secret Service API through dbus.

### Documentation

[Get Docs!](https://hwchen.github.io/secret-service-rs/secret_service/)

### Installation

Requires dbus development library installed.

On ubuntu, requires libdbus-1-dev and libgmp-dev.

### Functionality

- SecretService: initialize dbus, create plain/encrypted session.
- Collections: create, delete, search.
- Items: create, delete, search, get/set secret.

### Todo

- publishing

### Todo later

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
  
