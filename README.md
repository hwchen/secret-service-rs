# Secret Service

Secret Service Rust library.

Interfaces with the Linux Secret Service API through dbus.

My understanding is that encryption is negotiated each new session, so an item that was encrypted/decrypted in one session, will be encrypted/decrypted with the new session parameters when a new connection is created.

(API was not entirely clear on this from my reading, my conclusion is drawn from the fact that when secret is returned, the session path is that of the current session, and not the one when the item was created).

Readme current for 2/6/2016.

## Installation

On ubuntu, requires libdbus-1-dev to compile.

I'll provide better notes on installation once finished and published

## Progress

### Completed

- SecretService: initialize dbus, create plain/encrypted session.
- Collections: create, delete, search.
- Items: create, delete, search, get/set secret.
- crypto
- error handling (return an SSError)

### Todo

 actual docs/example
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
  
