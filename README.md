# Secret Service

Secret Service Rust library.

Interfaces with the Linux Secret Service API through dbus.

My understanding is that this library will interface directly with Secret Service. Encryption is negotiated each new session, so an item that was encrypted/decrypted in one session, will be encrypted/decrypted with the new session parameters when a new connection is created.

(API was not entirely clear on this, my conclusion is drawn from the fact that when secret is returned, the session path is that of the current session, and not the one when the item was created).

Readme current for 2/4/2016.

## Installation

On ubuntu, requires libdbus-1-dev to compile.

I'll provide better notes on installation once finished and published

## Progress

### Completed

- SecretService: initialize dbus, create plain/encrypted session
- Collections: create, delete, search
- Items: create, delete, search
- crypto

### Todo

- better comments
- handle drop?
- actual docs
- error handling (return an SSError)
- some refactoring
- publishing

I've been writing simple tests as I go along. Most of completed list has some coverage.



## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
  
