Unreleased
- Updated dependencies where reasonable
- Bumped MSRV to 1.58
- BREAKING: Updated to `zbus` 2.0. This changes error types and public path fields.
- BREAKING: `Error::Crypto` now contains a `&'static str` instead of a `String`.

[2.0.1]
- Updated crate's Rustdoc link

[2.0.0]
- dbus replaced by zbus, PURE RUST!
- update to 2018 edition
- BREAKING: `SsError` renamed to `Error`
- BREAKING: variants added to `Error`
- BREAKING: attributes are now `HashMap<&str, &str>` or `HashMap<String, String>` instead of `Vec<(&str, &str)>`. Not sure why I decided this way back when, but it could cause unexpected behavior for user: when the `Vec` was transformed to `HashMap` internally, tuples could be lost if the keys were the same.
- BREAKING: `Collection::new` and `Item::new` are now private (although I don't think it was possible to use them anyways)

_1.1.3_
- update deps

_1.1.2_
- update rand

[1.1.1]
- update deps

[1.1.0]
- Fix, get_collection_* returns Error::NoResult when doesn't exist
- udpate hkdf to 0.8

[1.0.0]
- switch from rust-crypto to RustCrypto
- remove gmp dep for powm
- update rand and num

_0.4.0_
- gmp is now optional dependency.
- gmp upgraded to 0.3 to fix "private-in-public" warnings which will be hard errors soon.

...

_0.1.0_
- dependency on gmp is removed.
- rust-crypto replaced by RustCrypto.
- as a result of above, error on encrypting and decrypting blank input is fixed.

[1.0.0]: https://github.com/hwchen/secret-service-rs/releases/tag/v1.0.0
[1.1.0]: https://github.com/hwchen/secret-service-rs/releases/tag/v1.1.0
[1.1.1]: https://github.com/hwchen/secret-service-rs/releases/tag/v1.1.1
[2.0.0]: https://github.com/hwchen/secret-service-rs/releases/tag/v2.0.0
[2.0.1]: https://github.com/hwchen/secret-service-rs/releases/tag/v2.0.1
