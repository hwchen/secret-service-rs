Unreleased
- Updated dependencies where reasonable
- Bumped MSRV to 1.60
- BREAKING: Updated to `zbus` 3.0. This changes error types and public path fields.
- BREAKING: The types exported from the crate root are now entirely async. Blocking functions have been moved into the `blocking` module.
- BREAKING: `Error::Crypto` now contains a `&'static str` instead of a `String`.
- BREAKING: `SecretService::search_items` now takes a `HashMap<&str, &str>` instead of `Vec<(&str, &str)>` for the attributes.
- BREAKING: The `SecretService::new()` method was renamed to `SecretService::connect()` to be more accurate.

[2.0.2]
- Increased minimum `zbus` version to 1.9.2, in order to increase the minimum version of the transitive dependency `nix` to at least 0.20.2, which is the first `nix` release to contain the fix for the security vulnerability described at https://rustsec.org/advisories/RUSTSEC-2021-0119 . A known issue with this version of `nix` is that it places an upper bound on the version of the `bitflags` dependency; if you are depending on `bitflags`, you may need to downgrade your `bitflags` version in order to upgrade to this version of `secret-service`, which you are encouraged to do in order to ensure that you are not exposed to the aforementioned `nix` vulnerability. In the long term, this will be fixed by upgrading `secret-service` to use a newer version of `zbus`, which itself depends on versions of `nix` which no longer have this restriction on `bitflags`.

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
[2.0.2]: https://github.com/hwchen/secret-service-rs/releases/tag/v2.0.2
