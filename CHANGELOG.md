# safe-nd - Change Log

## [0.7.2]

- Fix GitHub actions crate.io release, with `git log --no-merges`

## [0.7.1]

- Add `version` and `set_version` methods to `SeqEntryAction`.

## [0.7.0]

- Change the Client<->Node handshake protocol: it replaces a one-purpose `Challenge` enum with a more extensive pair of enums, `HandshakeRequest` and `HandshakeResponse`.
- Fix pedantic clippy errors.

## [0.6.2]

- Add `version` and `set_version` functions to `SeqEntryAction`.

## [0.6.1]

- Implement `From` trait for `id::client::FullId` to allow conversion from supported key types.

## [0.6.0]

- Change CI to GitHub Actions.
- Clean up explicitly-listed non-warn lints.
- Add `Keypair` and remove BLS methods for full IDs.

## [0.5.0]

- Expand `Challenge::Response` with an option to request section information from any node.
- Added a new message type, `Message::SectionInfo`, which can be used by Vaults to send the elders connection information to clients.
- Added `ConnectionInfo`.

## [0.4.0]

- Changed `AppPermissions` to include permissions for allowing mutations and getting a user's balance.

## [0.3.2]

- Added `RequestType` and `Request::get_type`

## [0.3.1]

- Fixed bug in the `error_response` function to return a `Transaction` Response for `CreateLoginPacketFor`.

## [0.3.0]

- Deprecate the `InvalidPermissions` error variant in favour of `AccessDenied`
- Fix deprecation errors on Rust 1.37

## [0.2.1]

- Make some documentation fixes and additions.
- Add `UnseqEntryActions` methods `actions`, `into_actions`, and `add_action`.
- Add `SeqEntryActions` methods `into_actions` and `add_action`.
- Add `AData` methods `owners_range`, `append_seq`, `append_unseq`, `append_pub_permissions`, `append_unpub_permissions`, and `append_owner`.

## [0.2.0]

- Added the identities (public and private) for clients and apps.
- Added the AppendOnlyData types.
- Added the unpublished MutableData type.
- Added the unpublished and published ImmutableData types.
- Added the Request and Response RPCs.

## [0.1.0]

- Initial implementation.
