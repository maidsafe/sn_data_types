# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### 0.11.1 (2020-07-29)


### Features

* **CD:** Automatically create a github release w/ latest changes ([8845a2d](https://github.com/maidsafe/safe-nd/commit/8845a2daee79498be620f2a5d01bdf51e8591bfa))
* **CD:** Enable auto merge of generated release PRs ([7fe369d](https://github.com/maidsafe/safe-nd/commit/7fe369d31856a83081a4c87626c94d9d935dabfb))
* automerge update ([c55da4d](https://github.com/maidsafe/safe-nd/commit/c55da4d6731492523a3874fac17bcc539bca296f))
* **audit:** add scheduled security audit scan ([4725d13](https://github.com/maidsafe/safe-nd/commit/4725d13ee7a473f46bf2e119d5021b6ab5f8fb71))


### Bug Fixes

* **ci:** release action update. ([33aa4ae](https://github.com/maidsafe/safe-nd/commit/33aa4ae4e281e11d1e0241e6be4c36e2b5daff95))

### 0.11.0 (2020-07-29)


### Features

* **CD:** Automatically create a github release w/ latest changes ([8845a2d](https://github.com/maidsafe/safe-nd/commit/8845a2daee79498be620f2a5d01bdf51e8591bfa))
* **CD:** Enable auto merge of generated release PRs ([7fe369d](https://github.com/maidsafe/safe-nd/commit/7fe369d31856a83081a4c87626c94d9d935dabfb))
* automerge update ([c55da4d](https://github.com/maidsafe/safe-nd/commit/c55da4d6731492523a3874fac17bcc539bca296f))
* **audit:** add scheduled security audit scan ([4725d13](https://github.com/maidsafe/safe-nd/commit/4725d13ee7a473f46bf2e119d5021b6ab5f8fb71))


### Bug Fixes

* **ci:** release action update. ([33aa4ae](https://github.com/maidsafe/safe-nd/commit/33aa4ae4e281e11d1e0241e6be4c36e2b5daff95))


### Others

* ***deps*** update threshold_crypto and add refactor code accordingly ([f6c748d](https://github.com/maidsafe/safe-nd/commit/f6c748d94cb696f69607aee0b1147d04ecda97ea))

* ***deps*** update rand and ed25519-dalek crate ([84f76af](https://github.com/maidsafe/safe-nd/commit/84f76af68df6c23dd634b9af0ac8ecb66429636c))

* ***deps*** reuse XorName from the xor-name crate ([95258f2](https://github.com/maidsafe/safe-nd/commit/95258f2e81822d8549e9f75ba1cc8fe5bb7a38f1))



### 0.10.4 (2020-07-29)


### Features

* automerge update ([c55da4d](https://github.com/maidsafe/safe-nd/commit/c55da4d6731492523a3874fac17bcc539bca296f))
* **audit:** add scheduled security audit scan ([4725d13](https://github.com/maidsafe/safe-nd/commit/4725d13ee7a473f46bf2e119d5021b6ab5f8fb71))

### 0.10.3 (2020-07-28)


### Features

* automerge update ([c55da4d](https://github.com/maidsafe/safe-nd/commit/c55da4d6731492523a3874fac17bcc539bca296f))
* **audit:** add scheduled security audit scan ([4725d13](https://github.com/maidsafe/safe-nd/commit/4725d13ee7a473f46bf2e119d5021b6ab5f8fb71))

### 0.10.2 (2020-07-27)


### Features

* **audit:** add scheduled security audit scan ([4725d13](https://github.com/maidsafe/safe-nd/commit/4725d13ee7a473f46bf2e119d5021b6ab5f8fb71))

## 10.1.0 (2020-07-21)


### Features

* **audit:** add scheduled security audit scan ([4725d13](https://github.com/joshuef/safe-nd/commit/4725d13ee7a473f46bf2e119d5021b6ab5f8fb71))

## [0.10.1]

- Upgrade bincode crate to v1.2.1

## [0.10.0]

- Addition of Sequence CRDT
- Upgrade rust-crdt crate to v4.1.0
- Removal of AppendOnlyData type
- Addition of a scheduled security audit scan on CI

## [0.9.0]

- Expose functions which tell you the Request's destination address (XorName) and the type of authorisation needed for the request (RequestAuthKind)
- Break the `Request` enum down into several ones
- Update README to link to contributing guidelines doc

## [0.8.0]

- Remove limit check from `Coins::from_nano`.
- Replace `ConnectionInfo` with `SocketAddr`.

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
- Add `AData` methods `owners_range`, `append_seq`, `append_unseq`, `append_pub_permissions`, `append_unpub_permissions`, and `set_owner`.

## [0.2.0]

- Added the identities (public and private) for clients and apps.
- Added the AppendOnlyData types.
- Added the unpublished MutableData type.
- Added the unpublished and published ImmutableData types.
- Added the Request and Response RPCs.

## [0.1.0]

- Initial implementation.
