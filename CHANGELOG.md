# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.11.24](https://github.com/maidsafe/sn_data_types/compare/v0.11.23...v0.11.24) (2020-10-27)


### Features

* **keys:** Keypair refactor + remove PublicIds ([6577a09](https://github.com/maidsafe/sn_data_types/commit/6577a09fbd9509b5d4a483ba266b23e81848955c))
* **sk:** from helper for bls SecretKey to add SerdeSecret ([1698367](https://github.com/maidsafe/sn_data_types/commit/1698367e014225df6238fbebbb34a7ed90e75e01))

### [0.11.23](https://github.com/maidsafe/sn_data_types/compare/v0.11.22...v0.11.23) (2020-10-20)


### Features

* **keys:** converting to more generic data types for keypair sk pk ([037b4c4](https://github.com/maidsafe/sn_data_types/commit/037b4c4d8284d05ea2761111b173222bd6277919))

### [0.11.22](https://github.com/maidsafe/sn_data_types/compare/v0.11.21...v0.11.22) (2020-10-19)

### [0.11.21](https://github.com/maidsafe/sn_data_types/compare/v0.11.20...v0.11.21) (2020-10-09)

### [0.11.20](https://github.com/maidsafe/sn_data_types/compare/v0.11.19...v0.11.20) (2020-10-09)

### [0.11.19](https://github.com/maidsafe/sn_data_types/compare/v0.11.18...v0.11.19) (2020-10-08)


### Features

* **msg_sender:** expose sender type query api ([1841c3f](https://github.com/maidsafe/sn_data_types/commit/1841c3f61316244022a70ed789fd4fb9d3613cc4))
* **msg_sender:** expose sig share and key set api ([814193e](https://github.com/maidsafe/sn_data_types/commit/814193ebd5739adaeacdbed9d1ecc22865c68e4f))
* **sender:** expose entityid public_key api ([c715c3c](https://github.com/maidsafe/sn_data_types/commit/c715c3c81cb8da8d45aaa3ca3e0da8a5bb02967b))


### Bug Fixes

* **sender_malarkey:** just fix it ([733beae](https://github.com/maidsafe/sn_data_types/commit/733beae651e2cde02e24597a8e57c992ff2e502b))

### [0.11.18](https://github.com/maidsafe/sn_data_types/compare/v0.11.17...v0.11.18) (2020-09-28)

### [0.11.17](https://github.com/maidsafe/sn_data_types/compare/v0.11.16...v0.11.17) (2020-09-15)

### [0.11.16](https://github.com/maidsafe/sn_data_types/compare/v0.11.15...v0.11.16) (2020-09-09)


### Bug Fixes

* **cd:** use cleaner naming for release changelog generation ([ff0867e](https://github.com/maidsafe/sn_data_types/commit/ff0867e3458901c09ad95504e3b920ea06aa08db))

### [0.11.15](https://github.com/maidsafe/sn_data_types/compare/v0.11.14...v0.11.15) (2020-09-09)

### Bug Fixes

* **CD:** use token option for checkout@2 ([dc8422b](https://github.com/maidsafe/sn_data_types/commit/dc8422bd28d242cf27580829e9e8623fc97163c1))

### [0.11.14](https://github.com/maidsafe/sn_data_types/compare/v0.11.13...v0.11.14) (2020-09-09)


### Bug Fixes

* **CD:** use branch creator token for creating tags ([ddfd304](https://github.com/maidsafe/sn_data_types/commit/ddfd3049068dc8b00b6cb48b29e0b224ee2a6459))

### [0.11.13](https://github.com/maidsafe/sn_data_types/compare/v0.11.12...v0.11.13) (2020-09-08)


### Bug Fixes

* **seq:** seq messaging updates for policy retrieval ([2688244](https://github.com/maidsafe/sn_data_types/commit/2688244e972c3d941b5759424e0724cfc7fe68c1))

### [0.11.12](https://github.com/maidsafe/sn_data_types/compare/v0.11.11...v0.11.12) (2020-09-08)


### Bug Fixes

* **seq:** updates to seq after policy changes. ([13d0861](https://github.com/maidsafe/sn_data_types/commit/13d086169f4fb14b76c7a3fe4a13c0a4ebdace96))

### [0.11.11](https://github.com/maidsafe/sn_data_types/compare/v0.11.10...v0.11.11) (2020-09-07)

### [0.11.10](https://github.com/maidsafe/sn_data_types/compare/v0.11.9...v0.11.10) (2020-09-07)

### [0.11.9](https://github.com/maidsafe/sn_data_types/compare/v0.11.8...v0.11.9) (2020-09-07)


### Bug Fixes

* **seq:** Update PolicyWrite to use new PolicyOp ([13b8ca6](https://github.com/maidsafe/sn_data_types/commit/13b8ca6985ed68545200ec3ca5cef714b278e160))

### 0.11.8 (2020-09-07)

### Bug Fixes

* **CD:** Re-add 'v' to tag to enable proper standard-version and changelog generation ([6c9bdb3](https://github.com/maidsafe/sn_data_types/commit/6c9bdb33c67f39b87d131e07885d148ab5d31fb1))


### 0.11.7 (2020-09-07)


### Features

* Add SafeKey abstraction over id types ([46c7e88](https://github.com/maidsafe/sn_data_types/commit/46c7e88df8ea71b30757b67f2e92462f0d3f9946))


### 0.11.6 (2020-09-03)


### Features

* **sequence:** support data ops to be concurrent with policy ops ([743198c](https://github.com/maidsafe/sn_data_types/commit/743198c277c1948b49863eee77115a78b6be1e69))


### 0.11.5 (2020-09-03)

Chore release


### 0.11.4 (2020-08-25)


Chore release


### 0.11.2 (2020-08-18)


### Features

* **blob:** get some owner pk for blob ([6c0a0a1](https://github.com/maidsafe/sn_data_types/commit/6c0a0a1dd859db44c84934e24ecd86ba3195fcca))
* remove SafeKey struct and app funcs ([00c77cb](https://github.com/maidsafe/sn_data_types/commit/00c77cb7e1a187a9f19acb1f22e68262fddeebdd))
* **duties:** add node duty, with node config ([72c595d](https://github.com/maidsafe/sn_data_types/commit/72c595d8de4fea8cf98c6780c184209c6b996f65))
* **farming:** add payment query for store cost ([214c00b](https://github.com/maidsafe/sn_data_types/commit/214c00b48346640b37c3a5c4af57fffa1f1449fd))
* **keypairs:** add new type to replace FullId ([5a17929](https://github.com/maidsafe/sn_data_types/commit/5a179297cbf0a29200ac6a8abfc9bffacd1c0872))
* **keypairs:** add new type to replace FullId ([2dee6d7](https://github.com/maidsafe/sn_data_types/commit/2dee6d771903c82cc83c41e7b60cf0de610daef2))
* **msgs:** add node transfer query ([809bfa8](https://github.com/maidsafe/sn_data_types/commit/809bfa823d971d2ab19c32b1ce26f89f6d82662c))
* **rewards:** register a node wallet for rewards ([7eef548](https://github.com/maidsafe/sn_data_types/commit/7eef5480e779ec974df0957cdb1067e5e5474428))
* get keypair from safekey easily ([f44c935](https://github.com/maidsafe/sn_data_types/commit/f44c935802d1d18677e8a487acb25b199f7e6418))


### Bug Fixes

* **nodekeypairs:** include index when setting bls ([765fcb3](https://github.com/maidsafe/sn_data_types/commit/765fcb34b2eaeeb029b30c3e2dfb757e9ae1e5ca))
* **tests:** test imports updated for blob/map ([87664f9](https://github.com/maidsafe/sn_data_types/commit/))
* **xorname:** use random xornames ([1d55b55](https://github.com/maidsafe/sn_data_types/commit/1d55b55bea2b1410b5ff667c642246b0234619ef))

### 0.11.1 (2020-07-29)

Chore release.

### 0.11.0 (2020-07-29)


### Features

* **CD:** Automatically create a github release w/ latest changes ([8845a2d](https://github.com/maidsafe/sn_data_types/commit/8845a2daee79498be620f2a5d01bdf51e8591bfa))
* **CD:** Enable auto merge of generated release PRs ([7fe369d](https://github.com/maidsafe/sn_data_types/commit/7fe369d31856a83081a4c87626c94d9d935dabfb))
* automerge update ([c55da4d](https://github.com/maidsafe/sn_data_types/commit/c55da4d6731492523a3874fac17bcc539bca296f))
* **audit:** add scheduled security audit scan ([4725d13](https://github.com/maidsafe/sn_data_types/commit/4725d13ee7a473f46bf2e119d5021b6ab5f8fb71))



### Bug Fixes

* **ci:** release action update. ([33aa4ae](https://github.com/maidsafe/sn_data_types/commit/33aa4ae4e281e11d1e0241e6be4c36e2b5daff95))



### Others

* ***deps*** update threshold_crypto and add refactor code accordingly ([f6c748d](https://github.com/maidsafe/sn_data_types/commit/f6c748d94cb696f69607aee0b1147d04ecda97ea))

* ***deps*** update rand and ed25519-dalek crate ([84f76af](https://github.com/maidsafe/sn_data_types/commit/84f76af68df6c23dd634b9af0ac8ecb66429636c))

* ***deps*** reuse XorName from the xor-name crate ([95258f2](https://github.com/maidsafe/sn_data_types/commit/95258f2e81822d8549e9f75ba1cc8fe5bb7a38f1))



### 0.10.4 (2020-07-29)


### Features


### 0.10.3 (2020-07-28)


### Features


### 0.10.2 (2020-07-27)


### Features


## 10.1.0 (2020-07-21)


### Features

* **audit:** add scheduled security audit scan ([4725d13](https://github.com/joshuef/sn_data_types/commit/4725d13ee7a473f46bf2e119d5021b6ab5f8fb71))

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
- Add `AData` methods `owners_range`, `append_seq`, `append_unseq`, `append_pub_permissions`, `append_unpub_permissions`, and `append_owner`.

## [0.2.0]

- Added the identities (public and private) for clients and apps.
- Added the AppendOnlyData types.
- Added the unpublished MutableData type.
- Added the unpublished and published Blob types.
- Added the Request and Response RPCs.

## [0.1.0]

- Initial implementation.
