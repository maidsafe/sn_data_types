# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.17.2](https://github.com/maidsafe/sn_data_types/compare/v0.17.1...v0.17.2) (2021-03-26)


### Features

* adds hex-parse for user-facing pk/sk variants and hex formatting for pk ([e152e45](https://github.com/maidsafe/sn_data_types/commit/e152e457d6dc0dab3b9b49e4d4d70ce3ca2541b2))

### [0.17.1](https://github.com/maidsafe/sn_data_types/compare/v0.17.0...v0.17.1) (2021-03-23)

## [0.17.0](https://github.com/maidsafe/sn_data_types/compare/v0.16.0...v0.17.0) (2021-03-22)


### ⚠ BREAKING CHANGES

* Renames walletinfo -> WalletHistory
- and add conenience methods to sectionelders

### Features

* **ownertype:** add verify api ([cc15962](https://github.com/maidsafe/sn_data_types/commit/cc159626e60a06fa173f1588a62a116d12708a48))
* **rewards:** add reward stage enum ([e15cbab](https://github.com/maidsafe/sn_data_types/commit/e15cbab888042db568e027c4c0ace7af178eacbf))
* **section:** add section elders struct ([e6be620](https://github.com/maidsafe/sn_data_types/commit/e6be6202f1ceb3012e06ca7cd70a299d2a10a613))


* rename walletinfo ([5ef267d](https://github.com/maidsafe/sn_data_types/commit/5ef267d0a7fc8bd9ad9c2c6475f148446e543295))

## [0.16.0](https://github.com/maidsafe/sn_data_types/compare/v0.15.3...v0.16.0) (2021-03-03)


### ⚠ BREAKING CHANGES

* **Seq:** Policy mutation APIs are removed and Sequence constructors need the Policy to be provided up front.

### Features

* **Seq:** making the Policy of a Sequence data type immutable ([1261f58](https://github.com/maidsafe/sn_data_types/commit/1261f58f4be4537f8cb3510071f6935ca844d95d))

### [0.15.3](https://github.com/maidsafe/sn_data_types/compare/v0.15.2...v0.15.3) (2021-02-25)

### [0.15.2](https://github.com/maidsafe/sn_data_types/compare/v0.15.1...v0.15.2) (2021-02-23)

### [0.15.1](https://github.com/maidsafe/sn_data_types/compare/v0.15.0...v0.15.1) (2021-02-23)

## [0.15.0](https://github.com/maidsafe/sn_data_types/compare/v0.14.8...v0.15.0) (2021-02-22)


### ⚠ BREAKING CHANGES

* **api:** borrow pattern updated, breaking the current dt api

### Features

* **api:** api updated ([1d83574](https://github.com/maidsafe/sn_data_types/commit/1d83574d625e3eb2db4555f18d066e66c62a31ab))

### [0.14.8](https://github.com/maidsafe/sn_data_types/compare/v0.14.7...v0.14.8) (2021-02-22)

### [0.14.7](https://github.com/maidsafe/sn_data_types/compare/v0.14.6...v0.14.7) (2021-02-22)

### [0.14.6](https://github.com/maidsafe/sn_data_types/compare/v0.14.5...v0.14.6) (2021-02-16)

### [0.14.5](https://github.com/maidsafe/sn_data_types/compare/v0.14.4...v0.14.5) (2021-02-16)

### [0.14.4](https://github.com/maidsafe/sn_data_types/compare/v0.14.3...v0.14.4) (2021-02-09)

### [0.14.3](https://github.com/maidsafe/sn_data_types/compare/v0.14.2...v0.14.3) (2021-02-03)

### [0.14.2](https://github.com/maidsafe/sn_data_types/compare/v0.14.1...v0.14.2) (2021-02-03)

### [0.14.1](https://github.com/maidsafe/sn_data_types/compare/v0.14.0...v0.14.1) (2021-02-02)

## [0.14.0](https://github.com/maidsafe/sn_data_types/compare/v0.13.5...v0.14.0) (2021-02-01)


### ⚠ BREAKING CHANGES

* rename money to token

* rename money to token ([f1a3154](https://github.com/maidsafe/sn_data_types/commit/f1a3154c3247df47860f7440161e1285d4ef755c))

### [0.13.5](https://github.com/maidsafe/sn_data_types/compare/v0.13.4...v0.13.5) (2021-02-01)


### Features

* Add Signing trait and OwnerType ([b7bb95f](https://github.com/maidsafe/sn_data_types/commit/b7bb95f5dff1fa5839b61c6dd6220943054747f9))
* Use Arc internally in Keypair ([343985a](https://github.com/maidsafe/sn_data_types/commit/343985a0cd4b0abb11c25583f4fa8d9685037488))

### [0.13.4](https://github.com/maidsafe/sn_data_types/compare/v0.13.3...v0.13.4) (2021-01-29)


### Features

* **multi_sig:** add signed transfer shares ([7daed15](https://github.com/maidsafe/sn_data_types/commit/7daed151f173c55ac6f7c0fe31fec06734b8c311))
* **transfers:** add as_share api to debit+credit ([a08ce5f](https://github.com/maidsafe/sn_data_types/commit/a08ce5f6768af7fa6a6b70515f343efceb5640ad))

### [0.13.3](https://github.com/maidsafe/sn_data_types/compare/v0.13.2...v0.13.3) (2021-01-28)

### [0.13.2](https://github.com/maidsafe/sn_data_types/compare/v0.13.1...v0.13.2) (2021-01-26)


### Bug Fixes

* **seq:** in_range API was not taking the end index correctly ([b225d0e](https://github.com/maidsafe/sn_data_types/commit/b225d0e0927a1110fe1dbac60e95b3f61d4899b3))

### [0.13.1](https://github.com/maidsafe/sn_data_types/compare/v0.13.0...v0.13.1) (2021-01-14)

## [0.13.0](https://github.com/maidsafe/sn_data_types/compare/v0.12.0...v0.13.0) (2021-01-05)


### ⚠ BREAKING CHANGES

* **errors:** errors not needed by this crate are removed

### Features

* **entry errors:** Merge entry errors into main errors ([c17098d](https://github.com/maidsafe/sn_data_types/commit/c17098dc68d7f2030d1de7b9e46944028ac18914))
* **messaging:** Messaging extracted ([8719170](https://github.com/maidsafe/sn_data_types/commit/87191702b62bd08a2bc6cd5d3e3293646c441773))


* **errors:** remove non dt-used errors ([07bd147](https://github.com/maidsafe/sn_data_types/commit/07bd147ef4764c8fe09ec5f4a5f7a3002b820822))

## [0.12.0](https://github.com/maidsafe/sn_data_types/compare/v0.11.42...v0.12.0) (2020-12-30)


### ⚠ BREAKING CHANGES

* **auth:** Auth message types removed as this is now managed via standard data types

### Features

* **auth:** Remove auth message types. ([70ab97e](https://github.com/maidsafe/sn_data_types/commit/70ab97eb331cc52bad289edd81884605e6ac4703))

### [0.11.42](https://github.com/maidsafe/sn_data_types/compare/v0.11.41...v0.11.42) (2020-12-29)


### Features

* **errors:** additional error types ([ad71e64](https://github.com/maidsafe/sn_data_types/commit/ad71e6431fea017abf3beffac199d6e40e818037))

### [0.11.41](https://github.com/maidsafe/sn_data_types/compare/v0.11.40...v0.11.41) (2020-12-28)


### Features

* **errors:** expose denied PK in error messages ([2d3082b](https://github.com/maidsafe/sn_data_types/commit/2d3082bf70dcfceba8110f74b8d8f95acbcdeb39))
* use thiserror for errors ([49c32bf](https://github.com/maidsafe/sn_data_types/commit/49c32bf7bb2238b3000386e3156ab2f7cab2fecc))

### [0.11.40](https://github.com/maidsafe/sn_data_types/compare/v0.11.39...v0.11.40) (2020-12-26)

### [0.11.39](https://github.com/maidsafe/sn_data_types/compare/v0.11.38...v0.11.39) (2020-12-17)

### [0.11.38](https://github.com/maidsafe/sn_data_types/compare/v0.11.37...v0.11.38) (2020-12-17)


### Features

* **chunks:** add StroageFull Cmd for Adults ([51a4043](https://github.com/maidsafe/sn_data_types/commit/51a4043fab4f628738f59322cbc0cdd67983f7b8))
* **MessageId:** create from source ([e8a7381](https://github.com/maidsafe/sn_data_types/commit/e8a7381fa4bbca9852e307147f450e80ad9f0c12))


### Bug Fixes

* **messaging:** fix destination for Transfer messages ([479826a](https://github.com/maidsafe/sn_data_types/commit/479826a093377f668d53ebfb5aa8a7898d083306))

### [0.11.37](https://github.com/maidsafe/sn_data_types/compare/v0.11.36...v0.11.37) (2020-12-08)


### Features

* **adult:** add adult duties for chunk replication ([a22b151](https://github.com/maidsafe/sn_data_types/commit/a22b1511a0d92513665435ba4c59a7572c96556d))

### [0.11.36](https://github.com/maidsafe/sn_data_types/compare/v0.11.35...v0.11.36) (2020-12-07)

### [0.11.35](https://github.com/maidsafe/sn_data_types/compare/v0.11.34...v0.11.35) (2020-12-03)


### Features

* **owner:** add owner getter for all datatypes ([775eb5d](https://github.com/maidsafe/sn_data_types/commit/775eb5d326f2d39a68880918f022412ebd705f4e))

### [0.11.34](https://github.com/maidsafe/sn_data_types/compare/v0.11.33...v0.11.34) (2020-12-01)


### Bug Fixes

* **cmd:** fix cmd destination for Metadata ([337035a](https://github.com/maidsafe/sn_data_types/commit/337035a76e4de57725ec9e51b69382b2f58cea53))
* **debug:** fix misleading debug implementation for blob commands ([b554e77](https://github.com/maidsafe/sn_data_types/commit/b554e7745f3d3edf536c2ab3482af2dacd7d7354))

### [0.11.33](https://github.com/maidsafe/sn_data_types/compare/v0.11.32...v0.11.33) (2020-11-25)

### [0.11.32](https://github.com/maidsafe/sn_data_types/compare/v0.11.31...v0.11.32) (2020-11-25)


### Features

* **seq:** require apply method call for seq crdt ([b1abdb4](https://github.com/maidsafe/sn_data_types/commit/b1abdb4f86ce8f54209282b0b16be9212b915b59))

### [0.11.31](https://github.com/maidsafe/sn_data_types/compare/v0.11.30...v0.11.31) (2020-11-24)

### [0.11.30](https://github.com/maidsafe/sn_data_types/compare/v0.11.29...v0.11.30) (2020-11-18)


### Features

* **seq:** reexpose check perms api ([39a63ca](https://github.com/maidsafe/sn_data_types/commit/39a63cab6e7133b7afe90d12e092d315df64e2d9))
* **sequence:** require signed ops ([4b0f54d](https://github.com/maidsafe/sn_data_types/commit/4b0f54d1102299edb03f70ea70e3ef329322260e))

### [0.11.29](https://github.com/maidsafe/sn_data_types/compare/v0.11.28...v0.11.29) (2020-11-18)

### [0.11.28](https://github.com/maidsafe/sn_data_types/compare/v0.11.27...v0.11.28) (2020-11-16)

### [0.11.27](https://github.com/maidsafe/sn_data_types/compare/v0.11.26...v0.11.27) (2020-11-11)

### [0.11.26](https://github.com/maidsafe/sn_data_types/compare/v0.11.25...v0.11.26) (2020-11-11)

### [0.11.25](https://github.com/maidsafe/sn_data_types/compare/v0.11.24...v0.11.25) (2020-11-10)


### Features

* **Seq:** add convenience APIs to query latest policy and permissions ([e47ca4e](https://github.com/maidsafe/sn_data_types/commit/e47ca4e91f0d498e38f083c032f51d7e0daa8276))
* **Seq:** adding policy enforcement logic ([e19e693](https://github.com/maidsafe/sn_data_types/commit/e19e6935600541524b1c12412f1b29f77aadb805))
* **Seq:** include a PublicKey as part of the crdt op, and use it to enforce policy when applying the ops ([8318be6](https://github.com/maidsafe/sn_data_types/commit/8318be6931343e4e562b4b0ae9c6dd5443ead7a9))

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
