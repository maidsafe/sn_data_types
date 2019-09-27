# safe-nd - Change Log

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
