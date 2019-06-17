// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]
// FIXME - write docs
#![allow(missing_docs)]

mod append_only_data;
mod coins;
mod errors;
mod identity;
mod immutable_data;
mod mutable_data;
mod public_key;
mod request;
mod response;

pub use append_only_data::{
    Address as ADataAddress, AppendOnlyData, Index as ADataIndex, Indices as ADataIndices,
    Owner as ADataOwner, PubPermissionSet as ADataPubPermissionSet,
    PubPermissions as ADataPubPermissions, PubSeqAppendOnlyData, PubUnseqAppendOnlyData,
    UnpubPermissionSet as ADataUnpubPermissionSet, UnpubPermissions as ADataUnpubPermissions,
    UnpubSeqAppendOnlyData, UnpubUnseqAppendOnlyData, User as ADataUser,
};
pub use coins::{Coins, MAX_COINS_VALUE};
pub use errors::{EntryError, Error, Result};
pub use identity::{
    app::{FullId as AppFullId, PublicId as AppPublicId},
    client::{FullId as ClientFullId, PublicId as ClientPublicId},
    node::{FullId as NodeFullId, PublicId as NodePublicId},
    PublicId,
};
pub use immutable_data::{
    Address as IDataAddress, ImmutableData, UnpubImmutableData, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES,
};
pub use mutable_data::{
    Address as MDataAddress, MutableData, PermissionSet as MDataPermissionSet,
    SeqEntryAction as MDataSeqEntryAction, SeqEntryActions as MDataSeqEntryActions, SeqMutableData,
    UnseqEntryAction as MDataUnseqEntryAction, UnseqEntryActions as MDataUnseqEntryActions,
    UnseqMutableData, Value as MDataValue,
};
pub use public_key::{PublicKey, Signature};
pub use request::{Request, Requester};
pub use response::Response;
pub use sha3::Sha3_512 as Ed25519Digest;

use hex_fmt::HexFmt;
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};

/// Permissions for an app stored by the Elders.
#[derive(
    Copy, Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Default, Debug,
)]
pub struct AppPermissions {
    pub transfer_coins: bool,
}

/// Constant byte length of `XorName`.
pub const XOR_NAME_LEN: usize = 32;

/// A [`XOR_NAME_BITS`](constant.XOR_NAME_BITS.html)-bit number, viewed as a point in XOR space.
///
/// This wraps an array of [`XOR_NAME_LEN`](constant.XOR_NAME_LEN.html) bytes, i.e. a number
/// between 0 and 2<sup>`XOR_NAME_BITS`</sup> - 1.
///
/// XOR space is the space of these numbers, with the [XOR metric][1] as a notion of distance,
/// i. e. the points with IDs `x` and `y` are considered to have distance `x xor y`.
///
/// [1]: https://en.wikipedia.org/wiki/Kademlia#System_details
#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct XorName(pub [u8; XOR_NAME_LEN]);

impl Debug for XorName {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:<8}", HexFmt(&self.0))
    }
}

impl Display for XorName {
    #[allow(trivial_casts)]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        (self as &Debug).fmt(formatter)
    }
}

impl Distribution<XorName> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> XorName {
        XorName(rng.gen())
    }
}

/// Wrapper message that contains a message ID and the requester ID along the request or response.
/// It should also contain a valid signature if it's sent by the owner(s).
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Message {
    Request {
        request: Request,
        message_id: MessageId,
        signature: Option<Signature>,
    },
    Response {
        response: Response,
        message_id: MessageId,
    },
}

impl Message {
    pub fn message_id(&self) -> MessageId {
        match self {
            Message::Request { message_id, .. } => *message_id,
            Message::Response { message_id, .. } => *message_id,
        }
    }
}

/// Unique ID for messages
///
/// This is used for deduplication: Since the network sends messages redundantly along different
/// routes, the same message will usually arrive more than once at any given node. A message with
/// an ID that is already in the cache will be ignored.
#[derive(Ord, PartialOrd, Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct MessageId(pub XorName);

impl MessageId {
    /// Generate a new `MessageId` with random content.
    pub fn new() -> MessageId {
        MessageId(rand::random())
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

/// Challenge request/response used to establish new connections and verify the key.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
pub enum Challenge {
    Request(Vec<u8>),
    Response(ClientPublicId, Signature),
}
