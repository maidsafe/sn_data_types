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
    variant_size_differences,
    unused
)]
// FIXME - write docs
#![allow(missing_docs)]

pub mod appendable_data;
pub mod mutable_data;
pub mod request;
pub mod response;

mod coins;
mod errors;
mod identity;
mod immutable_data;
mod public_key;

pub use coins::{Coins, MAX_COINS_VALUE};
pub use errors::{EntryError, Error};
pub use identity::{
    app::FullId as AppFullId, app::PublicId as AppPublicId, client::FullId as ClientFullId,
    client::PublicId as ClientPublicId, node::FullId as NodeFullId, node::PublicId as NodePublicId,
    PublicId,
};
pub use immutable_data::{ImmutableData, UnpubImmutableData, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES};
pub use public_key::{PublicKey, Signature};
pub use sha3::Sha3_512 as Ed25519Digest;

use crate::request::{Request, Requester};
use crate::response::Response;
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

/// Wrapper message that contains a message ID and the requester ID along the
/// request or response. It should also contain a valid signature if it's sent by
/// the owner(s).
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Message {
    Request {
        request: Request,
        message_id: MessageId,
        requester: Requester,
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

// Impl this in SAFE Client Libs if we still need old routing Message IDs:
//
// impl From<OldMessageId> for MessageId {
//     fn from(old_msg_id: OldMessageId) -> Self {
//         MessageId {
//             0: (old_msg_id.0).0,
//         }
//     }
// }
// impl Into<OldMessageId> for MessageId {
//     fn into(self) -> OldMessageId {
//         OldMessageId::from_name_array(self.0)
//     }
// }
