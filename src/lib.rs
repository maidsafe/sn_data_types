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

mod coins;
mod errors;
mod identity;
mod immutable_data;
mod mutable_data;
mod public_key;
mod request;
mod response;
mod sequence;
mod shared_data;
mod transaction;
mod utils;

pub use coins::{Coins, MAX_COINS_VALUE};
pub use errors::{EntryError, Error, Result};
pub use identity::{
    app::{FullId as AppFullId, PublicId as AppPublicId},
    client::{FullId as ClientFullId, PublicId as ClientPublicId},
    node::{FullId as NodeFullId, PublicId as NodePublicId},
    PublicId,
};
pub use immutable_data::{
    Address as IDataAddress, Data as IData, Kind as IDataKind, PubImmutableData,
    UnpubImmutableData, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES,
};
pub use mutable_data::{
    Action as MDataAction, Address as MDataAddress, Data as MData, Entries as MDataEntries,
    EntryActions as MDataEntryActions, Kind as MDataKind, PermissionSet as MDataPermissionSet,
    SeqEntries as MDataSeqEntries, SeqEntryAction as MDataSeqEntryAction,
    SeqEntryActions as MDataSeqEntryActions, SeqMutableData, SeqValue as MDataSeqValue,
    UnseqEntries as MDataUnseqEntries, UnseqEntryAction as MDataUnseqEntryAction,
    UnseqEntryActions as MDataUnseqEntryActions, UnseqMutableData, UnseqValue as MDataUnseqValue,
    Value as MDataValue, Values as MDataValues,
};
pub use public_key::{PublicKey, Signature};
pub use request::{LoginPacket, Request, MAX_LOGIN_PACKET_BYTES};
pub use response::Response;
pub use sequence::{
    AppendOperation as ADataAppend, Data as AData, Entries as ADataEntries, Entry as ADataEntry,
    PrivateSentriedSequence, PrivateSequence, PublicSentriedSequence, PublicSequence, Sequence,
    SequencePermissions as ADataPermissions,
};
pub use sha3::Sha3_512 as Ed25519Digest;
pub use shared_data::{
    Action as ADataAction, Address, ExpectedIndices, Index, Kind, Owner, PrivatePermissionSet,
    PrivatePermissions, PublicPermissionSet, PublicPermissions, User,
};
pub use transaction::{Transaction, TransactionId};
pub use utils::verify_signature;

use hex_fmt::HexFmt;
use multibase::Decodable;
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    Immutable(IData),
    Mutable(MData),
    AppendOnly(AData),
}

impl Data {
    pub fn is_public(&self) -> bool {
        match *self {
            Data::Immutable(ref idata) => idata.is_pub(),
            Data::Mutable(_) => false,
            Data::AppendOnly(ref adata) => adata.is_public(),
        }
    }

    pub fn is_unpub(&self) -> bool {
        !self.is_public()
    }
}

impl From<IData> for Data {
    fn from(data: IData) -> Self {
        Data::Immutable(data)
    }
}

impl From<MData> for Data {
    fn from(data: MData) -> Self {
        Data::Mutable(data)
    }
}

impl From<AData> for Data {
    fn from(data: AData) -> Self {
        Data::AppendOnly(data)
    }
}

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

impl XorName {
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    pub fn decode_from_zbase32<I: Decodable>(encoded: I) -> Result<Self> {
        utils::decode(encoded)
    }
}

impl Debug for XorName {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:<8}", HexFmt(&self.0))
    }
}

impl Display for XorName {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, formatter)
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
    Notification {
        notification: Notification,
    },
}

impl Message {
    pub fn message_id(&self) -> Option<MessageId> {
        match self {
            Message::Request { message_id, .. } => Some(*message_id),
            Message::Response { message_id, .. } => Some(*message_id),
            Message::Notification { .. } => None,
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
    Request(PublicId, Vec<u8>),
    Response(PublicId, Signature),
}

/// Notification of a transaction.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct Notification(pub Transaction);

#[cfg(test)]
mod test {
    use crate::XorName;
    use unwrap::unwrap;

    #[test]
    fn zbase32_encode_decode_xorname() {
        let name = XorName(rand::random());
        let encoded = name.encode_to_zbase32();
        let decoded = unwrap!(XorName::decode_from_zbase32(&encoded));
        assert_eq!(name, decoded);
    }
}
