// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! SAFE network data types.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help`.
#![forbid(unsafe_code)]
#![warn(
    // TODO: add missing debug implementations for structs?
    // missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

mod append_only_data;
mod errors;
mod identity;
mod immutable_data;
mod keys;
mod money;
mod mutable_data;
mod request;
mod response;
mod transfer;
mod utils;

pub use append_only_data::{
    Action as ADataAction, Address as ADataAddress, AppendOnlyData,
    AppendOperation as ADataAppendOperation, Data as AData, Entries as ADataEntries,
    Entry as ADataEntry, Index as ADataIndex, Indices as ADataIndices, Kind as ADataKind,
    Owner as ADataOwner, Permissions as ADataPermissions,
    PubPermissionSet as ADataPubPermissionSet, PubPermissions as ADataPubPermissions,
    PubSeqData as PubSeqAppendOnlyData, PubUnseqData as PubUnseqAppendOnlyData, SeqAppendOnly,
    UnpubPermissionSet as ADataUnpubPermissionSet, UnpubPermissions as ADataUnpubPermissions,
    UnpubSeqData as UnpubSeqAppendOnlyData, UnpubUnseqData as UnpubUnseqAppendOnlyData,
    UnseqAppendOnly, User as ADataUser,
};
pub use errors::{EntryError, Error, Result};
pub use identity::{
    app::{FullId as AppFullId, PublicId as AppPublicId},
    client::{FullId as ClientFullId, PublicId as ClientPublicId},
    node::{FullId as NodeFullId, PublicId as NodePublicId},
    PublicId,
};
pub use immutable_data::{
    Address as IDataAddress, Data as IData, Kind as IDataKind, PubData as PubImmutableData,
    UnpubData as UnpubImmutableData, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES,
};
pub use keys::{BlsKeypair, BlsKeypairShare, Keypair, PublicKey, Signature};
pub use money::Money;
pub use mutable_data::{
    Action as MDataAction, Address as MDataAddress, Data as MData, Entries as MDataEntries,
    EntryActions as MDataEntryActions, Kind as MDataKind, PermissionSet as MDataPermissionSet,
    SeqData as SeqMutableData, SeqEntries as MDataSeqEntries,
    SeqEntryAction as MDataSeqEntryAction, SeqEntryActions as MDataSeqEntryActions,
    SeqValue as MDataSeqValue, UnseqData as UnseqMutableData, UnseqEntries as MDataUnseqEntries,
    UnseqEntryAction as MDataUnseqEntryAction, UnseqEntryActions as MDataUnseqEntryActions,
    Value as MDataValue, Values as MDataValues,
};
pub use request::{
    ADataRequest, AuthorisationKind as RequestAuthKind, ClientRequest, IDataRequest, LoginPacket,
    LoginPacketRequest, MDataRequest, MoneyRequest, Request, Type as RequestType,
    MAX_LOGIN_PACKET_BYTES,
};
pub use response::{Response, TryFromError};
pub use sha3::Sha3_512 as Ed25519Digest;
pub use transfer::*;
pub use utils::verify_signature;

use hex_fmt::HexFmt;
use multibase::Decodable;
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Debug, Display, Formatter},
    net::SocketAddr,
};

/// Object storing a data variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    /// ImmutableData.
    Immutable(IData),
    /// MutableData.
    Mutable(MData),
    /// AppendOnlyData.
    AppendOnly(AData),
}

impl Data {
    /// Returns true if published.
    pub fn is_pub(&self) -> bool {
        match *self {
            Self::Immutable(ref idata) => idata.is_pub(),
            Self::Mutable(_) => false,
            Self::AppendOnly(ref adata) => adata.is_pub(),
        }
    }

    /// Returns true if unpublished.
    pub fn is_unpub(&self) -> bool {
        !self.is_pub()
    }
}

impl From<IData> for Data {
    fn from(data: IData) -> Self {
        Self::Immutable(data)
    }
}

impl From<MData> for Data {
    fn from(data: MData) -> Self {
        Self::Mutable(data)
    }
}

impl From<AData> for Data {
    fn from(data: AData) -> Self {
        Self::AppendOnly(data)
    }
}

/// Permissions for an app stored by the Client Handlers.
#[derive(
    Copy, Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Default, Debug,
)]
pub struct AppPermissions {
    /// Whether this app has permissions to perform data mutations.
    pub data_mutations: bool,
    /// Whether this app has permissions to transfer money.
    pub transfer_money: bool,
    /// Whether this app has permissions to read the account balance.
    pub read_balance: bool,
    /// Whether this app has permissions to read the account transfer history.
    pub read_transfer_history: bool,
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
    /// Returns the `XorName` serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Creates from z-base-32 encoded string.
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
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Request with the message ID.
    Request {
        /// Request.
        request: Request,
        /// Associated message ID.
        message_id: MessageId,
        /// Signature of `(request, message_id)`. Optional if the request is read-only.
        signature: Option<Signature>,
    },
    /// Response matched to the message ID.
    Response {
        /// Response.
        response: Response,
        /// Associated message ID.
        message_id: MessageId,
    },
    /// Notification of a transfer.
    TransferNotification {
        /// Notification.
        payload: TransferNotification,
    },
}

impl Message {
    /// Gets the message ID, if applicable.
    pub fn message_id(&self) -> Option<MessageId> {
        match self {
            Self::Request { message_id, .. } | Self::Response { message_id, .. } => {
                Some(*message_id)
            }
            Self::TransferNotification { .. } => None,
        }
    }
}

/// Unique ID for messages.
///
/// This is used for deduplication: Since the network sends messages redundantly along different
/// routes, the same message will usually arrive more than once at any given node. A message with
/// an ID that is already in the cache will be ignored.
#[derive(Ord, PartialOrd, Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct MessageId(pub XorName);

impl MessageId {
    /// Generates a new `MessageId` with random content.
    pub fn new() -> Self {
        Self(rand::random())
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

/// Handshake requests sent from clients to vaults to establish new connections and verify a client's
/// key (to prevent replay attacks).
#[derive(Serialize, Deserialize)]
pub enum HandshakeRequest {
    /// Sent by clients as an initial bootstrap request, and then for subsequent bootstrap attempts.
    Bootstrap(PublicId),
    /// Sent to destination nodes as a response to `HandshakeResponse::Join`.
    Join(PublicId),
    /// Response to `HandshakeResponse::Challenge` sent by a vault.
    ChallengeResult(Signature),
}

/// Handshake responses sent from vaults to clients.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
pub enum HandshakeResponse {
    /// Sent by nodes when a client should attempt to connect to the section that's closest to
    /// its destination (section managing the client's account).
    Rebootstrap(Vec<(XorName, SocketAddr)>),
    /// Sent by nodes when a client reaches its destination section.
    Join(Vec<(XorName, SocketAddr)>),
    /// Sent by nodes as a response to a valid `HandshakeRequest::Join`.
    Challenge(PublicId, Vec<u8>),
    /// Sent by nodes as a response to an invalid `HandshakeRequest::Join` (when a client attempts to join a wrong section).
    InvalidSection,
}

#[cfg(test)]
mod tests {
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
