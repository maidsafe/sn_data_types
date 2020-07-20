// Copyright 2020 MaidSafe.net limited.
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

mod coins;
mod errors;
mod identity;
mod immutable_data;
mod keys;
mod mutable_data;
mod request;
mod response;
mod sequence;
mod utils;

pub use coins::Coins;
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
    AuthorisationKind as RequestAuthKind, ClientRequest, CoinsRequest, IDataRequest, LoginPacket,
    LoginPacketRequest, MDataRequest, Request, SDataRequest, Type as RequestType,
    MAX_LOGIN_PACKET_BYTES,
};
pub use response::{Response, TryFromError};
pub use sequence::{
    Action as SDataAction, Address as SDataAddress, Data as SData,
    DataMutationOp as SDataDataMutationOp, Entries as SDataEntries, Entry as SDataEntry,
    Index as SDataIndex, Kind as SDataKind, Permissions as SDataPermissions, Policy as SDataPolicy,
    PrivPermissions as SDataPrivPermissions, PrivPolicy as SDataPrivPolicy, PrivSeqData,
    PubPermissions as SDataPubPermissions, PubPolicy as SDataPubPolicy, PubSeqData,
    User as SDataUser,
};
use serde::{Deserialize, Serialize};
pub use sha3::Sha3_512 as Ed25519Digest;
use std::{fmt::Debug, net::SocketAddr};
pub use utils::verify_signature;
use xor_name::XorName;

/// Object storing a data variant.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    /// ImmutableData.
    Immutable(IData),
    /// MutableData.
    Mutable(MData),
    /// Sequence.
    Sequence(SData),
}

impl Data {
    /// Returns true if published.
    pub fn is_pub(&self) -> bool {
        match *self {
            Self::Immutable(ref idata) => idata.is_pub(),
            Self::Mutable(_) => false,
            Self::Sequence(ref sdata) => sdata.is_pub(),
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

impl From<SData> for Data {
    fn from(data: SData) -> Self {
        Self::Sequence(data)
    }
}

/// Permissions for an app stored by the Client Handlers.
#[derive(
    Copy, Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Default, Debug,
)]
pub struct AppPermissions {
    /// Whether this app has permissions to transfer coins.
    pub transfer_coins: bool,
    /// Whether this app has permissions to perform mutations.
    pub perform_mutations: bool,
    /// Whether this app has permissions to read the coin balance.
    pub get_balance: bool,
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
    /// Notification of a transaction.
    Notification {
        /// Notification.
        notification: Notification,
    },
}

impl Message {
    /// Gets the message ID, if applicable.
    pub fn message_id(&self) -> Option<MessageId> {
        match self {
            Self::Request { message_id, .. } | Self::Response { message_id, .. } => {
                Some(*message_id)
            }
            Self::Notification { .. } => None,
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

/// Transaction ID.
pub type TransactionId = u64; // TODO: Use the trait UUID

/// Coin transaction.
#[derive(Copy, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct Transaction {
    /// Transaction ID.
    pub id: TransactionId,
    /// Amount of coins.
    pub amount: Coins,
}

/// Notification of a transaction.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct Notification(pub Transaction);
