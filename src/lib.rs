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

mod blob;
mod errors;
mod identity;
mod keys;
mod map;
mod messaging;
mod money;
mod rewards;
mod sequence;
mod transfer;
mod utils;

pub use blob::{
    Address as BlobAddress, Data as Blob, Kind as BlobKind, PrivateData as PrivateBlob,
    PublicData as PublicBlob, MAX_BLOB_SIZE_IN_BYTES,
};
pub use errors::{EntryError, Error, Result};
pub use identity::{
    client::{FullId as ClientFullId, PublicId as ClientPublicId},
    node::{FullId as NodeFullId, NodeKeypairs, PublicId as NodePublicId},
    PublicId,
};
pub use keys::{
    BlsKeypair, BlsKeypairShare, BlsProof, BlsProofShare, Ed25519Proof, Keypair, Proof, Proven,
    PublicKey, Signature, SignatureShare,
};
pub use map::{
    Action as MapAction, Address as MapAddress, Data as Map, Entries as MapEntries,
    EntryActions as MapEntryActions, Kind as MapKind, PermissionSet as MapPermissionSet,
    SeqData as SeqMap, SeqEntries as MapSeqEntries, SeqEntryAction as MapSeqEntryAction,
    SeqEntryActions as MapSeqEntryActions, SeqValue as MapSeqValue, UnseqData as UnseqMap,
    UnseqEntries as MapUnseqEntries, UnseqEntryAction as MapUnseqEntryAction,
    UnseqEntryActions as MapUnseqEntryActions, Value as MapValue, Values as MapValues,
};
pub use messaging::{
    Account, AccountRead, AccountWrite, Address, AdultDuties, AuthCmd, AuthQuery,
    AuthorisationKind, BlobRead, BlobWrite, Cmd, CmdError, DataAuthKind, DataCmd, DataQuery, Duty,
    ElderDuties, Event, MapRead, MapWrite, Message, MessageId, MiscAuthKind, MoneyAuthKind,
    MsgEnvelope, MsgSender, NodeCmd, NodeCmdError, NodeDataCmd, NodeDataError, NodeDataQuery,
    NodeDataQueryResponse, NodeDuties, NodeEvent, NodeQuery, NodeQueryResponse, NodeRewardError,
    NodeRewardQuery, NodeRewardQueryResponse, NodeSystemCmd, NodeTransferCmd, NodeTransferError,
    NodeTransferQuery, NodeTransferQueryResponse, Query, QueryResponse, SequenceRead,
    SequenceWrite, TransferCmd, TransferError, TransferQuery, TryFromError, MAX_LOGIN_PACKET_BYTES,
};
pub use money::Money;
pub use rewards::{RewardCounter, Work};

pub use sequence::{
    Action as SequenceAction, Address as SequenceAddress, Data as Sequence,
    Entries as SequenceEntries, Entry as SequenceEntry, Index as SequenceIndex,
    Indices as SequenceIndices, Kind as SequenceKind, Owner as SequenceOwner,
    Permissions as SequencePermissions, PrivSeqData,
    PrivUserPermissions as SequencePrivUserPermissions,
    PrivatePermissions as SequencePrivatePermissions, PubSeqData,
    PubUserPermissions as SequencePubUserPermissions,
    PublicPermissions as SequencePublicPermissions, User as SequenceUser,
    UserPermissions as SequenceUserPermissions, WriteOp as SequenceWriteOp,
};
pub use sha3::Sha3_512 as Ed25519Digest;
pub use transfer::*;
pub use utils::verify_signature;

use serde::{Deserialize, Serialize};
use std::{fmt::Debug, net::SocketAddr};
use xor_name::XorName;

/// Object storing a data variant.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    /// Blob.
    Immutable(Blob),
    /// MutableData.
    Mutable(Map),
    /// Sequence.
    Sequence(Sequence),
}

impl Data {
    /// Returns true if published.
    pub fn is_pub(&self) -> bool {
        match *self {
            Self::Immutable(ref idata) => idata.is_pub(),
            Self::Mutable(_) => false,
            Self::Sequence(ref sequence) => sequence.is_pub(),
        }
    }

    /// Returns true if unpublished.
    pub fn is_unpub(&self) -> bool {
        !self.is_pub()
    }
}

impl From<Blob> for Data {
    fn from(data: Blob) -> Self {
        Self::Immutable(data)
    }
}

impl From<Map> for Data {
    fn from(data: Map) -> Self {
        Self::Mutable(data)
    }
}

impl From<Sequence> for Data {
    fn from(data: Sequence) -> Self {
        Self::Sequence(data)
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

/// Handshake requests sent from clients to vaults to establish new connections and verify a client's
/// key (to prevent replay attacks).
#[derive(Serialize, Deserialize)]
pub enum HandshakeRequest {
    /// Sent by clients as an initial bootstrap request, and then for subsequent bootstrap attempts.
    Bootstrap(PublicKey),
    /// Sent to destination nodes as a response to `HandshakeResponse::Join`.
    Join(PublicKey),
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
    Challenge(PublicKey, Vec<u8>),
    /// Sent by nodes as a response to an invalid `HandshakeRequest::Join` (when a client attempts to join a wrong section).
    InvalidSection,
}
