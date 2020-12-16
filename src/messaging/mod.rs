// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod account;
mod auth;
mod blob;
mod cmd;
mod data;
mod duty;
mod map;
mod network;
mod query;
mod sender;
mod sequence;
mod transfer;

pub use self::{
    account::{Account, AccountRead, AccountWrite, MAX_LOGIN_PACKET_BYTES},
    auth::{AuthCmd, AuthQuery},
    blob::{BlobRead, BlobWrite},
    cmd::Cmd,
    data::{DataCmd, DataQuery},
    duty::{AdultDuties, Duty, ElderDuties, NodeDuties},
    map::{MapRead, MapWrite},
    network::{
        NodeCmd, NodeCmdError, NodeDataCmd, NodeDataError, NodeDataQuery, NodeDataQueryResponse,
        NodeEvent, NodeQuery, NodeQueryResponse, NodeRewardError, NodeRewardQuery,
        NodeRewardQueryResponse, NodeSystemCmd, NodeTransferCmd, NodeTransferError,
        NodeTransferQuery, NodeTransferQueryResponse,
    },
    query::Query,
    sender::{Address, MsgSender, TransientElderKey, TransientSectionKey},
    sequence::{SequenceRead, SequenceWrite},
    transfer::{TransferCmd, TransferQuery},
};
use crate::{
    errors::ErrorDebug, utils, AppPermissions, Blob, Error, Map, MapEntries, MapPermissionSet,
    MapValue, MapValues, Money, PublicKey, ReplicaEvent, ReplicaPublicKeySet, Result, Sequence,
    SequenceEntries, SequenceEntry, SequencePermissions, SequencePrivatePolicy,
    SequencePublicPolicy, Signature, TransferAgreementProof, TransferValidated,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    fmt,
};
use xor_name::XorName;

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct MsgEnvelope {
    ///
    pub message: Message,
    /// The source of the message.
    pub origin: MsgSender,
    /// Intermediate actors, so far, on the path of this message.
    /// Every new actor handling this message, would add itself here.
    pub proxies: Vec<MsgSender>, // or maybe enough with just option of `proxy` (leaning heavily towards it now)
}

impl MsgEnvelope {
    /// Gets the message ID.
    pub fn id(&self) -> MessageId {
        self.message.id()
    }

    /// This is not quite good.
    /// It does work for the cases we have,
    /// but it does so without being clearly robust/flexible.
    /// So, needs some improvement..
    pub fn verify(&self) -> Result<bool> {
        let data = if self.proxies.is_empty() {
            utils::serialise(&self.message)?
        } else {
            let mut msg = self.clone();
            let _ = msg.proxies.pop();
            utils::serialise(&msg)?
        };
        let sender = self.most_recent_sender();
        Ok(sender.verify(&data))
    }

    /// The proxy would first sign the MsgEnvelope,
    /// and then call this method to add itself
    /// (public key + the signature) to the envelope.
    pub fn add_proxy(&mut self, proxy: MsgSender) {
        self.proxies.push(proxy);
    }

    ///
    pub fn most_recent_sender(&self) -> &MsgSender {
        match self.proxies.last() {
            None => &self.origin,
            Some(proxy) => proxy,
        }
    }

    ///
    pub fn destination(&self) -> Result<Address> {
        use Address::*;
        use Message::*;
        match &self.message {
            Cmd { cmd, .. } => self.cmd_dst(cmd),
            Query { query, .. } => Ok(Section(query.dst_address())),
            Event { event, .. } => Ok(Client(event.dst_address())), // TODO: needs the correct client address
            QueryResponse { query_origin, .. } => Ok(query_origin.clone()),
            CmdError { cmd_origin, .. } => Ok(cmd_origin.clone()),
            NodeCmd { cmd, .. } => Ok(cmd.dst_address()),
            NodeEvent { event, .. } => Ok(event.dst_address()),
            NodeQuery { query, .. } => Ok(query.dst_address()),
            NodeCmdError { cmd_origin, .. } => Ok(cmd_origin.clone()),
            NodeQueryResponse { query_origin, .. } => Ok(query_origin.clone()),
        }
    }

    fn cmd_dst(&self, cmd: &Cmd) -> Result<Address> {
        use Address::*;
        use Cmd::*;
        match cmd {
            // temporary case, while not impl at `Authenticator`
            Auth(_) => Ok(Section(self.origin.address().xorname())),
            // always to `Payment` section
            Transfer(c) => Ok(Section(c.dst_address())),
            // Data dst (after reaching `Gateway`)
            // is `Payment` and then `Metadata`.
            Data { cmd, payment } => {
                let sender = self.most_recent_sender();
                match sender.address() {
                    // From `Client` to `Gateway`.
                    Client(xorname) => Ok(Section(xorname)),
                    Node(_) => {
                        match sender.duty() {
                            // From `Gateway` to `Payment`.
                            Some(Duty::Elder(ElderDuties::Gateway)) => {
                                Ok(Section(payment.sender().into()))
                            }
                            // From `Payment` to `Metadata`.
                            Some(Duty::Elder(ElderDuties::Payment))
                            | Some(Duty::Elder(ElderDuties::Metadata)) => {
                                Ok(Section(cmd.dst_address()))
                            }
                            // As it reads; simply no such recipient ;)
                            _ => Err(Error::NoSuchRecipient),
                        }
                    }
                    Section(_) => {
                        match sender.duty() {
                            // Accumulated at `Metadata`.
                            // I.e. this means we accumulated a section signature from `Payment` Elders.
                            // (this is done at `Metadata` Elders, and the accumulated section is added to most recent sender)
                            Some(Duty::Elder(ElderDuties::Payment))
                            | Some(Duty::Elder(ElderDuties::Metadata)) => {
                                Ok(Section(cmd.dst_address()))
                            }
                            // As it reads; simply no such recipient ;)
                            _ => Err(Error::NoSuchRecipient),
                        }
                    }
                }
            }
        }
    }
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum Message {
    /// A Cmd is leads to a write / change of state.
    /// We expect them to be successful, and only return a msg
    /// if something went wrong.
    Cmd {
        /// Cmd.
        cmd: Cmd,
        /// Message ID.
        id: MessageId,
    },
    /// Queries is a read-only operation.
    Query {
        /// Query.
        query: Query,
        /// Message ID.
        id: MessageId,
    },
    /// An Event is a fact about something that happened.
    Event {
        /// Request.
        event: Event,
        /// Message ID.
        id: MessageId,
        /// ID of causing cmd.
        correlation_id: MessageId,
    },
    /// The response to a query, containing the query result.
    QueryResponse {
        /// QueryResponse.
        response: QueryResponse,
        /// Message ID.
        id: MessageId,
        /// ID of causing query.
        correlation_id: MessageId,
        /// The sender of the causing query.
        query_origin: Address,
    },
    /// Cmd error.
    CmdError {
        /// The error.
        error: CmdError,
        /// Message ID.
        id: MessageId,
        /// ID of causing cmd.
        correlation_id: MessageId,
        /// The sender of the causing cmd.
        cmd_origin: Address,
    },
    /// Cmds only sent internally in the network.
    NodeCmd {
        /// NodeCmd.
        cmd: NodeCmd,
        /// Message ID.
        id: MessageId,
    },
    /// An error of a NodeCmd.
    NodeCmdError {
        /// The error.
        error: NodeCmdError,
        /// Message ID.
        id: MessageId,
        /// ID of causing cmd.
        correlation_id: MessageId,
        /// The sender of the causing cmd.
        cmd_origin: Address,
    },
    /// Events only sent internally in the network.
    NodeEvent {
        /// Request.
        event: NodeEvent,
        /// Message ID.
        id: MessageId,
        /// ID of causing cmd.
        correlation_id: MessageId,
    },
    /// Queries is a read-only operation.
    NodeQuery {
        /// Query.
        query: NodeQuery,
        /// Message ID.
        id: MessageId,
    },
    /// The response to a query, containing the query result.
    NodeQueryResponse {
        /// QueryResponse.
        response: NodeQueryResponse,
        /// Message ID.
        id: MessageId,
        /// ID of causing query.
        correlation_id: MessageId,
        /// The sender of the causing query.
        query_origin: Address,
    },
}

impl Message {
    /// Gets the message ID.
    pub fn id(&self) -> MessageId {
        match self {
            Self::Cmd { id, .. }
            | Self::Query { id, .. }
            | Self::Event { id, .. }
            | Self::QueryResponse { id, .. }
            | Self::CmdError { id, .. }
            | Self::NodeCmd { id, .. }
            | Self::NodeEvent { id, .. }
            | Self::NodeQuery { id, .. }
            | Self::NodeCmdError { id, .. }
            | Self::NodeQueryResponse { id, .. } => *id,
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
use tiny_keccak::sha3_256;
impl MessageId {
    /// Generates a new `MessageId` with random content.
    pub fn new() -> Self {
        Self(XorName::random())
    }

    /// Generates a new based on provided id.
    pub fn in_response_to(src: &MessageId) -> MessageId {
        let mut hash_bytes = Vec::new();
        let src = src.0;
        hash_bytes.extend_from_slice(&src.0);
        MessageId(XorName(sha3_256(&hash_bytes)))
    }

    /// Generates a new based on provided sources.
    pub fn combine(srcs: Vec<XorName>) -> MessageId {
        let mut hash_bytes = Vec::new();
        for src in srcs.into_iter() {
            hash_bytes.extend_from_slice(&src.0);
        }
        MessageId(XorName(sha3_256(&hash_bytes)))
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum CmdError {
    ///
    Auth(Error), // temporary, while Authenticator is not handling this
    ///
    Data(Error), // DataError enum for better differentiation?
    ///
    Transfer(TransferError),
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum TransferError {
    /// The error of a ValidateTransfer cmd.
    TransferValidation(Error),
    /// The error of a RegisterTransfer cmd.
    TransferRegistration(Error),
}

/// Events from the network that
/// are pushed to the client.
#[allow(clippy::large_enum_variant, clippy::type_complexity)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum Event {
    /// The transfer was validated by a Replica instance.
    TransferValidated {
        /// This is the client id.
        /// A client can fhave any number of accounts.
        client: XorName,
        /// This is the validation of the transfer
        /// requested by the client for an account.
        event: TransferValidated,
    },
    /// An aggregate event created client side
    /// (for upper Client layers) out of a quorum of TransferValidated events.
    /// This is a temporary variant, until
    /// SignatureAccumulation has been broken out
    /// to its own crate, and can be used at client.
    TransferAgreementReached {
        /// This is the client id.
        /// A client can fhave any number of accounts.
        client: XorName,
        /// The accumulated proof.
        proof: TransferAgreementProof,
    },
}

impl Event {
    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> XorName {
        use Event::*;
        match self {
            TransferValidated { client, .. } => *client,
            TransferAgreementReached { client, .. } => *client,
        }
    }
}

/// Query responses from the network.
#[allow(clippy::large_enum_variant, clippy::type_complexity)]
#[derive(Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum QueryResponse {
    //
    // ===== Blob =====
    //
    /// Get Blob.
    GetBlob(Result<Blob>),
    //
    // ===== Map =====
    //
    /// Get Map.
    GetMap(Result<Map>),
    /// Get Map shell.
    GetMapShell(Result<Map>),
    /// Get Map version.
    GetMapVersion(Result<u64>),
    /// List all Map entries (key-value pairs).
    ListMapEntries(Result<MapEntries>),
    /// List all Map keys.
    ListMapKeys(Result<BTreeSet<Vec<u8>>>),
    /// List all Map values.
    ListMapValues(Result<MapValues>),
    /// Get Map permissions for a user.
    ListMapUserPermissions(Result<MapPermissionSet>),
    /// List all Map permissions.
    ListMapPermissions(Result<BTreeMap<PublicKey, MapPermissionSet>>),
    /// Get Map value.
    GetMapValue(Result<MapValue>),
    //
    // ===== Sequence Data =====
    //
    /// Get Sequence.
    GetSequence(Result<Sequence>),
    /// Get Sequence owners.
    GetSequenceOwner(Result<PublicKey>),
    /// Get Sequence entries from a range.
    GetSequenceRange(Result<SequenceEntries>),
    /// Get Sequence last entry.
    GetSequenceLastEntry(Result<(u64, SequenceEntry)>),
    /// Get public Sequence permissions for a user.
    GetSequencePublicPolicy(Result<SequencePublicPolicy>),
    /// Get private Sequence permissions for a user.
    GetSequencePrivatePolicy(Result<SequencePrivatePolicy>),
    /// Get Sequence permissions for a user.
    GetSequenceUserPermissions(Result<SequencePermissions>),
    //
    // ===== Money =====
    //
    /// Get replica keys
    GetReplicaKeys(Result<ReplicaPublicKeySet>),
    /// Get key balance.
    GetBalance(Result<Money>),
    /// Get key transfer history.
    GetHistory(Result<Vec<ReplicaEvent>>),
    /// Get Store Cost.
    GetStoreCost(Result<Money>),
    //
    // ===== Account =====
    //
    /// Get an encrypted account.
    GetAccount(Result<(Vec<u8>, Signature)>),
    //
    // ===== Client auth =====
    //
    /// Get a list of authorised keys and the version of the auth keys container from Elders.
    ListAuthKeysAndVersion(Result<(BTreeMap<PublicKey, AppPermissions>, u64)>),
}

/// The kind of authorisation needed for a request.
pub enum AuthorisationKind {
    /// Authorisation for data requests.
    Data(DataAuthKind),
    /// Authorisation for money requests.
    Money(MoneyAuthKind),
    /// Miscellaneous authorisation kinds.
    /// NB: Not very well categorized yet
    Misc(MiscAuthKind),
    /// When none required.
    None,
}

/// Authorisation for data requests.
pub enum DataAuthKind {
    /// Read of public data.
    PublicRead,
    /// Read of private data.
    PrivateRead,
    /// Write of data/metadata.
    Write,
}

/// Authorisation for money requests.
pub enum MoneyAuthKind {
    /// Request to get key balance.
    ReadBalance,
    /// Request to get key transfer history.
    ReadHistory,
    /// Request to transfer money from key.
    Transfer,
}

/// Miscellaneous authorisation kinds.
/// NB: Not very well categorized yet
pub enum MiscAuthKind {
    /// Request to manage app keys.
    ManageAppKeys,
    /// Request to mutate and transfer money from key.
    WriteAndTransfer,
}

/// Error type for an attempted conversion from `QueryResponse` to a type implementing
/// `TryFrom<Response>`.
#[derive(Debug, PartialEq)]
pub enum TryFromError {
    /// Wrong variant found in `QueryResponse`.
    WrongType,
    /// The `QueryResponse` contained an error.
    Response(Error),
}

macro_rules! try_from {
    ($ok_type:ty, $($variant:ident),*) => {
        impl TryFrom<QueryResponse> for $ok_type {
            type Error = TryFromError;
            fn try_from(response: QueryResponse) -> std::result::Result<Self, Self::Error> {
                match response {
                    $(
                        QueryResponse::$variant(Ok(data)) => Ok(data),
                        QueryResponse::$variant(Err(error)) => Err(TryFromError::Response(error)),
                    )*
                    _ => Err(TryFromError::WrongType),
                }
            }
        }
    };
}

try_from!(Blob, GetBlob);
try_from!(Map, GetMap, GetMapShell);
try_from!(u64, GetMapVersion);
try_from!(MapEntries, ListMapEntries);
try_from!(BTreeSet<Vec<u8>>, ListMapKeys);
try_from!(MapValues, ListMapValues);
try_from!(MapPermissionSet, ListMapUserPermissions);
try_from!(BTreeMap<PublicKey, MapPermissionSet>, ListMapPermissions);
try_from!(MapValue, GetMapValue);
try_from!(Sequence, GetSequence);
try_from!(PublicKey, GetSequenceOwner);
try_from!(SequenceEntries, GetSequenceRange);
try_from!((u64, SequenceEntry), GetSequenceLastEntry);
try_from!(SequencePublicPolicy, GetSequencePublicPolicy);
try_from!(SequencePrivatePolicy, GetSequencePrivatePolicy);
try_from!(SequencePermissions, GetSequenceUserPermissions);
try_from!(Money, GetBalance);
try_from!(ReplicaPublicKeySet, GetReplicaKeys);
try_from!(Vec<ReplicaEvent>, GetHistory);
try_from!(
    (BTreeMap<PublicKey, AppPermissions>, u64),
    ListAuthKeysAndVersion
);
try_from!((Vec<u8>, Signature), GetAccount);

impl fmt::Debug for QueryResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use QueryResponse::*;

        match self {
            // Blob
            GetBlob(res) => write!(f, "QueryResponse::GetBlob({:?})", ErrorDebug(res)),
            // Map
            GetMap(res) => write!(f, "QueryResponse::GetMap({:?})", ErrorDebug(res)),
            GetMapShell(res) => write!(f, "QueryResponse::GetMapShell({:?})", ErrorDebug(res)),
            GetMapVersion(res) => write!(f, "QueryResponse::GetMapVersion({:?})", ErrorDebug(res)),
            ListMapEntries(res) => {
                write!(f, "QueryResponse::ListMapEntries({:?})", ErrorDebug(res))
            }
            ListMapKeys(res) => write!(f, "QueryResponse::ListMapKeys({:?})", ErrorDebug(res)),
            ListMapValues(res) => write!(f, "QueryResponse::ListMapValues({:?})", ErrorDebug(res)),
            ListMapPermissions(res) => write!(
                f,
                "QueryResponse::ListMapPermissions({:?})",
                ErrorDebug(res)
            ),
            ListMapUserPermissions(res) => write!(
                f,
                "QueryResponse::ListMapUserPermissions({:?})",
                ErrorDebug(res)
            ),
            GetMapValue(res) => write!(f, "QueryResponse::GetMapValue({:?})", ErrorDebug(res)),
            // Sequence
            GetSequence(res) => write!(f, "QueryResponse::GetSequence({:?})", ErrorDebug(res)),
            GetSequenceRange(res) => {
                write!(f, "QueryResponse::GetSequenceRange({:?})", ErrorDebug(res))
            }
            GetSequenceLastEntry(res) => write!(
                f,
                "QueryResponse::GetSequenceLastEntry({:?})",
                ErrorDebug(res)
            ),
            GetSequenceUserPermissions(res) => write!(
                f,
                "QueryResponse::GetSequenceUserPermissions({:?})",
                ErrorDebug(res)
            ),
            GetSequencePublicPolicy(res) => write!(
                f,
                "QueryResponse::GetSequencePublicPolicy({:?})",
                ErrorDebug(res)
            ),
            GetSequencePrivatePolicy(res) => write!(
                f,
                "QueryResponse::GetSequencePrivatePolicy({:?})",
                ErrorDebug(res)
            ),
            GetSequenceOwner(res) => {
                write!(f, "QueryResponse::GetSequenceOwner({:?})", ErrorDebug(res))
            }
            // Money
            GetReplicaKeys(res) => {
                write!(f, "QueryResponse::GetReplicaKeys({:?})", ErrorDebug(res))
            }
            GetBalance(res) => write!(f, "QueryResponse::GetBalance({:?})", ErrorDebug(res)),
            GetHistory(res) => write!(f, "QueryResponse::GetHistory({:?})", ErrorDebug(res)),
            GetStoreCost(res) => write!(f, "QueryResponse::GetStoreCost({:?})", ErrorDebug(res)),
            // Account
            GetAccount(res) => write!(f, "QueryResponse::GetAccount({:?})", ErrorDebug(res)),
            // Client Auth
            ListAuthKeysAndVersion(res) => write!(
                f,
                "QueryResponse::ListAuthKeysAndVersion({:?})",
                ErrorDebug(res)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PublicBlob, Result, UnseqMap};
    use std::convert::{TryFrom, TryInto};

    #[test]
    fn debug_format() {
        use crate::Error;
        let errored_response = QueryResponse::GetSequence(Err(Error::AccessDenied));
        assert_eq!(
            format!("{:?}", errored_response),
            "QueryResponse::GetSequence(AccessDenied)"
        );
    }

    #[test]
    fn try_from() -> Result<()> {
        use QueryResponse::*;

        let i_data = Blob::Public(PublicBlob::new(vec![1, 3, 1, 4]));
        let e = Error::AccessDenied;
        assert_eq!(
            i_data,
            GetBlob(Ok(i_data.clone()))
                .try_into()
                .map_err(|_| Error::Unexpected("Mismatched types".to_string()))?
        );
        assert_eq!(
            Err(TryFromError::Response(e.clone())),
            Blob::try_from(GetBlob(Err(e.clone())))
        );

        let mut data = BTreeMap::new();
        let _ = data.insert(vec![1], vec![10]);
        let owners = PublicKey::Bls(threshold_crypto::SecretKey::random().public_key());
        let m_data = Map::Unseq(UnseqMap::new_with_data(
            *i_data.name(),
            1,
            data,
            BTreeMap::new(),
            owners,
        ));
        assert_eq!(
            m_data,
            GetMap(Ok(m_data.clone()))
                .try_into()
                .map_err(|_| Error::Unexpected("Mismatched types".to_string()))?
        );
        assert_eq!(
            Err(TryFromError::Response(e.clone())),
            Map::try_from(GetMap(Err(e)))
        );
        Ok(())
    }
}
