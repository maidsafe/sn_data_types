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
mod sequence;
mod transfer;

pub use self::{
    account::{Account, AccountRead, AccountWrite, MAX_LOGIN_PACKET_BYTES},
    auth::{AuthCmd, AuthQuery},
    blob::{BlobRead, BlobWrite},
    cmd::Cmd,
    data::{DataCmd, DataQuery},
    duty::{AdultDuty, Duty, ElderDuty},
    map::{MapRead, MapWrite},
    network::*,
    query::Query,
    sequence::{SequenceRead, SequenceWrite},
    transfer::{TransferCmd, TransferQuery},
};
use crate::{
    errors::ErrorDebug, AppPermissions, Blob, DebitAgreementProof, Error, Map, MapEntries,
    MapPermissionSet, MapValue, MapValues, Money, PublicKey, ReplicaEvent, ReplicaPublicKeySet,
    Result, Sequence, SequenceEntries, SequenceEntry, SequenceOwner, SequencePermissions,
    SequenceUserPermissions, Signature, TransferValidated, XorName,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    fmt,
};

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct MsgEnvelope {
    ///
    pub message: Message,
    /// The source of the message.
    pub origin: MsgSender,
    /// Intermediate actors, so far, on the path of this message.
    /// Every new actor handling this message, would add itself here.
    pub proxies: Vec<MsgSender>, // or maybe enough with just `proxy`
}

impl MsgEnvelope {
    /// Gets the message ID.
    pub fn id(&self) -> MessageId {
        self.message.id()
    }

    /// The proxy would first sign the MsgEnvelope,
    /// and then call this method to add itself
    /// (public key + the signature) to the envelope.
    pub fn with_proxy(&self, proxy: MsgSender) -> MsgEnvelope {
        let mut clone = self.clone();
        clone.proxies.push(proxy);
        clone
    }

    ///
    pub fn most_recent_sender(&self) -> &MsgSender {
        match self.proxies.last() {
            None => &self.origin,
            Some(proxy) => proxy,
        }
    }

    /// TODO
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        AuthorisationKind::None

        // use Address::*;
        // use Message::*;
        // match &self.message {
        //     Cmd { cmd, .. } => self.cmd_dst(cmd),
        //     Query { query, .. } => Section(query.authorisation_kind()),
        //     Event { event, .. } => Client(event.authorisation_kind()),
        //     QueryResponse { query_origin, .. } => query_origin.clone(),
        //     CmdError { cmd_origin, .. } => cmd_origin.clone(),
        //     NetworkCmd { cmd, .. } => cmd.authorisation_kind(),
        //     NetworkEvent { event, .. } => event.authorisation_kind(),
        //     NetworkQuery { query, .. } => query.authorisation_kind(),
        //     NetworkCmdError { cmd_origin, .. } => cmd_origin.clone(),
        //     NetworkQueryResponse { query_origin, .. } => query_origin.clone(),
        // }
    }

    ///
    pub fn destination(&self) -> Address {
        use Address::*;
        use Message::*;
        match &self.message {
            Cmd { cmd, .. } => self.cmd_dst(cmd),
            Query { query, .. } => Section(query.dst_address()),
            Event { event, .. } => Client(event.dst_address()), // TODO: needs the correct client address
            QueryResponse { query_origin, .. } => query_origin.clone(),
            CmdError { cmd_origin, .. } => cmd_origin.clone(),
            NetworkCmd { cmd, .. } => cmd.dst_address(),
            NetworkEvent { event, .. } => event.dst_address(),
            NetworkQuery { query, .. } => query.dst_address(),
            NetworkCmdError { cmd_origin, .. } => cmd_origin.clone(),
            NetworkQueryResponse { query_origin, .. } => query_origin.clone(),
        }
    }

    fn cmd_dst(&self, cmd: &Cmd) -> Address {
        use Address::*;
        use Cmd::*;
        match cmd {
            // temporary case, while not impl at `Authenticator`
            Auth(_) => Section((*self.origin.id()).into()),
            // always to `Payment` section
            Transfer(c) => Section(c.dst_address()),
            // Data dst (after reaching `Gateway`)
            // is `Payment` and then `Metadata`.
            Data { cmd, payment } => {
                match self.most_recent_sender() {
                    // From `Client` to `Gateway`.
                    MsgSender::Client { .. } => Section((*self.origin.id()).into()),
                    // From `Gateway` to `Payment`.
                    MsgSender::Node {
                        duty: Duty::Elder(ElderDuty::Gateway),
                        ..
                    } => Section(payment.from().into()),
                    // From `Payment` to `Metadata`.
                    MsgSender::Node {
                        duty: Duty::Elder(ElderDuty::Payment),
                        ..
                    } => Section(cmd.dst_address()),
                    // Accumulated at `Metadata`.
                    // I.e. this means we accumulated a section signature from `Payment` Elders.
                    // (this is done at `Metadata` Elders, and the accumulated section is added to most recent sender)
                    MsgSender::Section {
                        duty: Duty::Elder(ElderDuty::Payment),
                        ..
                    } => Section(cmd.dst_address()),
                    _ => {
                        // this should not be a valid case
                        // just putting a default address here for now
                        // (pointing at `Gateway` seems best)
                        Section((*self.origin.id()).into())
                    }
                }
            }
        }
    }
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum MsgSender {
    ///
    Client {
        ///
        id: PublicKey,
        ///
        signature: Signature,
    },
    ///
    Node {
        ///
        id: PublicKey,
        ///
        duty: Duty,
        ///
        signature: Signature,
    },
    ///
    Section {
        ///
        id: PublicKey,
        ///
        duty: Duty,
        ///
        signature: Signature,
    },
}

impl MsgSender {
    ///
    pub fn id(&self) -> &PublicKey {
        use MsgSender::*;
        match self {
            Client { id, .. } | Node { id, .. } | Section { id, .. } => id,
        }
    }
    ///
    pub fn address(&self) -> Address {
        use MsgSender::*;
        match self {
            Client { id, .. } => Address::Client((*id).into()),
            Node { id, .. } => Address::Node((*id).into()),
            Section { id, .. } => Address::Section((*id).into()),
        }
    }
    ///
    pub fn signature(&self) -> &Signature {
        use MsgSender::*;
        match self {
            Client { signature, .. } | Node { signature, .. } | Section { signature, .. } => {
                signature
            }
        }
    }
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum Address {
    ///
    Client(XorName),
    ///
    Node(XorName),
    ///
    Section(XorName),
}

impl Address {
    /// Extracts the underlying XorName.
    pub fn xorname(&self) -> XorName {
        use Address::*;
        match self {
            Client(xorname) | Node(xorname) | Section(xorname) => *xorname,
        }
    }
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
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
    NetworkCmd {
        /// NetworkCmd.
        cmd: NetworkCmd,
        /// Message ID.
        id: MessageId,
    },
    /// An error of a NetworkCmd.
    NetworkCmdError {
        /// The error.
        error: NetworkCmdError,
        /// Message ID.
        id: MessageId,
        /// ID of causing cmd.
        correlation_id: MessageId,
        /// The sender of the causing cmd.
        cmd_origin: Address,
    },
    /// Events only sent internally in the network.
    NetworkEvent {
        /// Request.
        event: NetworkEvent,
        /// Message ID.
        id: MessageId,
        /// ID of causing cmd.
        correlation_id: MessageId,
    },
    /// Queries is a read-only operation.
    NetworkQuery {
        /// Query.
        query: NetworkQuery,
        /// Message ID.
        id: MessageId,
    },
    /// The response to a query, containing the query result.
    NetworkQueryResponse {
        /// QueryResponse.
        response: NetworkQueryResponse,
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
            | Self::NetworkCmd { id, .. }
            | Self::NetworkEvent { id, .. }
            | Self::NetworkQuery { id, .. }
            | Self::NetworkCmdError { id, .. }
            | Self::NetworkQueryResponse { id, .. } => *id,
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
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
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
    TransferDebitAgreementReached {
        /// This is the client id.
        /// A client can fhave any number of accounts.
        client: XorName,
        /// The accumulated proof.
        proof: DebitAgreementProof,
    },
}

impl Event {
    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> XorName {
        use Event::*;
        match self {
            TransferValidated { client, .. } => *client,
            TransferDebitAgreementReached { client, .. } => *client,
        }
    }
}

/// Query responses from the network.
#[allow(clippy::large_enum_variant, clippy::type_complexity)]
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
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
    GetSequenceOwner(Result<SequenceOwner>),
    /// Get Sequence entries from a range.
    GetSequenceRange(Result<SequenceEntries>),
    /// Get Sequence last entry.
    GetSequenceLastEntry(Result<(u64, SequenceEntry)>),
    /// List all Sequence permissions at the provided index.
    GetSequencePermissions(Result<SequencePermissions>),
    /// Get Sequence permissions for a user.
    GetSequenceUserPermissions(Result<SequenceUserPermissions>),
    //
    // ===== Money =====
    //
    /// Get replica keys
    GetReplicaKeys(Result<ReplicaPublicKeySet>),
    /// Get key balance.
    GetBalance(Result<Money>),
    /// Get key transfer history.
    GetHistory(Result<Vec<ReplicaEvent>>),
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
try_from!(SequenceOwner, GetSequenceOwner);
try_from!(SequenceEntries, GetSequenceRange);
try_from!((u64, SequenceEntry), GetSequenceLastEntry);
try_from!(SequencePermissions, GetSequencePermissions);
try_from!(SequenceUserPermissions, GetSequenceUserPermissions);
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
            GetSequencePermissions(res) => write!(
                f,
                "QueryResponse::GetSequencePermissions({:?})",
                ErrorDebug(res)
            ),
            GetSequenceUserPermissions(res) => write!(
                f,
                "QueryResponse::GetSequenceUserPermissions({:?})",
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
    use crate::{PubBlob as PublicBlob, UnseqMutableData};
    use std::convert::{TryFrom, TryInto};
    use unwrap::{unwrap, unwrap_err};

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
    fn try_from() {
        use QueryResponse::*;

        let i_data = Blob::Public(PublicBlob::new(vec![1, 3, 1, 4]));
        let e = Error::AccessDenied;
        assert_eq!(i_data, unwrap!(GetBlob(Ok(i_data.clone())).try_into()));
        assert_eq!(
            TryFromError::Response(e.clone()),
            unwrap_err!(Blob::try_from(GetBlob(Err(e.clone()))))
        );

        let mut data = BTreeMap::new();
        let _ = data.insert(vec![1], vec![10]);
        let owners = PublicKey::Bls(threshold_crypto::SecretKey::random().public_key());
        let m_data = Map::Unseq(UnseqMutableData::new_with_data(
            *i_data.name(),
            1,
            data,
            BTreeMap::new(),
            owners,
        ));
        assert_eq!(m_data, unwrap!(GetMap(Ok(m_data.clone())).try_into()));
        assert_eq!(
            TryFromError::Response(e.clone()),
            unwrap_err!(Map::try_from(GetMap(Err(e))))
        );
    }
}
