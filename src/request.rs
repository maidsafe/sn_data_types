// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod login_packet;

pub use self::login_packet::{LoginPacket, MAX_LOGIN_PACKET_BYTES};
use crate::{
    Address, AppPermissions, BlobAddress, BlobData, Coins, Error, Key, MapData, MapTransaction,
    Owner, PrivateAuth, PublicAuth, PublicKey, Response, SequenceCmdOption, SequenceData,
    TransactionId, User, Version, XorName,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// RPC Request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Request {
    Read(ReadRequest),
    Write(WriteRequest),
}

#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum ReadRequest {
    Map(MapReadRequest),
    Sequence(SequenceReadRequest),
    Blob(BlobReadRequest),
    Currency(CurrencyReadRequest),
    Misc(MiscReadRequest),
}

#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum MapReadRequest {
    ///
    /// ==== Data ====
    ///
    GetMap(Address),
    GetMapShell(Address),
    /// Returns the expected version for the entire map instance.
    GetMapVersion(Address),
    /// Returns expected Version of data, owners and auth.
    GetMapExpectedVersions(Address),
    /// Returns each value that the keys map to.
    GetMapValues(Address),
    GetMapValue {
        address: Address,
        key: Key,
    },
    GetMapValueAt {
        address: Address,
        key: Key,
        version: Version,
    },
    /// Returns all key-value pairs.
    GetMapEntries(Address),
    /// Returns all keys
    GetMapKeys(Address),
    /// Returns the list of all values that this key has previously mapped to, including current value.
    GetMapKeyHistory {
        address: Address,
        key: Key,
    },
    /// Returns a range of the key history (see GetMapKeyHistory).
    GetMapKeyHistoryRange {
        address: Address,
        key: Key,
        start: Version,
        end: Version,
    },
    ///
    /// ==== Owners ====
    ///
    GetMapOwner(Address),
    /// Get Map owner at the provided version.
    GetMapOwnerAt {
        address: Address,
        version: Version,
    },
    GetMapOwnerHistory(Address),
    GetMapOwnerHistoryRange {
        address: Address,
        start: Version,
        end: Version,
    },
    ///
    /// ==== Permissions ====
    ///
    GetMapAuth(Address),
    /// Get Map authorization at the provided version.
    GetMapAuthAt {
        address: Address,
        version: Version,
    },
    GetPublicMapAuthHistory(Address),
    GetPrivateMapAuthHistory(Address),
    GetPublicMapAuthHistoryRange {
        address: Address,
        key: Key,
        start: Version,
        end: Version,
    },
    GetPrivateMapAuthHistoryRange {
        address: Address,
        key: Key,
        start: Version,
        end: Version,
    },
    GetPublicMapUserPermissions {
        address: Address,
        user: User,
    },
    GetPrivateMapUserPermissions {
        address: Address,
        user: PublicKey,
    },
    /// Get Map permissions for a specified user(s), as of a version.
    GetPublicMapUserPermissionsAt {
        address: Address,
        version: Version,
        user: User,
    },
    /// Get Map permissions for a specified public key, as of a version.
    GetPrivateMapUserPermissionsAt {
        address: Address,
        version: Version,
        public_key: PublicKey,
    },
}

#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum SequenceReadRequest {
    ///
    /// ==== Data ====
    ///
    /// Get Sequence from the network.
    GetSequence(Address),
    /// Get expected versions: data, owners, permissions.
    GetSequenceExpectedVersions(Address),
    /// Get `Sequence` shell at a certain point in history (`data_version` refers to the list
    /// of data).
    GetSequenceShell {
        address: Address,
        expected_data_version: Version,
    },
    /// Get an entry at the current version.
    GetSequenceCurrentEntry(Address),
    /// Get a range of entries from an Sequence object on the network.
    GetSequenceRange {
        address: Address,
        // Range of entries to fetch.
        //
        // For example, get 10 last entries:
        // range: (Version::FromEnd(10), Version::FromEnd(0))
        //
        // Get all entries:
        // range: (Version::FromStart(0), Version::FromEnd(0))
        //
        // Get first 5 entries:
        // range: (Version::FromStart(0), Version::FromStart(5))
        range: (Version, Version),
    },
    GetSequenceValue {
        address: Address,
        version: Version,
    },
    ///
    /// ==== Owners ====
    ///
    /// Get Sequence current owner.
    GetSequenceOwner(Address),
    /// Get Sequence owner as of version.
    GetSequenceOwnerAt {
        address: Address,
        version: Version,
    },
    GetSequenceOwnerHistory(Address),
    GetSequenceOwnerHistoryRange {
        address: Address,
        start: Version,
        end: Version,
    },
    ///
    /// ==== Permissions ====
    ///
    GetSequenceAuth(Address),
    /// Get Sequence authorization as of version.
    GetSequenceAuthAt {
        address: Address,
        version: Version,
    },
    GetPublicSequenceAuthHistory(Address),
    GetPrivateSequenceAuthHistory(Address),
    GetPublicSequenceAuthHistoryRange {
        address: Address,
        key: Key,
        start: Version,
        end: Version,
    },
    GetPrivateSequenceAuthHistoryRange {
        address: Address,
        key: Key,
        start: Version,
        end: Version,
    },
    /// Get Sequence permissions for a specified user(s).
    GetPublicSequenceUserPermissions {
        address: Address,
        user: User,
    },
    /// Get Sequence permissions for a specified public key.
    GetPrivateSequenceUserPermissions {
        address: Address,
        user: PublicKey,
    },
    /// Get Sequence permissions for a specified user(s), as of version.
    GetPublicSequenceUserPermissionsAt {
        address: Address,
        version: Version,
        user: User,
    },
    /// Get Sequence permissions for a specified public key, as of version.
    GetPrivateSequenceUserPermissionsAt {
        address: Address,
        version: Version,
        public_key: PublicKey,
    },
}

#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum WriteRequest {
    Map(MapWriteRequest),
    Sequence(SequenceWriteRequest),
    Blob(BlobWriteRequest),
    Currency(CurrencyWriteRequest),
    Misc(MiscWriteRequest),
}

#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum MapWriteRequest {
    ///
    /// ==== Data ====
    ///
    PutMap(MapData),
    DeletePrivateMap(Address),
    CommitMapTx {
        address: Address,
        tx: MapTransaction,
    },
    ///
    /// ==== Owners ====
    ///
    /// Set owner. Only the current owner(s) can perform this action.
    SetMapOwner {
        address: Address,
        owner: Owner,
        expected_version: u64,
    },
    ///
    /// ==== Permissions ====
    ///
    /// Set authorization.
    SetPublicMapAuth {
        address: Address,
        auth: PublicAuth,
        expected_version: u64,
    },
    /// Set authorization.
    SetPrivateMapAuth {
        address: Address,
        auth: PrivateAuth,
        expected_version: u64,
    },
}

#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum SequenceWriteRequest {
    ///
    /// ==== Data ====
    ///
    /// Put a new Sequence onto the network.
    PutSequence(SequenceData),
    /// Delete private `Sequence`.
    /// This operation MUST return an error if applied to published Sequence. Only the current
    /// owner(s) can perform this action.
    DeletePrivateSequence(Address),
    // Operate on a Sequence instance.
    Handle(SequenceCmdOption),
    ///
    /// ==== Owners ====
    ///
    /// Set owner. Only the current owner(s) can perform this action.
    SetSequenceOwner {
        address: Address,
        owner: Owner,
        expected_version: u64,
    },
    ///
    /// ==== Permissions ====
    ///
    /// Set authorization.
    SetPublicSequenceAuth {
        address: Address,
        auth: PublicAuth,
        expected_version: u64,
    },
    /// Set authorization.
    SetPrivateSequenceAuth {
        address: Address,
        auth: PrivateAuth,
        expected_version: u64,
    },
}

#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum BlobReadRequest {
    GetBlob(BlobAddress),
}

#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum BlobWriteRequest {
    PutBlob(BlobData),
    DeletePrivateBlob(BlobAddress),
}

/// RPC Balance read request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum CurrencyReadRequest {
    /// Get a default balance // when no other differntiation is yet designed
    GetBalance,
    // GetBalanceOf(PublicKey), // when various balances can be managed
}

/// RPC Balance write request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum CurrencyWriteRequest {
    /// Balance transfer
    TransferCoins {
        destination: XorName,
        amount: Coins,
        transaction_id: TransactionId,
    },
    /// Create a new coin balance
    CreateBalance {
        new_balance_owner: PublicKey,
        amount: Coins,
        transaction_id: TransactionId,
    },
}

/// RPC misc read request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum MiscReadRequest {
    // ===== Login Packet =====
    //
    GetLoginPacket(XorName),
    //
    // ===== Client (Owner) to SrcElders =====
    //
    /// List authorised keys and version stored by Elders.
    ListAuthKeysAndVersion,
}

/// RPC misc write request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum MiscWriteRequest {
    //
    // ===== Login Packet =====
    //
    CreateLoginPacket(LoginPacket),
    CreateLoginPacketFor {
        new_owner: PublicKey,
        amount: Coins,
        transaction_id: TransactionId,
        new_login_packet: LoginPacket,
    },
    UpdateLoginPacket(LoginPacket),
    //
    // ===== Client (Owner) to SrcElders =====
    //
    /// Inserts an authorised key (for an app, user, etc.).
    InsertAuthKey {
        /// Authorised key to be inserted
        key: PublicKey,
        /// Incremented version
        version: u64,
        /// Permissions
        permissions: AppPermissions,
    },
    /// Deletes an authorised key.
    DeleteAuthKey {
        /// Authorised key to be deleted
        key: PublicKey,
        /// Incremented version
        version: u64,
    },
}

impl Request {
    /// Create a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use BlobWriteRequest::*;
        use CurrencyWriteRequest::*;
        use MapReadRequest::*;
        use MapWriteRequest::*;
        use MiscReadRequest::*;
        use MiscWriteRequest::*;
        use Request::*;
        use SequenceReadRequest::*;
        use SequenceWriteRequest::*;
        match &*self {
            Read(read) => match read {
                ReadRequest::Blob(blob) => match blob {
                    BlobReadRequest::GetBlob(_) => Response::GetBlob(Err(error)),
                },
                ReadRequest::Currency(cur) => match cur {
                    CurrencyReadRequest::GetBalance => Response::GetBalance(Err(error)),
                },
                ReadRequest::Map(map) => match map {
                    GetMap(_) => Response::GetMap(Err(error)),
                    GetMapAuth(_) => Response::GetMapAuth(Err(error)),
                    GetMapAuthAt { .. } => Response::GetMapAuthAt(Err(error)),
                    GetMapEntries(_) => Response::GetMapEntries(Err(error)),
                    GetMapExpectedVersions(_) => Response::GetMapExpectedVersions(Err(error)),
                    GetMapKeyHistory { .. } => Response::GetMapKeyHistory(Err(error)),
                    GetMapKeyHistoryRange { .. } => Response::GetMapKeyHistoryRange(Err(error)),
                    GetMapKeys(_) => Response::GetMapKeys(Err(error)),
                    GetMapOwner(_) => Response::GetMapOwner(Err(error)),
                    GetMapOwnerAt { .. } => Response::GetMapOwnerAt(Err(error)),
                    GetMapOwnerHistory(_) => Response::GetMapOwnerHistory(Err(error)),
                    GetMapOwnerHistoryRange { .. } => Response::GetMapOwnerHistoryRange(Err(error)),
                    GetMapShell(_) => Response::GetMapShell(Err(error)),
                    GetMapValue { .. } => Response::GetMapValue(Err(error)),
                    GetMapValueAt { .. } => Response::GetMapValueAt(Err(error)),
                    GetMapValues(_) => Response::GetMapValues(Err(error)),
                    GetMapVersion(_) => Response::GetMapVersion(Err(error)),
                    GetPrivateMapAuthHistory(_) => Response::GetPrivateMapAuthHistory(Err(error)),
                    GetPrivateMapAuthHistoryRange { .. } => {
                        Response::GetPrivateMapAuthHistoryRange(Err(error))
                    }
                    GetPrivateMapUserPermissions { .. } => {
                        Response::GetPrivateMapUserPermissions(Err(error))
                    }
                    GetPrivateMapUserPermissionsAt { .. } => {
                        Response::GetPrivateMapUserPermissionsAt(Err(error))
                    }
                    GetPublicMapAuthHistory(_) => Response::GetPublicMapAuthHistory(Err(error)),
                    GetPublicMapAuthHistoryRange { .. } => {
                        Response::GetPublicMapAuthHistoryRange(Err(error))
                    }
                    GetPublicMapUserPermissions { .. } => {
                        Response::GetPublicMapUserPermissions(Err(error))
                    }
                    GetPublicMapUserPermissionsAt { .. } => {
                        Response::GetPublicMapUserPermissionsAt(Err(error))
                    }
                },
                ReadRequest::Misc(misc) => match misc {
                    // ===== Login Packet =====
                    GetLoginPacket(_) => Response::GetLoginPacket(Err(error)),
                    // ===== Client (Owner) to SrcElders =====
                    ListAuthKeysAndVersion => Response::ListAuthKeysAndVersion(Err(error)),
                },
                ReadRequest::Sequence(seq) => match seq {
                    GetSequence(_) => Response::GetSequence(Err(error)),
                    GetSequenceShell { .. } => Response::GetSequenceShell(Err(error)),
                    GetSequenceValue { .. } => Response::GetSequenceValue(Err(error)),
                    GetSequenceRange { .. } => Response::GetSequenceRange(Err(error)),
                    GetSequenceExpectedVersions(_) => {
                        Response::GetSequenceExpectedVersions(Err(error))
                    }
                    GetSequenceCurrentEntry(_) => Response::GetSequenceCurrentEntry(Err(error)),
                    GetSequenceOwner(_) => Response::GetSequenceOwner(Err(error)),
                    GetSequenceOwnerAt { .. } => Response::GetSequenceOwnerAt(Err(error)),
                    GetSequenceOwnerHistory(_) => Response::GetSequenceOwnerHistory(Err(error)),
                    GetSequenceOwnerHistoryRange { .. } => {
                        Response::GetSequenceOwnerHistoryRange(Err(error))
                    }
                    GetSequenceAuth { .. } => Response::GetSequenceAuth(Err(error)),
                    GetSequenceAuthAt { .. } => Response::GetSequenceAuthAt(Err(error)),
                    GetPublicSequenceAuthHistory(_) => {
                        Response::GetPublicSequenceAuthHistory(Err(error))
                    }
                    GetPrivateSequenceAuthHistory(_) => {
                        Response::GetPrivateSequenceAuthHistory(Err(error))
                    }
                    GetPublicSequenceAuthHistoryRange { .. } => {
                        Response::GetPublicSequenceAuthHistoryRange(Err(error))
                    }
                    GetPrivateSequenceAuthHistoryRange { .. } => {
                        Response::GetPrivateSequenceAuthHistoryRange(Err(error))
                    }
                    GetPublicSequenceUserPermissions { .. } => {
                        Response::GetPublicSequenceUserPermissions(Err(error))
                    }
                    GetPrivateSequenceUserPermissions { .. } => {
                        Response::GetPrivateSequenceUserPermissions(Err(error))
                    }
                    GetPublicSequenceUserPermissionsAt { .. } => {
                        Response::GetPublicSequenceUserPermissionsAt(Err(error))
                    }
                    GetPrivateSequenceUserPermissionsAt { .. } => {
                        Response::GetPrivateSequenceUserPermissionsAt(Err(error))
                    }
                },
            },
            Write(write) => match write {
                WriteRequest::Blob(blob) => match blob {
                    PutBlob(_) | DeletePrivateBlob(_) => Response::Mutation(Err(error)),
                },
                WriteRequest::Currency(cur) => match cur {
                    TransferCoins { .. } | CreateBalance { .. } => {
                        Response::Transaction(Err(error))
                    }
                },
                WriteRequest::Map(map) => match map {
                    PutMap(_)
                    | DeletePrivateMap(_)
                    | SetMapOwner { .. }
                    | SetPublicMapAuth { .. }
                    | SetPrivateMapAuth { .. }
                    | CommitMapTx { .. } => Response::Mutation(Err(error)),
                },
                WriteRequest::Misc(misc) => match misc {
                    // ===== Login Packet =====
                    CreateLoginPacket { .. } |
                    CreateLoginPacketFor { .. } |
                    UpdateLoginPacket { .. } |
                    // ===== Client (Owner) to SrcElders =====
                    InsertAuthKey { .. } |
                    DeleteAuthKey { .. } => Response::Mutation(Err(error)),
                },
                WriteRequest::Sequence(seq) => match seq {
                    PutSequence(_)
                    | DeletePrivateSequence(_)
                    | SetSequenceOwner { .. }
                    | SetPublicSequenceAuth { .. }
                    | SetPrivateSequenceAuth { .. }
                    | Handle(_) => Response::Mutation(Err(error)),
                },
            },
        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use BlobWriteRequest::*;
        use CurrencyWriteRequest::*;
        use MapReadRequest::*;
        use MapWriteRequest::*;
        use MiscReadRequest::*;
        use MiscWriteRequest::*;
        use Request::*;
        use SequenceReadRequest::*;
        use SequenceWriteRequest::*;
        write!(
            formatter,
            "{}",
            match &*self {
                Read(read) => match read {
                    ReadRequest::Blob(blob) => match blob {
                        BlobReadRequest::GetBlob(_) => "BlobReadRequest::GetBlob",
                    },
                    ReadRequest::Currency(cur) => match cur {
                        CurrencyReadRequest::GetBalance => "CurrencyReadRequest::GetBalance",
                    },
                    ReadRequest::Map(map) => match map {
                        GetMap(_) => "MapReadRequest::GetMap",
                        GetMapAuth(_) => "MapReadRequest::GetMapAuth",
                        GetMapAuthAt { .. } => "MapReadRequest::GetMapAuthAt",
                        GetMapEntries(_) => "MapReadRequest::GetMapEntries",
                        GetMapExpectedVersions(_) => "MapReadRequest::GetMapExpectedVersions",
                        GetMapKeyHistory { .. } => "MapReadRequest::GetMapKeyHistory",
                        GetMapKeyHistoryRange { .. } => "MapReadRequest::GetMapKeyHistoryRange",
                        GetMapKeys(_) => "MapReadRequest::GetMapKeys",
                        GetMapOwner(_) => "MapReadRequest::GetMapOwner",
                        GetMapOwnerAt { .. } => "MapReadRequest::GetMapOwnerAt",
                        GetMapOwnerHistory(_) => "MapReadRequest::GetMapOwnerHistory",
                        GetMapOwnerHistoryRange { .. } => "MapReadRequest::GetMapOwnerHistoryRange",
                        GetMapShell(_) => "MapReadRequest::GetMapShell",
                        GetMapValue { .. } => "MapReadRequest::GetMapValue",
                        GetMapValueAt { .. } => "MapReadRequest::GetMapValueAt",
                        GetMapValues(_) => "MapReadRequest::GetMapValues",
                        GetMapVersion(_) => "MapReadRequest::GetMapVersion",
                        GetPrivateMapAuthHistory(_) => "MapReadRequest::GetPrivateMapAuthHistory",
                        GetPrivateMapAuthHistoryRange { .. } => {
                            "MapReadRequest::GetPrivateMapAuthHistoryRange"
                        }
                        GetPrivateMapUserPermissions { .. } => {
                            "MapReadRequest::GetPrivateMapUserPermissions"
                        }
                        GetPrivateMapUserPermissionsAt { .. } => {
                            "MapReadRequest::GetPrivateMapUserPermissionsAt"
                        }
                        GetPublicMapAuthHistory(_) => "MapReadRequest::GetPublicMapAuthHistory",
                        GetPublicMapAuthHistoryRange { .. } => {
                            "MapReadRequest::GetPublicMapAuthHistoryRange"
                        }
                        GetPublicMapUserPermissions { .. } => {
                            "MapReadRequest::GetPublicMapUserPermissions"
                        }
                        GetPublicMapUserPermissionsAt { .. } => {
                            "MapReadRequest::GetPublicMapUserPermissionsAt"
                        }
                    },
                    ReadRequest::Misc(misc) => match misc {
                        // ===== Login Packet =====
                        GetLoginPacket(_) => "MiscReadRequest::GetLoginPacket",
                        // ===== Client (Owner) to SrcElders =====
                        ListAuthKeysAndVersion => "MiscReadRequest::ListAuthKeysAndVersion",
                    },
                    ReadRequest::Sequence(seq) => match seq {
                        GetSequence(_) => "SequenceReadRequest::GetSequence",
                        GetSequenceShell { .. } => "SequenceReadRequest::GetSequenceShell",
                        GetSequenceValue { .. } => "SequenceReadRequest::GetSequenceValue",
                        GetSequenceRange { .. } => "SequenceReadRequest::GetSequenceRange",
                        GetSequenceExpectedVersions(_) => {
                            "SequenceReadRequest::GetSequenceExpectedVersions"
                        }
                        GetSequenceCurrentEntry(_) => {
                            "SequenceReadRequest::GetSequenceCurrentEntry"
                        }
                        GetSequenceOwner(_) => "SequenceReadRequest::GetSequenceOwner",
                        GetSequenceOwnerAt { .. } => "SequenceReadRequest::GetSequenceOwnerAt",
                        GetSequenceOwnerHistory(_) => {
                            "SequenceReadRequest::GetSequenceOwnerHistory"
                        }
                        GetSequenceOwnerHistoryRange { .. } => {
                            "SequenceReadRequest::GetSequenceOwnerHistoryRange"
                        }
                        GetSequenceAuth { .. } => "SequenceReadRequest::GetSequenceAuth",
                        GetSequenceAuthAt { .. } => "SequenceReadRequest::GetSequenceAuthAt",
                        GetPublicSequenceAuthHistory(_) => {
                            "SequenceReadRequest::GetPublicSequenceAuthHistory"
                        }
                        GetPrivateSequenceAuthHistory(_) => {
                            "SequenceReadRequest::GetPrivateSequenceAuthHistory"
                        }
                        GetPublicSequenceAuthHistoryRange { .. } => {
                            "SequenceReadRequest::GetPublicSequenceAuthHistoryRange"
                        }
                        GetPrivateSequenceAuthHistoryRange { .. } => {
                            "SequenceReadRequest::GetPrivateSequenceAuthHistoryRange"
                        }
                        GetPublicSequenceUserPermissions { .. } => {
                            "SequenceReadRequest::GetPublicSequenceUserPermissions"
                        }
                        GetPrivateSequenceUserPermissions { .. } => {
                            "SequenceReadRequest::GetPrivateSequenceUserPermissions"
                        }
                        GetPublicSequenceUserPermissionsAt { .. } => {
                            "SequenceReadRequest::GetPublicSequenceUserPermissionsAt"
                        }
                        GetPrivateSequenceUserPermissionsAt { .. } => {
                            "SequenceReadRequest::GetPrivateSequenceUserPermissionsAt"
                        }
                    },
                },
                Write(write) => match write {
                    WriteRequest::Blob(blob) => match blob {
                        PutBlob(_) => "BlobWriteRequest::PutBlob",
                        DeletePrivateBlob(_) => "BlobWriteRequest::DeletePrivateBlob",
                    },
                    WriteRequest::Currency(cur) => match cur {
                        TransferCoins { .. } => "CurrencyWriteRequest::TransferCoins",
                        CreateBalance { .. } => "CurrencyWriteRequest::CreateBalance",
                    },
                    WriteRequest::Map(map) => match map {
                        PutMap(_) => "MapWriteRequest::PutMap",
                        DeletePrivateMap(_) => "MapWriteRequest::DeletePrivateMap",
                        SetMapOwner { .. } => "MapWriteRequest::SetMapOwner",
                        SetPublicMapAuth { .. } => "MapWriteRequest::SetPublicMapAuth",
                        SetPrivateMapAuth { .. } => "MapWriteRequest::SetPrivateMapAuth",
                        CommitMapTx { .. } => "MapWriteRequest::CommitMapTx",
                    },
                    WriteRequest::Misc(misc) => match misc {
                        // ===== Login Packet =====
                        CreateLoginPacket { .. } => "MiscWriteRequest::CreateLoginPacket",
                        CreateLoginPacketFor { .. } => "MiscWriteRequest::CreateLoginPacketFor",
                        UpdateLoginPacket { .. } => "MiscWriteRequest::UpdateLoginPacket",
                        // ===== Client (Owner) to SrcElders =====
                        InsertAuthKey { .. } => "MiscWriteRequest::InsertAuthKey",
                        DeleteAuthKey { .. } => "MiscWriteRequest::DeleteAuthKey",
                    },
                    WriteRequest::Sequence(seq) => match seq {
                        PutSequence(_) => "SequenceWriteRequest::PutSequence",
                        DeletePrivateSequence(_) => "SequenceWriteRequest::DeletePrivateSequence",
                        SetSequenceOwner { .. } => "SequenceWriteRequest::SetSequenceOwner",
                        SetPublicSequenceAuth { .. } => {
                            "SequenceWriteRequest::SetPublicSequenceAuth"
                        }
                        SetPrivateSequenceAuth { .. } => {
                            "SequenceWriteRequest::SetPrivateSequenceAuth"
                        }
                        Handle(_) => "SequenceWriteRequest::Handle",
                    },
                },
            }
        )
    }
}
