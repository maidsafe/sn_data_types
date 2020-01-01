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
    Address, AppPermissions, AppendOperation, Blob, BlobAddress, Coins, Error, Key, Map,
    MapTransaction, Owner, PrivateAccessList, PublicAccessList, PublicKey, Response, Sequence,
    TransactionId, User, Version, XorName,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// RPC Request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Request {
    /// --- Map Read ----
    ///
    /// ==== Data ====
    ///
    GetMap(Address),
    GetMapShell {
        address: Address,
        expected_data_version: Version,
    },
    /// Returns the expected version for the entire map instance.
    GetMapVersion(Address),
    /// Returns expected Version of data, owners and access list.
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
    /// Returns history for all keys
    GetMapKeyHistories(Address),
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
    GetMapAccessList(Address),
    /// Get Map access list at the provided version.
    GetMapAccessListAt {
        address: Address,
        version: Version,
    },
    GetPublicMapAccessListHistory(Address),
    GetPrivateMapAccessListHistory(Address),
    GetPublicMapAccessListHistoryRange {
        address: Address,
        start: Version,
        end: Version,
    },
    GetPrivateMapAccessListHistoryRange {
        address: Address,
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
    ///
    /// ---- Sequence Read -----
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
    GetSequenceAccessList(Address),
    /// Get Sequence access list as of version.
    GetSequenceAccessListAt {
        address: Address,
        version: Version,
    },
    GetPublicSequenceAccessListHistory(Address),
    GetPrivateSequenceAccessListHistory(Address),
    GetPublicSequenceAccessListHistoryRange {
        address: Address,
        start: Version,
        end: Version,
    },
    GetPrivateSequenceAccessListHistoryRange {
        address: Address,
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
    /// ---- Map Write ----
    ///
    /// ==== Data ====
    ///
    PutMap(Map),
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
    /// Set access list.
    SetPublicMapAccessList {
        address: Address,
        access_list: PublicAccessList,
        expected_version: u64,
    },
    /// Set access list.
    SetPrivateMapAccessList {
        address: Address,
        access_list: PrivateAccessList,
        expected_version: u64,
    },
    /// ---- Sequence Write ----
    ///
    /// ==== Data ====
    ///
    /// Put a new Sequence onto the network.
    PutSequence(Sequence),
    /// Delete private `Sequence`.
    /// This operation MUST return an error if applied to published Sequence. Only the current
    /// owner(s) can perform this action.
    DeletePrivateSequence(Address),
    // Append to a Sequence instance.
    Append(AppendOperation),
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
    /// Set access list.
    SetPublicSequenceAccessList {
        address: Address,
        access_list: PublicAccessList,
        expected_version: u64,
    },
    /// Set access list.
    SetPrivateSequenceAccessList {
        address: Address,
        access_list: PrivateAccessList,
        expected_version: u64,
    },
    ///
    /// --- Blob Read ---
    ///
    GetBlob(BlobAddress),
    ///
    /// --- Blob Write ---
    ///
    PutBlob(Blob),
    DeletePrivateBlob(BlobAddress),
    /// ---- Currency Read ----
    /// Get a default balance // when no other differntiation is yet designed
    GetBalance,
    ///
    /// ---- Currency Write ----
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
    /// ---- Misc Read ----
    ///
    /// ===== Login Packet =====
    ///
    GetLoginPacket(XorName),
    ///
    /// ===== Client (Owner) to SrcElders =====
    ///
    /// List authorised keys and version stored by Elders.
    ListAuthKeysAndVersion,
    ///
    /// ---- Misc Write ----
    ///
    /// ===== Login Packet =====
    ///
    CreateLoginPacket(LoginPacket),
    CreateLoginPacketFor {
        new_owner: PublicKey,
        amount: Coins,
        transaction_id: TransactionId,
        new_login_packet: LoginPacket,
    },
    UpdateLoginPacket(LoginPacket),
    ///
    /// ===== Client (Owner) to SrcElders =====
    ///
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
        use Request::*;
        match &*self {
            GetBlob(_) => Response::GetBlob(Err(error)),
            GetBalance => Response::GetBalance(Err(error)),
            GetMap(_) => Response::GetMap(Err(error)),
            GetMapAccessList(_) => Response::GetMapAccessList(Err(error)),
            GetMapAccessListAt { .. } => Response::GetMapAccessListAt(Err(error)),
            GetMapEntries(_) => Response::GetMapEntries(Err(error)),
            GetMapExpectedVersions(_) => Response::GetMapExpectedVersions(Err(error)),
            GetMapKeyHistory { .. } => Response::GetMapKeyHistory(Err(error)),
            GetMapKeyHistoryRange { .. } => Response::GetMapKeyHistoryRange(Err(error)),
            GetMapKeys(_) => Response::GetMapKeys(Err(error)),
            GetMapKeyHistories(_) => Response::GetMapKeyHistories(Err(error)),
            GetMapOwner(_) => Response::GetMapOwner(Err(error)),
            GetMapOwnerAt { .. } => Response::GetMapOwnerAt(Err(error)),
            GetMapOwnerHistory(_) => Response::GetMapOwnerHistory(Err(error)),
            GetMapOwnerHistoryRange { .. } => Response::GetMapOwnerHistoryRange(Err(error)),
            GetMapShell { .. } => Response::GetMapShell(Err(error)),
            GetMapValue { .. } => Response::GetMapValue(Err(error)),
            GetMapValueAt { .. } => Response::GetMapValueAt(Err(error)),
            GetMapValues(_) => Response::GetMapValues(Err(error)),
            GetMapVersion(_) => Response::GetMapVersion(Err(error)),
            GetPrivateMapAccessListHistory(_) => {
                Response::GetPrivateMapAccessListHistory(Err(error))
            }
            GetPrivateMapAccessListHistoryRange { .. } => {
                Response::GetPrivateMapAccessListHistoryRange(Err(error))
            }
            GetPrivateMapUserPermissions { .. } => {
                Response::GetPrivateMapUserPermissions(Err(error))
            }
            GetPrivateMapUserPermissionsAt { .. } => {
                Response::GetPrivateMapUserPermissionsAt(Err(error))
            }
            GetPublicMapAccessListHistory(_) => {
                Response::GetPublicMapAccessListHistory(Err(error))
            }
            GetPublicMapAccessListHistoryRange { .. } => {
                Response::GetPublicMapAccessListHistoryRange(Err(error))
            }
            GetPublicMapUserPermissions { .. } => {
                Response::GetPublicMapUserPermissions(Err(error))
            }
            GetPublicMapUserPermissionsAt { .. } => {
                Response::GetPublicMapUserPermissionsAt(Err(error))
            }
            // ===== Login Packet =====
            GetLoginPacket(_) => Response::GetLoginPacket(Err(error)),
            // ===== Client (Owner) to SrcElders =====
            ListAuthKeysAndVersion => Response::ListAuthKeysAndVersion(Err(error)),
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
            GetSequenceAccessList { .. } => Response::GetSequenceAccessList(Err(error)),
            GetSequenceAccessListAt { .. } => Response::GetSequenceAccessListAt(Err(error)),
            GetPublicSequenceAccessListHistory(_) => {
                Response::GetPublicSequenceAccessListHistory(Err(error))
            }
            GetPrivateSequenceAccessListHistory(_) => {
                Response::GetPrivateSequenceAccessListHistory(Err(error))
            }
            GetPublicSequenceAccessListHistoryRange { .. } => {
                Response::GetPublicSequenceAccessListHistoryRange(Err(error))
            }
            GetPrivateSequenceAccessListHistoryRange { .. } => {
                Response::GetPrivateSequenceAccessListHistoryRange(Err(error))
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
            PutBlob(_) | DeletePrivateBlob(_) => Response::Mutation(Err(error)),
                TransferCoins { .. } | CreateBalance { .. } => {
                    Response::Transaction(Err(error))
                }
            PutMap(_)
            | DeletePrivateMap(_)
            | SetMapOwner { .. }
            | SetPublicMapAccessList { .. }
            | SetPrivateMapAccessList { .. }
            | CommitMapTx { .. } => Response::Mutation(Err(error)),
            // ===== Login Packet =====
            CreateLoginPacket { .. } |
            CreateLoginPacketFor { .. } |
            UpdateLoginPacket { .. } |
            // ===== Client (Owner) to SrcElders =====
            InsertAuthKey { .. } |
            DeleteAuthKey { .. } => Response::Mutation(Err(error)),
            PutSequence(_)
            | DeletePrivateSequence(_)
            | SetSequenceOwner { .. }
            | SetPublicSequenceAccessList { .. }
            | SetPrivateSequenceAccessList { .. }
            | Append(_) => Response::Mutation(Err(error)),
        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use Request::*;
        write!(
            formatter,
            "{}",
            match &*self {
                GetBlob(_) => "BlobReadRequest::GetBlob",
                GetBalance => "CurrencyReadRequest::GetBalance",
                GetMap(_) => "MapReadRequest::GetMap",
                GetMapAccessList(_) => "MapReadRequest::GetMapAccessList",
                GetMapAccessListAt { .. } => "MapReadRequest::GetMapAccessListAt",
                GetMapEntries(_) => "MapReadRequest::GetMapEntries",
                GetMapExpectedVersions(_) => "MapReadRequest::GetMapExpectedVersions",
                GetMapKeyHistory { .. } => "MapReadRequest::GetMapKeyHistory",
                GetMapKeyHistoryRange { .. } => "MapReadRequest::GetMapKeyHistoryRange",
                GetMapKeyHistories(_) => "MapReadRequest::GetMapKeyHistories",
                GetMapKeys(_) => "MapReadRequest::GetMapKeys",
                GetMapOwner(_) => "MapReadRequest::GetMapOwner",
                GetMapOwnerAt { .. } => "MapReadRequest::GetMapOwnerAt",
                GetMapOwnerHistory(_) => "MapReadRequest::GetMapOwnerHistory",
                GetMapOwnerHistoryRange { .. } => "MapReadRequest::GetMapOwnerHistoryRange",
                GetMapShell { .. } => "MapReadRequest::GetMapShell",
                GetMapValue { .. } => "MapReadRequest::GetMapValue",
                GetMapValueAt { .. } => "MapReadRequest::GetMapValueAt",
                GetMapValues(_) => "MapReadRequest::GetMapValues",
                GetMapVersion(_) => "MapReadRequest::GetMapVersion",
                GetPrivateMapAccessListHistory(_) => {
                    "MapReadRequest::GetPrivateMapAccessListHistory"
                }
                GetPrivateMapAccessListHistoryRange { .. } => {
                    "MapReadRequest::GetPrivateMapAccessListHistoryRange"
                }
                GetPrivateMapUserPermissions { .. } => {
                    "MapReadRequest::GetPrivateMapUserPermissions"
                }
                GetPrivateMapUserPermissionsAt { .. } => {
                    "MapReadRequest::GetPrivateMapUserPermissionsAt"
                }
                GetPublicMapAccessListHistory(_) => "MapReadRequest::GetPublicMapAccessListHistory",
                GetPublicMapAccessListHistoryRange { .. } => {
                    "MapReadRequest::GetPublicMapAccessListHistoryRange"
                }
                GetPublicMapUserPermissions { .. } => "MapReadRequest::GetPublicMapUserPermissions",
                GetPublicMapUserPermissionsAt { .. } => {
                    "MapReadRequest::GetPublicMapUserPermissionsAt"
                }
                // ===== Login Packet =====
                GetLoginPacket(_) => "MiscReadRequest::GetLoginPacket",
                // ===== Client (Owner) to SrcElders =====
                ListAuthKeysAndVersion => "MiscReadRequest::ListAuthKeysAndVersion",
                GetSequence(_) => "SequenceReadRequest::GetSequence",
                GetSequenceShell { .. } => "SequenceReadRequest::GetSequenceShell",
                GetSequenceValue { .. } => "SequenceReadRequest::GetSequenceValue",
                GetSequenceRange { .. } => "SequenceReadRequest::GetSequenceRange",
                GetSequenceExpectedVersions(_) => {
                    "SequenceReadRequest::GetSequenceExpectedVersions"
                }
                GetSequenceCurrentEntry(_) => "SequenceReadRequest::GetSequenceCurrentEntry",
                GetSequenceOwner(_) => "SequenceReadRequest::GetSequenceOwner",
                GetSequenceOwnerAt { .. } => "SequenceReadRequest::GetSequenceOwnerAt",
                GetSequenceOwnerHistory(_) => "SequenceReadRequest::GetSequenceOwnerHistory",
                GetSequenceOwnerHistoryRange { .. } => {
                    "SequenceReadRequest::GetSequenceOwnerHistoryRange"
                }
                GetSequenceAccessList { .. } => "SequenceReadRequest::GetSequenceAccessList",
                GetSequenceAccessListAt { .. } => "SequenceReadRequest::GetSequenceAccessListAt",
                GetPublicSequenceAccessListHistory(_) => {
                    "SequenceReadRequest::GetPublicSequenceAccessListHistory"
                }
                GetPrivateSequenceAccessListHistory(_) => {
                    "SequenceReadRequest::GetPrivateSequenceAccessListHistory"
                }
                GetPublicSequenceAccessListHistoryRange { .. } => {
                    "SequenceReadRequest::GetPublicSequenceAccessListHistoryRange"
                }
                GetPrivateSequenceAccessListHistoryRange { .. } => {
                    "SequenceReadRequest::GetPrivateSequenceAccessListHistoryRange"
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
                PutBlob(_) => "BlobWriteRequest::PutBlob",
                DeletePrivateBlob(_) => "BlobWriteRequest::DeletePrivateBlob",
                TransferCoins { .. } => "CurrencyWriteRequest::TransferCoins",
                CreateBalance { .. } => "CurrencyWriteRequest::CreateBalance",
                PutMap(_) => "MapWriteRequest::PutMap",
                DeletePrivateMap(_) => "MapWriteRequest::DeletePrivateMap",
                SetMapOwner { .. } => "MapWriteRequest::SetMapOwner",
                SetPublicMapAccessList { .. } => "MapWriteRequest::SetPublicMapAccessList",
                SetPrivateMapAccessList { .. } => "MapWriteRequest::SetPrivateMapAccessList",
                CommitMapTx { .. } => "MapWriteRequest::CommitMapTx",
                // ===== Login Packet =====
                CreateLoginPacket { .. } => "MiscWriteRequest::CreateLoginPacket",
                CreateLoginPacketFor { .. } => "MiscWriteRequest::CreateLoginPacketFor",
                UpdateLoginPacket { .. } => "MiscWriteRequest::UpdateLoginPacket",
                // ===== Client (Owner) to SrcElders =====
                InsertAuthKey { .. } => "MiscWriteRequest::InsertAuthKey",
                DeleteAuthKey { .. } => "MiscWriteRequest::DeleteAuthKey",
                PutSequence(_) => "SequenceWriteRequest::PutSequence",
                DeletePrivateSequence(_) => "SequenceWriteRequest::DeletePrivateSequence",
                SetSequenceOwner { .. } => "SequenceWriteRequest::SetSequenceOwner",
                SetPublicSequenceAccessList { .. } => {
                    "SequenceWriteRequest::SetPublicSequenceAccessList"
                }
                SetPrivateSequenceAccessList { .. } => {
                    "SequenceWriteRequest::SetPrivateSequenceAccessList"
                }
                Append(_) => "SequenceWriteRequest::Append",
            }
        )
    }
}
