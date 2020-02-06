// Copyright 2020 MaidSafe.net limited.
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
    Address, AppPermissions, AppendOperation, Coins, Error, IData, IDataAddress, MData,
    MDataAddress, MDataEntryActions, MDataPermissionSet, Owner, PrivateAccessList,
    PublicAccessList, PublicKey, Response, Sequence, TransactionId, User, Version, XorName,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The type of a `Request`.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Type {
    /// Request is a Get for public data.
    PublicGet,
    /// Request is a Get for private data.
    PrivateGet,
    /// Request is a Mutation.
    Mutation,
    /// Request is a Transaction.
    Transaction,
}

/// RPC Request that is sent to vaults.
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Request {
    //
    // ===== Immutable Data =====
    //
    /// Put ImmutableData.
    PutIData(IData),
    /// Get ImmutableData.
    GetIData(IDataAddress),
    /// Delete unpublished ImmutableData.
    DeleteUnpubIData(IDataAddress),
    //
    // ===== Mutable Data =====
    //
    /// Put MutableData.
    PutMData(MData),
    /// Get MutableData.
    GetMData(MDataAddress),
    /// Get MutableData value.
    GetMDataValue {
        /// MutableData address.
        address: MDataAddress,
        /// Key to get.
        key: Vec<u8>,
    },
    /// Delete MutableData.
    DeleteMData(MDataAddress),
    /// Get MutableData shell.
    GetMDataShell(MDataAddress),
    /// Get MutableData version.
    GetMDataVersion(MDataAddress),
    /// List MutableData entries.
    ListMDataEntries(MDataAddress),
    /// List MutableData keys.
    ListMDataKeys(MDataAddress),
    /// List MutableData values.
    ListMDataValues(MDataAddress),
    /// Set MutableData user permissions.
    SetMDataUserPermissions {
        /// MutableData address.
        address: MDataAddress,
        /// User to set permissions for.
        user: PublicKey,
        /// New permissions.
        permissions: MDataPermissionSet,
        /// Version to set.
        version: u64,
    },
    /// Delete MutableData user permissions.
    DelMDataUserPermissions {
        /// MutableData address.
        address: MDataAddress,
        /// User to delete permissions for.
        user: PublicKey,
        /// Version to delete.
        version: u64,
    },
    /// List MutableData permissions.
    ListMDataPermissions(MDataAddress),
    /// Get MutableData permissions for a user.
    ListMDataUserPermissions {
        /// MutableData address.
        address: MDataAddress,
        /// User to get permissions for.
        user: PublicKey,
    },
    /// Mutate MutableData entries.
    MutateMDataEntries {
        /// MutableData address.
        address: MDataAddress,
        /// Mutation actions to perform.
        actions: MDataEntryActions,
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
        /// The address of the instance.
        address: Address,
        /// The data version of the instance. `None` if no data has been added yet.
        data_version: Option<Version>,
    },
    /// Get an entry at the current version.
    GetSequenceCurrentEntry(Address),
    /// Get a range of entries from an Sequence object on the network.
    GetSequenceRange {
        /// The address of the instance.
        address: Address,
        /// Range of entries to fetch.
        ///
        /// For example, get 10 last entries:
        /// range: (Version::FromEnd(10), Version::FromEnd(0))
        ///
        /// Get all entries:
        /// range: (Version::FromStart(0), Version::FromEnd(0))
        ///
        /// Get first 5 entries:
        /// range: (Version::FromStart(0), Version::FromStart(5))
        range: (Version, Version),
    },
    /// Get a Sequence value as of a specific version.
    GetSequenceValue {
        /// The address of the instance.
        address: Address,
        /// The data version of the instance.
        version: Version,
    },
    ///
    /// ==== Owners ====
    ///
    /// Get Sequence current owner.
    GetSequenceOwner(Address),
    /// Get Sequence owner as of version.
    GetSequenceOwnerAt {
        /// The address of the instance.
        address: Address,
        /// The owner version of the instance.
        version: Version,
    },
    /// Returns the history of owners.
    GetSequenceOwnerHistory(Address),
    /// Returns a range of the history of owners.
    GetSequenceOwnerHistoryRange {
        /// The address of the instance.
        address: Address,
        /// The owner version range start.
        start: Version,
        /// The owner version range end.
        end: Version,
    },
    ///
    /// ==== Permissions ====
    ///
    GetSequenceAccessList(Address),
    /// Get Sequence access list as of version.
    GetSequenceAccessListAt {
        /// The address of the instance.
        address: Address,
        /// The access list version of the instance.
        version: Version,
    },
    /// Returns the history of access lists for a public instance.
    GetPublicSequenceAccessListHistory(Address),
    /// Returns the history of access lists for a private instance.
    GetPrivateSequenceAccessListHistory(Address),
    /// Returns a range of the history of access lists for a public instance.
    GetPublicSequenceAccessListHistoryRange {
        /// The address of the instance.
        address: Address,
        /// The access list version range start.
        start: Version,
        /// The access list version range end.
        end: Version,
    },
    /// Returns a range of the history of access lists for a private instance.
    GetPrivateSequenceAccessListHistoryRange {
        /// The address of the instance.
        address: Address,
        /// The access list version range start.
        start: Version,
        /// The access list version range end.
        end: Version,
    },
    /// Get Sequence permissions for a specified user(s).
    GetPublicSequenceUserPermissions {
        /// The address of the instance.
        address: Address,
        /// The user category variant.
        user: User,
    },
    /// Get Sequence permissions for a specified public key.
    GetPrivateSequenceUserPermissions {
        /// The address of the instance.
        address: Address,
        /// The public key of the specific user.
        user: PublicKey,
    },
    /// Get Sequence permissions for a specified user(s), as of version.
    GetPublicSequenceUserPermissionsAt {
        /// The address of the instance.
        address: Address,
        /// The access list version of the instance.
        version: Version,
        /// The user category variant.
        user: User,
    },
    /// Get Sequence permissions for a specified public key, as of version.
    GetPrivateSequenceUserPermissionsAt {
        /// The address of the instance.
        address: Address,
        /// The access list version of the instance.
        version: Version,
        /// The public key of the specific user.
        public_key: PublicKey,
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
    /// Append to a Sequence instance.
    Append(AppendOperation),
    ///
    /// ==== Owners ====
    ///
    /// Set owner. Only the current owner(s) can perform this action.
    SetSequenceOwner {
        /// The address of the instance.
        address: Address,
        /// The owner of the instance.
        owner: Owner,
        /// The expected owner version.
        expected_version: u64,
    },
    ///
    /// ==== Permissions ====
    ///
    /// Set access list.
    SetPublicSequenceAccessList {
        /// The address of the instance.
        address: Address,
        /// The new access list.
        access_list: PublicAccessList,
        /// The expected access list version.
        expected_version: u64,
    },
    /// Set access list.
    SetPrivateSequenceAccessList {
        /// The address of the instance.
        address: Address,
        /// The new access list.
        access_list: PrivateAccessList,
        /// The expected access list version.
        expected_version: u64,
    },
    // ===== Coins =====
    //
    /// Balance transfer.
    TransferCoins {
        /// The destination to transfer to.
        destination: XorName,
        /// The amount in coins to transfer.
        amount: Coins,
        /// The ID of the transaction.
        transaction_id: TransactionId,
    },
    /// Get current wallet balance.
    GetBalance,
    /// Create a new coin balance.
    CreateBalance {
        /// The new owner of the balance.
        new_balance_owner: PublicKey,
        /// The new balance amount in coins.
        amount: Coins,
        /// The ID of the transaction.
        transaction_id: TransactionId,
    },
    //
    // ===== Login Packet =====
    //
    /// Create a login packet.
    CreateLoginPacket(LoginPacket),
    /// Create a login packet for a given user and transfer some initial coins.
    CreateLoginPacketFor {
        /// The new owner of the login packet.
        new_owner: PublicKey,
        /// The new balance amount in coins.
        amount: Coins,
        /// The ID of the transaction.
        transaction_id: TransactionId,
        /// The new login packet.
        new_login_packet: LoginPacket,
    },
    /// Update a login packet.
    UpdateLoginPacket(LoginPacket),
    /// Get an encrypted login packet.
    GetLoginPacket(XorName),
    //
    // ===== Client (Owner) to SrcElders =====
    //
    /// List authorised keys and version stored by Elders.
    ListAuthKeysAndVersion,
    /// Insert an authorised key (for an app, user, etc.).
    InsAuthKey {
        /// Authorised key to be inserted
        key: PublicKey,
        /// Incremented version
        version: u64,
        /// Permissions
        permissions: AppPermissions,
    },
    /// Delete an authorised key.
    DelAuthKey {
        /// Authorised key to be deleted
        key: PublicKey,
        /// Incremented version
        version: u64,
    },
}

impl Request {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use Request::*;

        match *self {
            // IData requests

            GetIData(address) => {
                if address.is_pub() {
                    Type::PublicGet
                } else {
                    Type::PrivateGet
                }
            }

            // Sequence requests
            GetSequence(address) |
            GetSequenceShell { address, .. } |
            GetSequenceValue { address, .. } |
            GetSequenceRange { address, .. } |
            GetSequenceExpectedVersions(address) |
            GetSequenceCurrentEntry(address) |
            GetSequenceOwner(address) |
            GetSequenceOwnerAt { address, .. } |
            GetSequenceOwnerHistory(address) |
            GetSequenceOwnerHistoryRange { address, .. } |
            GetSequenceAccessList(address) |
            GetSequenceAccessListAt { address, .. } |
            GetPublicSequenceAccessListHistory(address) |
            GetPrivateSequenceAccessListHistory(address) |
            GetPublicSequenceAccessListHistoryRange { address, .. } |
            GetPrivateSequenceAccessListHistoryRange { address, .. } |
            GetPublicSequenceUserPermissions { address, .. } |
            GetPrivateSequenceUserPermissions { address, .. } |
            GetPublicSequenceUserPermissionsAt { address, .. } |
            GetPrivateSequenceUserPermissionsAt { address, .. } => {
                if address.is_public() {
                    Type::PublicGet
                } else {
                    Type::PrivateGet
                }
            }

            // MData requests (always unpub)

            GetMData(_)
            | GetMDataValue { .. }
            | GetMDataShell(_)
            | GetMDataVersion(_)
            | ListMDataEntries(_)
            | ListMDataKeys(_)
            | ListMDataValues(_)
            | ListMDataPermissions(_)
                | ListMDataUserPermissions { .. } => Type::PrivateGet,

            // Coins
            GetBalance |
            // Login packet
            GetLoginPacket(..) |
            // Client (Owner) to SrcElders
            ListAuthKeysAndVersion => Type::PrivateGet,

            // Transaction

            // Coins
            TransferCoins { .. } | CreateBalance { .. } |
            // Login Packet
            CreateLoginPacketFor { .. } => {
                Type::Transaction
            }

            // Mutation

            // IData
            PutIData(_) |
            DeleteUnpubIData(_) |
            // MData
            PutMData(_) |
            DeleteMData(_) |
            SetMDataUserPermissions { .. } |
            DelMDataUserPermissions { .. } |
            MutateMDataEntries { .. } |
            // Sequence
            PutSequence(_)
            | DeletePrivateSequence(_)
            | SetSequenceOwner { .. }
            | SetPublicSequenceAccessList { .. }
            | SetPrivateSequenceAccessList { .. }
            | Append(_) |
            // Login Packet
            CreateLoginPacket { .. } |
            UpdateLoginPacket { .. } |
            // Client (Owner) to SrcElders
            InsAuthKey { .. } |
            DelAuthKey { .. } => Type::Mutation,
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use Request::*;

        match *self {
            // IData
            GetIData(_) => Response::GetIData(Err(error)),
            // MData
            GetMData(_) => Response::GetMData(Err(error)),
            GetMDataValue { .. } => Response::GetMDataValue(Err(error)),
            GetMDataShell(_) => Response::GetMDataShell(Err(error)),
            GetMDataVersion(_) => Response::GetMDataVersion(Err(error)),
            ListMDataEntries(_) => Response::ListMDataEntries(Err(error)),
            ListMDataKeys(_) => Response::ListMDataKeys(Err(error)),
            ListMDataValues(_) => Response::ListMDataValues(Err(error)),
            ListMDataPermissions(_) => Response::ListMDataPermissions(Err(error)),
            ListMDataUserPermissions { .. } => Response::ListMDataUserPermissions(Err(error)),
            // Sequence
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
            // Coins
            GetBalance => Response::GetBalance(Err(error)),
            // Login Packet
            GetLoginPacket(..) => Response::GetLoginPacket(Err(error)),
            // Client (Owner) to SrcElders
            ListAuthKeysAndVersion => Response::ListAuthKeysAndVersion(Err(error)),

            // Transaction

            // Coins
            TransferCoins { .. } | CreateBalance { .. }
            // Login Packet
            | CreateLoginPacketFor { .. } => Response::Transaction(Err(error)),

            // Mutation

            // IData
            PutIData(_) |
            DeleteUnpubIData(_) |
            // MData
            PutMData(_) |
            DeleteMData(_) |
            SetMDataUserPermissions { .. } |
            DelMDataUserPermissions { .. } |
            MutateMDataEntries { .. } |
            // Sequence
            PutSequence(_)
            | DeletePrivateSequence(_)
            | SetSequenceOwner { .. }
            | SetPublicSequenceAccessList { .. }
            | SetPrivateSequenceAccessList { .. }
            | Append(_) |
            // Login Packet
            CreateLoginPacket { .. } |
            UpdateLoginPacket { .. } |
            // Client (Owner) to SrcElders
            InsAuthKey { .. } |
            DelAuthKey { .. } => Response::Mutation(Err(error)),

        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use Request::*;

        write!(
            formatter,
            "Request::{}",
            match *self {
                // IData
                PutIData(_) => "PutIData",
                GetIData(_) => "GetIData",
                DeleteUnpubIData(_) => "DeleteUnpubIData",
                // MData
                PutMData(_) => "PutMData",
                GetMData(_) => "GetMData",
                GetMDataValue { .. } => "GetMDataValue",
                DeleteMData(_) => "DeleteMData",
                GetMDataShell(_) => "GetMDataShell",
                GetMDataVersion(_) => "GetMDataVersion",
                ListMDataEntries(_) => "ListMDataEntries",
                ListMDataKeys(_) => "ListMDataKeys",
                ListMDataValues(_) => "ListMDataValues",
                SetMDataUserPermissions { .. } => "SetMDataUserPermissions",
                DelMDataUserPermissions { .. } => "DelMDataUserPermissions",
                ListMDataPermissions(_) => "ListMDataPermissions",
                ListMDataUserPermissions { .. } => "ListMDataUserPermissions",
                MutateMDataEntries { .. } => "MutateMDataEntries",
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
                // Coins
                TransferCoins { .. } => "TransferCoins",
                GetBalance => "GetBalance",
                CreateBalance { .. } => "CreateBalance",
                // Login Packet
                CreateLoginPacket { .. } => "CreateLoginPacket",
                CreateLoginPacketFor { .. } => "CreateLoginPacketFor",
                UpdateLoginPacket { .. } => "UpdateLoginPacket",
                GetLoginPacket(..) => "GetLoginPacket",
                // Client (Owner) to SrcElders
                ListAuthKeysAndVersion => "ListAuthKeysAndVersion",
                InsAuthKey { .. } => "InsAuthKey",
                DelAuthKey { .. } => "DelAuthKey",
            }
        )
    }
}
