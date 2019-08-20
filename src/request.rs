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
    AData, ADataAddress, ADataAppendOperation, ADataIndex, ADataOwner, ADataPubPermissions,
    ADataUnpubPermissions, ADataUser, AppPermissions, Coins, Error, IData, IDataAddress, MData,
    MDataAddress, MDataEntryActions, MDataPermissionSet, PublicKey, Response, TransactionId,
    XorName,
};
use serde::{Deserialize, Serialize};
use std::fmt;

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
    //
    // ===== Append Only Data =====
    //
    /// Put a new AppendOnlyData onto the network.
    PutAData(AData),
    /// Get AppendOnlyData from the network.
    GetAData(ADataAddress),
    /// Get AppendOnlyData shell at a certain point in history (`data_index` refers to the list of
    /// data).
    GetADataShell {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Index of the data at which to get the shell.
        data_index: ADataIndex,
    },
    /// Delete an unpublished `AppendOnlyData`.
    ///
    /// This operation MUST return an error if applied to published AppendOnlyData. Only the current
    /// owner(s) can perform this action.
    DeleteAData(ADataAddress),
    /// Get a range of entries from an AppendOnlyData object on the network.
    GetADataRange {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Range of entries to fetch.
        ///
        /// For example, get 10 last entries:
        /// range: (Index::FromEnd(10), Index::FromEnd(0))
        ///
        /// Get all entries:
        /// range: (Index::FromStart(0), Index::FromEnd(0))
        ///
        /// Get first 5 entries:
        /// range: (Index::FromStart(0), Index::FromStart(5))
        range: (ADataIndex, ADataIndex),
    },
    /// Get AppendOnlyData value.
    GetADataValue {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Key to get.
        key: Vec<u8>,
    },
    /// Get current indices: data, owners, permissions.
    GetADataIndices(ADataAddress),
    /// Get an entry with the current index.
    GetADataLastEntry(ADataAddress),
    /// List all permissions at the provided index.
    GetADataPermissions {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Permissions index.
        permissions_index: ADataIndex,
    },
    /// Get published permissions for a specified user(s).
    GetPubADataUserPermissions {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Permissions index.
        permissions_index: ADataIndex,
        /// User to get permissions for.
        user: ADataUser,
    },
    /// Get unpublished permissions for a specified user(s).
    GetUnpubADataUserPermissions {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Permissions index.
        permissions_index: ADataIndex,
        /// User to get permissions for.
        public_key: PublicKey,
    },
    /// Get owners at the provided index.
    GetADataOwners {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Onwers index.
        owners_index: ADataIndex,
    },
    /// Add a new published `permissions` entry.
    AddPubADataPermissions {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Published permissions.
        permissions: ADataPubPermissions,
        /// Index to add to.
        permissions_index: u64,
    },
    /// Add a new unpublished `permissions` entry.
    AddUnpubADataPermissions {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Unpublished permissions.
        permissions: ADataUnpubPermissions,
        /// Index to add to.
        permissions_index: u64,
    },
    /// Add a new `owners` entry. Only the current owner(s) can perform this action.
    SetADataOwner {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// New owner.
        owner: ADataOwner,
        /// Owners index.
        owners_index: u64,
    },
    /// Append sequenced AppendOnlyData at the given index.
    AppendSeq {
        /// Entries to append.
        append: ADataAppendOperation,
        /// Index.
        index: u64,
    },
    /// Append unsequenced AppendOnlyData.
    AppendUnseq(ADataAppendOperation),
    //
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
        /// If this transfer is a refund, this field contains the reason for it. Otherwise it is `None`.
        refund_reason: Option<Error>,
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
            // AData
            GetAData(_) => Response::GetAData(Err(error)),
            GetADataShell { .. } => Response::GetADataShell(Err(error)),
            GetADataValue { .. } => Response::GetADataValue(Err(error)),
            GetADataRange { .. } => Response::GetADataRange(Err(error)),
            GetADataIndices(_) => Response::GetADataIndices(Err(error)),
            GetADataLastEntry(_) => Response::GetADataLastEntry(Err(error)),
            GetADataPermissions { .. } => Response::GetADataPermissions(Err(error)),
            GetPubADataUserPermissions { .. } => Response::GetPubADataUserPermissions(Err(error)),
            GetUnpubADataUserPermissions { .. } => {
                Response::GetUnpubADataUserPermissions(Err(error))
            }
            GetADataOwners { .. } => Response::GetADataOwners(Err(error)),
            // Coins
            TransferCoins { .. } => Response::Transaction(Err(error)),
            GetBalance => Response::GetBalance(Err(error)),
            CreateBalance { .. } => Response::Transaction(Err(error)),
            // Login Packet
            GetLoginPacket(..) => Response::GetLoginPacket(Err(error)),
            // Client (Owner) to SrcElders
            ListAuthKeysAndVersion => Response::ListAuthKeysAndVersion(Err(error)),

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
            // AData
            PutAData(_) |
            DeleteAData(_) |
            AddPubADataPermissions { .. } |
            AddUnpubADataPermissions { .. } |
            SetADataOwner { .. } |
            AppendSeq { .. } |
            AppendUnseq(_) |
            // Login Packet
            CreateLoginPacket { .. } |
            CreateLoginPacketFor { .. } |
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
            "{}",
            match *self {
                // IData
                PutIData(_) => "Request::PutIData",
                GetIData(_) => "Request::GetIData",
                DeleteUnpubIData(_) => "Request::DeleteUnpubIData",
                // MData
                PutMData(_) => "Request::PutMData",
                GetMData(_) => "Request::GetMData",
                GetMDataValue { .. } => "Request::GetMDataValue",
                DeleteMData(_) => "Request::DeleteMData",
                GetMDataShell(_) => "Request::GetMDataShell",
                GetMDataVersion(_) => "Request::GetMDataVersion",
                ListMDataEntries(_) => "Request::ListMDataEntries",
                ListMDataKeys(_) => "Request::ListMDataKeys",
                ListMDataValues(_) => "Request::ListMDataValues",
                SetMDataUserPermissions { .. } => "Request::SetMDataUserPermissions",
                DelMDataUserPermissions { .. } => "Request::DelMDataUserPermissions",
                ListMDataPermissions(_) => "Request::ListMDataPermissions",
                ListMDataUserPermissions { .. } => "Request::ListMDataUserPermissions",
                MutateMDataEntries { .. } => "Request::MutateMDataEntries",
                // AData
                PutAData(_) => "Request::PutAData",
                GetAData(_) => "Request::GetAData",
                GetADataShell { .. } => "Request::GetADataShell",
                GetADataValue { .. } => "Request::GetADataValue ",
                DeleteAData(_) => "Request::DeleteAData",
                GetADataRange { .. } => "Request::GetADataRange",
                GetADataIndices(_) => "Request::GetADataIndices",
                GetADataLastEntry(_) => "Request::GetADataLastEntry",
                GetADataPermissions { .. } => "Request::GetADataPermissions",
                GetPubADataUserPermissions { .. } => "Request::GetPubADataUserPermissions",
                GetUnpubADataUserPermissions { .. } => "Request::GetUnpubADataUserPermissions",
                GetADataOwners { .. } => "Request::GetADataOwners",
                AddPubADataPermissions { .. } => "Request::AddPubADataPermissions",
                AddUnpubADataPermissions { .. } => "Request::AddUnpubADataPermissions",
                SetADataOwner { .. } => "Request::SetADataOwner",
                AppendSeq { .. } => "Request::AppendSeq",
                AppendUnseq(_) => "Request::AppendUnseq",
                // Coins
                TransferCoins { .. } => "Request::TransferCoins",
                GetBalance => "Request::GetBalance",
                CreateBalance { .. } => "Request::CreateBalance",
                // Login Packet
                CreateLoginPacket { .. } => "Request::CreateLoginPacket",
                CreateLoginPacketFor { .. } => "Request::CreateLoginPacketFor",
                UpdateLoginPacket { .. } => "Request::UpdateLoginPacket",
                GetLoginPacket(..) => "Request::GetLoginPacket",
                // Client (Owner) to SrcElders
                ListAuthKeysAndVersion => "Request::ListAuthKeysAndVersion",
                InsAuthKey { .. } => "Request::InsAuthKey",
                DelAuthKey { .. } => "Request::DelAuthKey",
            }
        )
    }
}
