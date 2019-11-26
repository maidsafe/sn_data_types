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
    AData,
    ADataAppend,
    Address,
    AppPermissions,
    Coins,
    Error,
    IData,
    IDataAddress,
    Index,
    MData,
    //MDataAddress, MDataEntryActions, MDataPermissionSet,
    Owner,
    PrivatePermissions,
    PublicKey,
    PublicPermissions,
    Response,
    TransactionId,
    User,
    XorName,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// RPC Request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Request {
    //
    // ===== Immutable Data =====
    //
    PutIData(IData),
    GetIData(IDataAddress),
    DeleteUnpubIData(IDataAddress),
    //
    // ===== Mutable Data =====
    //
    PutMData(MData),
    //GetMData(MDataAddress),
    // GetMDataValue {
    //     address: MDataAddress,
    //     key: Vec<u8>,
    // },
    // DeleteMData(MDataAddress),
    // GetMDataShell(MDataAddress),
    // GetMDataVersion(MDataAddress),
    // ListMDataEntries(MDataAddress),
    // ListMDataKeys(MDataAddress),
    // ListMDataValues(MDataAddress),
    // SetMDataUserPermissions {
    //     address: MDataAddress,
    //     user: PublicKey,
    //     permissions: MDataPermissionSet,
    //     version: u64,
    // },
    // DelMDataUserPermissions {
    //     address: MDataAddress,
    //     user: PublicKey,
    //     version: u64,
    // },
    // ListMDataPermissions(MDataAddress),
    // ListMDataUserPermissions {
    //     address: MDataAddress,
    //     user: PublicKey,
    // },
    // MutateMDataEntries {
    //     address: MDataAddress,
    //     actions: MDataEntryActions,
    // },
    //
    // ===== Append Only Data =====
    //
    /// Put a new AppendOnlyData onto the network.
    PutAData(AData),
    /// Get AppendOnlyData from the network.
    GetAData(Address),
    /// Get `AppendOnlyData` shell at a certain point in history (`data_index` refers to the list
    /// of data).
    GetADataShell {
        address: Address,
        data_index: Index,
    },
    /// Delete an unpublished unsequenced `AppendOnlyData`.
    ///
    /// This operation MUST return an error if applied to published AppendOnlyData. Only the current
    /// owner(s) can perform this action.
    DeleteAData(Address),
    /// Get a range of entries from an AppendOnlyData object on the network.
    GetADataRange {
        address: Address,
        // Range of entries to fetch.
        //
        // For example, get 10 last entries:
        // range: (Index::FromEnd(10), Index::FromEnd(0))
        //
        // Get all entries:
        // range: (Index::FromStart(0), Index::FromEnd(0))
        //
        // Get first 5 entries:
        // range: (Index::FromStart(0), Index::FromStart(5))
        range: (Index, Index),
    },
    GetADataValue {
        address: Address,
        key: Vec<u8>,
    },
    /// Get current indices: data, owners, permissions.
    GetADataIndices(Address),
    /// Get an entry with the current index.
    GetADataLastEntry(Address),
    /// Get permissions at the provided index.
    GetADataPermissions {
        address: Address,
        permissions_index: Index,
    },
    /// Get permissions for a specified user(s).
    GetPubUserPermissions {
        address: Address,
        permissions_index: Index,
        user: User,
    },
    /// Get permissions for a specified public key.
    GetUnpubUserPermissions {
        address: Address,
        permissions_index: Index,
        public_key: PublicKey,
    },
    /// Get owners at the provided index.
    GetOwners {
        address: Address,
        owners_index: Index,
    },
    /// Add a new `permissions` entry.
    AddPubADataPermissions {
        address: Address,
        permissions: PublicPermissions,
        permissions_idx: u64,
    },
    /// Add a new `permissions` entry.
    AddUnpubADataPermissions {
        address: Address,
        permissions: PrivatePermissions,
        permissions_idx: u64,
    },
    /// Add a new `owners` entry. Only the current owner(s) can perform this action.
    SetOwner {
        address: Address,
        owner: Owner,
        owners_idx: u64,
    },
    AppendSeq {
        append: ADataAppend,
        index: u64,
    },
    AppendUnseq(ADataAppend),
    //
    // ===== Coins =====
    //
    /// Balance transfer
    TransferCoins {
        destination: XorName,
        amount: Coins,
        transaction_id: TransactionId,
    },
    /// Get current wallet balance
    GetBalance,
    /// Create a new coin balance
    CreateBalance {
        new_balance_owner: PublicKey,
        amount: Coins,
        transaction_id: TransactionId,
    },
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
    GetLoginPacket(XorName),
    //
    // ===== Client (Owner) to SrcElders =====
    //
    /// List authorised keys and version stored by Elders.
    ListAuthKeysAndVersion,
    /// Inserts an authorised key (for an app, user, etc.).
    InsAuthKey {
        /// Authorised key to be inserted
        key: PublicKey,
        /// Incremented version
        version: u64,
        /// Permissions
        permissions: AppPermissions,
    },
    /// Deletes an authorised key.
    DelAuthKey {
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

        match *self {
            // IData
            GetIData(_) => Response::GetIData(Err(error)),
            // MData
            //GetMData(_) => Response::GetMData(Err(error)),
            //GetMDataValue { .. } => Response::GetMDataValue(Err(error)),
            //GetMDataShell(_) => Response::GetMDataShell(Err(error)),
            //GetMDataVersion(_) => Response::GetMDataVersion(Err(error)),
            //ListMDataEntries(_) => Response::ListMDataEntries(Err(error)),
            //ListMDataKeys(_) => Response::ListMDataKeys(Err(error)),
            //ListMDataValues(_) => Response::ListMDataValues(Err(error)),
            //ListMDataPermissions(_) => Response::ListMDataPermissions(Err(error)),
            //ListMDataUserPermissions { .. } => Response::ListMDataUserPermissions(Err(error)),
            // AData
            GetAData(_) => Response::GetAData(Err(error)),
            GetADataShell { .. } => Response::GetADataShell(Err(error)),
            GetADataValue { .. } => Response::GetADataValue(Err(error)),
            GetADataRange { .. } => Response::GetADataRange(Err(error)),
            GetADataIndices(_) => Response::GetExpectedIndices(Err(error)),
            GetADataLastEntry(_) => Response::GetADataLastEntry(Err(error)),
            GetADataPermissions { .. } => Response::GetADataPermissions(Err(error)),
            GetPubUserPermissions { .. } => Response::GetPubADataUserPermissions(Err(error)),
            GetUnpubUserPermissions { .. } => {
                Response::GetUnpubADataUserPermissions(Err(error))
            }
            GetOwners { .. } => Response::GetOwners(Err(error)),
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
            //DeleteMData(_) |
            //SetMDataUserPermissions { .. } |
            //DelMDataUserPermissions { .. } |
            //MutateMDataEntries { .. } |
            // AData
            PutAData(_) |
            DeleteAData(_) |
            AddPubADataPermissions { .. } |
            AddUnpubADataPermissions { .. } |
            SetOwner { .. } |
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
                // GetMData(_) => "Request::GetMData",
                // GetMDataValue { .. } => "Request::GetMDataValue",
                // DeleteMData(_) => "Request::DeleteMData",
                // GetMDataShell(_) => "Request::GetMDataShell",
                // GetMDataVersion(_) => "Request::GetMDataVersion",
                // ListMDataEntries(_) => "Request::ListMDataEntries",
                // ListMDataKeys(_) => "Request::ListMDataKeys",
                // ListMDataValues(_) => "Request::ListMDataValues",
                // SetMDataUserPermissions { .. } => "Request::SetMDataUserPermissions",
                // DelMDataUserPermissions { .. } => "Request::DelMDataUserPermissions",
                // ListMDataPermissions(_) => "Request::ListMDataPermissions",
                // ListMDataUserPermissions { .. } => "Request::ListMDataUserPermissions",
                // MutateMDataEntries { .. } => "Request::MutateMDataEntries",
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
                GetPubUserPermissions { .. } => "Request::GetPubUserPermissions",
                GetUnpubUserPermissions { .. } => "Request::GetUnpubUserPermissions",
                GetOwners { .. } => "Request::GetOwners",
                AddPubADataPermissions { .. } => "Request::AddPubADataPermissions",
                AddUnpubADataPermissions { .. } => "Request::AddUnpubADataPermissions",
                SetOwner { .. } => "Request::SetOwner",
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
