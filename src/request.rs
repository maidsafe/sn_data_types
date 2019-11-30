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
    Address,
    AppPermissions,
    BlobAddress,
    BlobData,
    Coins,
    Error,
    Index,
    MapData,
    //MapAddress, MapEntryActions, MapPermissionSet,
    Owner,
    PrivatePermissions,
    PublicKey,
    PublicPermissions,
    Response,
    SequenceAppend,
    SequenceData,
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
    // ===== Blob =====
    //
    PutBlob(BlobData),
    GetBlob(BlobAddress),
    DeleteUnpubBlob(BlobAddress),
    //
    // ===== Map =====
    //
    PutMap(MapData),
    //GetMap(MapAddress),
    // GetMapValue {
    //     address: MapAddress,
    //     key: Vec<u8>,
    // },
    // DeleteMap(MapAddress),
    // GetMapShell(MapAddress),
    // GetMapVersion(MapAddress),
    // ListMapEntries(MapAddress),
    // ListMapKeys(MapAddress),
    // ListMapValues(MapAddress),
    // SetMapUserPermissions {
    //     address: MapAddress,
    //     user: PublicKey,
    //     permissions: MapPermissionSet,
    //     version: u64,
    // },
    // DelMapUserPermissions {
    //     address: MapAddress,
    //     user: PublicKey,
    //     version: u64,
    // },
    // ListMapPermissions(MapAddress),
    // ListMapUserPermissions {
    //     address: MapAddress,
    //     user: PublicKey,
    // },
    // MutateMapEntries {
    //     address: MapAddress,
    //     actions: MapEntryActions,
    // },
    //
    // ===== Append Only Data =====
    //
    /// Put a new AppendOnlyData onto the network.
    PutSequence(SequenceData),
    /// Get AppendOnlyData from the network.
    GetSequence(Address),
    /// Get `AppendOnlyData` shell at a certain point in history (`data_index` refers to the list
    /// of data).
    GetSequenceShell {
        address: Address,
        data_index: Index,
    },
    /// Delete an unpublished unsequenced `AppendOnlyData`.
    ///
    /// This operation MUST return an error if applied to published AppendOnlyData. Only the current
    /// owner(s) can perform this action.
    DeleteSequence(Address),
    /// Get a range of entries from an AppendOnlyData object on the network.
    GetSequenceRange {
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
    GetSequenceValue {
        address: Address,
        key: Vec<u8>,
    },
    /// Get current indices: data, owners, permissions.
    GetSequenceIndices(Address),
    /// Get an entry with the current index.
    GetSequenceLastEntry(Address),
    /// Get permissions at the provided index.
    GetSequencePermissions {
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
    AddPubSequencePermissions {
        address: Address,
        permissions: PublicPermissions,
        permissions_idx: u64,
    },
    /// Add a new `permissions` entry.
    AddUnpubSequencePermissions {
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
        append: SequenceAppend,
        index: u64,
    },
    AppendUnseq(SequenceAppend),
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
            // Blob
            GetBlob(_) => Response::GetBlob(Err(error)),
            // Map
            //GetMap(_) => Response::GetMap(Err(error)),
            //GetMapValue { .. } => Response::GetMapValue(Err(error)),
            //GetMapShell(_) => Response::GetMapShell(Err(error)),
            //GetMapVersion(_) => Response::GetMapVersion(Err(error)),
            //ListMapEntries(_) => Response::ListMapEntries(Err(error)),
            //ListMapKeys(_) => Response::ListMapKeys(Err(error)),
            //ListMapValues(_) => Response::ListMapValues(Err(error)),
            //ListMapPermissions(_) => Response::ListMapPermissions(Err(error)),
            //ListMapUserPermissions { .. } => Response::ListMapUserPermissions(Err(error)),
            // Sequence
            GetSequence(_) => Response::GetSequence(Err(error)),
            GetSequenceShell { .. } => Response::GetSequenceShell(Err(error)),
            GetSequenceValue { .. } => Response::GetSequenceValue(Err(error)),
            GetSequenceRange { .. } => Response::GetSequenceRange(Err(error)),
            GetSequenceIndices(_) => Response::GetExpectedIndices(Err(error)),
            GetSequenceLastEntry(_) => Response::GetSequenceLastEntry(Err(error)),
            GetSequencePermissions { .. } => Response::GetSequencePermissions(Err(error)),
            GetPubUserPermissions { .. } => Response::GetPubSequenceUserPermissions(Err(error)),
            GetUnpubUserPermissions { .. } => {
                Response::GetUnpubSequenceUserPermissions(Err(error))
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

            // Blob
            PutBlob(_) |
            DeleteUnpubBlob(_) |
            // Map
            PutMap(_) |
            //DeleteMap(_) |
            //SetMapUserPermissions { .. } |
            //DelMapUserPermissions { .. } |
            //MutateMapEntries { .. } |
            // Sequence
            PutSequence(_) |
            DeleteSequence(_) |
            AddPubSequencePermissions { .. } |
            AddUnpubSequencePermissions { .. } |
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
                // Blob
                PutBlob(_) => "Request::PutBlob",
                GetBlob(_) => "Request::GetBlob",
                DeleteUnpubBlob(_) => "Request::DeleteUnpubBlob",
                // Map
                PutMap(_) => "Request::PutMap",
                // GetMap(_) => "Request::GetMap",
                // GetMapValue { .. } => "Request::GetMapValue",
                // DeleteMap(_) => "Request::DeleteMap",
                // GetMapShell(_) => "Request::GetMapShell",
                // GetMapVersion(_) => "Request::GetMapVersion",
                // ListMapEntries(_) => "Request::ListMapEntries",
                // ListMapKeys(_) => "Request::ListMapKeys",
                // ListMapValues(_) => "Request::ListMapValues",
                // SetMapUserPermissions { .. } => "Request::SetMapUserPermissions",
                // DelMapUserPermissions { .. } => "Request::DelMapUserPermissions",
                // ListMapPermissions(_) => "Request::ListMapPermissions",
                // ListMapUserPermissions { .. } => "Request::ListMapUserPermissions",
                // MutateMapEntries { .. } => "Request::MutateMapEntries",
                // Sequence
                PutSequence(_) => "Request::PutSequence",
                GetSequence(_) => "Request::GetSequence",
                GetSequenceShell { .. } => "Request::GetSequenceShell",
                GetSequenceValue { .. } => "Request::GetSequenceValue ",
                DeleteSequence(_) => "Request::DeleteSequence",
                GetSequenceRange { .. } => "Request::GetSequenceRange",
                GetSequenceIndices(_) => "Request::GetSequenceIndices",
                GetSequenceLastEntry(_) => "Request::GetSequenceLastEntry",
                GetSequencePermissions { .. } => "Request::GetSequencePermissions",
                GetPubUserPermissions { .. } => "Request::GetPubUserPermissions",
                GetUnpubUserPermissions { .. } => "Request::GetUnpubUserPermissions",
                GetOwners { .. } => "Request::GetOwners",
                AddPubSequencePermissions { .. } => "Request::AddPubSequencePermissions",
                AddUnpubSequencePermissions { .. } => "Request::AddUnpubSequencePermissions",
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
