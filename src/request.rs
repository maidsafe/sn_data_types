// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    appendable_data::{self, Index, Owners, PubPermissions, UnpubPermissions, User},
    coins::Coins,
    mutable_data::{PermissionSet, SeqEntryAction, UnseqEntryAction},
    ADataAddress, AppPermissions, AppendOnlyData as AppendOnlyTrait, IDataAddress, ImmutableData,
    MDataAddress, MessageId, PubSeqAppendOnlyData, PubUnseqAppendOnlyData, PublicKey,
    SeqMutableData, Signature, UnpubImmutableData, UnpubSeqAppendOnlyData, UnseqMutableData,
    XorName,
};
use rust_sodium::crypto::sign;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub enum Requester {
    Owner(Signature),
    Key(PublicKey),
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub enum AppendOnlyData {
    PubSeq(appendable_data::SeqAppendOnlyData<PubPermissions>),
    UnpubSeq(appendable_data::SeqAppendOnlyData<UnpubPermissions>),
    PubUnseq(appendable_data::UnseqAppendOnlyData<PubPermissions>),
    UnpubUnseq(appendable_data::UnseqAppendOnlyData<UnpubPermissions>),
}

impl AppendOnlyData {
    pub fn address(&self) -> &ADataAddress {
        match self {
            AppendOnlyData::PubSeq(data) => data.address(),
            AppendOnlyData::PubUnseq(data) => data.address(),
            AppendOnlyData::UnpubSeq(data) => data.address(),
            AppendOnlyData::UnpubUnseq(data) => data.address(),
        }
    }

    pub fn name(&self) -> &XorName {
        self.address().name()
    }

    pub fn tag(&self) -> u64 {
        self.address().tag()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct AppendOperation {
    // Address of an AppendOnlyData object on the network.
    pub address: ADataAddress,
    // A list of entries to append.
    pub values: Vec<(Vec<u8>, Vec<u8>)>,
}

/// RPC Request that is sent to vaults
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Request {
    //
    // ===== Immutable Data =====
    //
    /// Get unpublished IData from the network.
    GetUnpubIData {
        address: IDataAddress,
    },
    PutUnpubIData {
        data: UnpubImmutableData,
    },
    /// Delete unpublished IData from the network.
    DeleteUnpubIData {
        address: XorName,
    },
    /// Get published IData from the network.
    GetPubIData {
        address: XorName,
    },
    PutPubIData {
        data: ImmutableData,
    },
    //
    // ===== Mutable Data =====
    //
    /// Delete MData from the network.
    DeleteMData {
        address: MDataAddress,
    },
    GetMData {
        address: MDataAddress,
    },
    PutUnseqMData {
        data: UnseqMutableData,
    },
    GetSeqMData {
        address: MDataAddress,
    },
    GetUnseqMData {
        address: MDataAddress,
    },
    PutSeqMData {
        data: SeqMutableData,
    },
    GetSeqMDataShell {
        address: MDataAddress,
    },

    GetUnseqMDataShell {
        address: MDataAddress,
    },

    GetMDataVersion {
        address: MDataAddress,
    },

    ListUnseqMDataEntries {
        address: MDataAddress,
    },

    ListSeqMDataEntries {
        address: MDataAddress,
    },

    ListMDataKeys {
        address: MDataAddress,
    },

    ListUnseqMDataValues {
        address: MDataAddress,
    },

    ListSeqMDataValues {
        address: MDataAddress,
    },

    SetMDataUserPermissions {
        address: MDataAddress,
        user: PublicKey,
        permissions: PermissionSet,
        version: u64,
    },

    DelMDataUserPermissions {
        address: MDataAddress,
        user: PublicKey,
        version: u64,
    },

    ListMDataPermissions {
        address: MDataAddress,
    },

    ListMDataUserPermissions {
        address: MDataAddress,
        user: PublicKey,
    },

    MutateSeqMDataEntries {
        address: MDataAddress,
        actions: BTreeMap<Vec<u8>, SeqEntryAction>,
    },

    MutateUnseqMDataEntries {
        address: MDataAddress,
        actions: BTreeMap<Vec<u8>, UnseqEntryAction>,
    },

    GetSeqMDataValue {
        address: MDataAddress,
        key: Vec<u8>,
    },

    GetUnseqMDataValue {
        address: MDataAddress,
        key: Vec<u8>,
    },

    GetMDataShell {
        address: MDataAddress,
    },

    ListMDataEntries {
        address: MDataAddress,
    },

    ListMDataValues {
        address: MDataAddress,
    },
    //
    // ===== Append Only Data =====
    //
    /// Get a range of entries from an AppendOnlyData object on the network.
    GetADataRange {
        // Address of an AppendOnlyData object on the network.
        address: ADataAddress,

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

    /// Get current indices: data, owners, permissions.
    GetADataIndices {
        address: ADataAddress,
    },

    /// Get an entry with the current index.
    GetADataLastEntry {
        address: ADataAddress,
    },

    /// Get permissions at the provided index.
    GetADataPermissions {
        address: ADataAddress,
        permissions_index: Index,
    },

    /// Get permissions for a specified user(s).
    GetPubADataUserPermissions {
        address: ADataAddress,
        permissions_index: Index,
        user: User,
    },

    /// Get permissions for a specified public key.
    GetUnpubADataUserPermissions {
        address: ADataAddress,
        permissions_index: Index,
        user: PublicKey,
    },

    /// Get owners at the provided index.
    GetADataOwners {
        address: ADataAddress,
        owners_index: Index,
    },

    /// Add a new `permissions` entry.
    /// The `Permissions` struct instance MUST contain a valid index.
    AddPubADataPermissions {
        address: ADataAddress,
        // New permission set
        permissions: PubPermissions,
    },

    /// Add a new `permissions` entry.
    /// The `Permissions` struct instance MUST contain a valid index.
    AddUnpubADataPermissions {
        address: ADataAddress,
        // New permission set
        permissions: UnpubPermissions,
    },

    /// Add a new `owners` entry.
    /// The `Owners` struct instance MUST contain a valid index.
    /// Only the current owner(s) can perform this action.
    SetADataOwners {
        address: ADataAddress,
        owners: Owners,
    },

    /// Append operations
    AppendPubSeq {
        append: AppendOperation,
        index: u64,
    },
    AppendUnpubSeq {
        append: AppendOperation,
        index: u64,
    },
    AppendPubUnseq(AppendOperation),
    AppendUnpubUnseq(AppendOperation),

    /// Put a new AppendOnlyData onto the network.
    PutAData {
        data: AppendOnlyData,
    },
    /// Get AppendOnlyData from the network.
    GetAData {
        // Address of AppendOnlyData to be retrieved
        address: ADataAddress,
    },
    /// Get `AppendOnlyData` shell at a certain point in history (`data_index` refers to the list
    /// of data).
    GetADataShell {
        address: ADataAddress,
        data_index: Index,
    },

    /// Delete an unpublished unsequenced `AppendOnlyData`.
    ///
    /// This operation MUST return an error if applied to published AppendOnlyData.
    /// Only the current owner(s) can perform this action.
    DeleteAData(ADataAddress),

    // -- Coins --
    /// Balance transfer
    TransferCoins {
        source: XorName,
        destination: XorName,
        amount: Coins,
        transaction_id: u64, // TODO: Use the trait UUID
    },
    /// Get transaction
    GetTransaction {
        coins_balance_id: XorName,
        transaction_id: u64, // TODO: Use the trait UUID
    },
    /// Get current wallet balance
    GetBalance {
        coins_balance_id: XorName,
    },

    // --- Client (Owner) to Elders ---
    // ==========================
    /// Lists authorised keys and version stored by Elders.
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

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "{}",
            match *self {
                //
                // Immutable Data
                //
                Request::GetUnpubIData { .. } => "Request::GetUnpubIData",
                Request::PutUnpubIData { .. } => "Request::PutUnpubIData",
                Request::DeleteUnpubIData { .. } => "Request::DeleteUnpubIData",
                Request::GetPubIData { .. } => "Request::GetPubIData",
                Request::PutPubIData { .. } => "Request::PutPubIData",
                //
                // Mutable Data
                //
                Request::GetUnseqMData { .. } => "Request::GetUnseqMData",
                Request::PutUnseqMData { .. } => "Request::PutUnseqMData",
                Request::PutSeqMData { .. } => "Request::PutSeqMData",
                Request::GetMDataShell { .. } => "Request::GetMDataShell",
                Request::GetMDataVersion { .. } => "Request::GetMDataVersion",
                Request::ListMDataEntries { .. } => "Request::ListMDataEntries",
                Request::ListMDataKeys { .. } => "Request::ListMDataKeys",
                Request::ListUnseqMDataValues { .. } => "Request::ListUnseqMDataValues",
                Request::ListSeqMDataValues { .. } => "Request::ListSeqMDataValues",
                Request::SetMDataUserPermissions { .. } => "Request::SetMDataUserPermissions",
                Request::DeleteMData { .. } => "Request::DeleteMData",
                Request::GetADataRange { .. } => "Request::GetADataRange",
                Request::GetADataLastEntry { .. } => "Request::GetADataLastEntry",
                Request::GetADataIndices { .. } => "Request::GetADataIndexes",
                Request::GetADataPermissions { .. } => "Request::GetADataPermissions",
                Request::ListAuthKeysAndVersion { .. } => "Request::ListAuthKeysAndVersion",
                Request::InsAuthKey { .. } => "Request::InsAuthKey",
                Request::DelAuthKey { .. } => "Request::DelAuthKey",
                // TODO
                ref _x => "Request",
            }
        )
    }
}
