// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    ADataAddress, ADataIndex, ADataOwner, ADataPubPermissions, ADataUnpubPermissions, ADataUser,
    AppPermissions, AppendOnlyData as AppendOnlyTrait, AppendOnlyData as ADataTrait, Coins,
    IDataAddress, IDataKind, MDataAddress, MDataPermissionSet, MDataSeqEntryAction,
    MDataUnseqEntryAction, PubSeqAppendOnlyData, PubUnseqAppendOnlyData, PublicKey, SeqMutableData,
    UnpubSeqAppendOnlyData, UnpubUnseqAppendOnlyData, UnseqMutableData, XorName,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub enum AppendOnlyData {
    PubSeq(PubSeqAppendOnlyData),
    UnpubSeq(UnpubSeqAppendOnlyData),
    PubUnseq(PubUnseqAppendOnlyData),
    UnpubUnseq(UnpubUnseqAppendOnlyData),
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
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Request {
    //
    // ===== Immutable Data =====
    //
    PutIData(IDataKind),
    GetIData(IDataAddress),
    DeleteUnpubIData(IDataAddress),
    //
    // ===== Mutable Data =====
    //
    PutUnseqMData(UnseqMutableData),
    PutSeqMData(SeqMutableData),
    GetMData(MDataAddress),
    GetMDataValue {
        address: MDataAddress,
        key: Vec<u8>,
    },
    DeleteMData(MDataAddress),
    GetMDataShell(MDataAddress),
    GetMDataVersion(MDataAddress),
    ListMDataEntries(MDataAddress),
    ListMDataKeys(MDataAddress),
    ListMDataValues(MDataAddress),
    SetMDataUserPermissions {
        address: MDataAddress,
        user: PublicKey,
        permissions: MDataPermissionSet,
        version: u64,
    },
    DelMDataUserPermissions {
        address: MDataAddress,
        user: PublicKey,
        version: u64,
    },
    ListMDataPermissions(MDataAddress),
    ListMDataUserPermissions {
        address: MDataAddress,
        user: PublicKey,
    },
    MutateSeqMDataEntries {
        address: MDataAddress,
        actions: BTreeMap<Vec<u8>, MDataSeqEntryAction>,
    },
    MutateUnseqMDataEntries {
        address: MDataAddress,
        actions: BTreeMap<Vec<u8>, MDataUnseqEntryAction>,
    },
    //
    // ===== Append Only Data =====
    //
    /// Put a new AppendOnlyData onto the network.
    PutAData(AppendOnlyData),
    /// Get AppendOnlyData from the network.
    GetAData(ADataAddress),
    /// Get `AppendOnlyData` shell at a certain point in history (`data_index` refers to the list
    /// of data).
    GetADataShell {
        address: ADataAddress,
        data_index: ADataIndex,
    },
    /// Delete an unpublished unsequenced `AppendOnlyData`.
    ///
    /// This operation MUST return an error if applied to published AppendOnlyData. Only the current
    /// owner(s) can perform this action.
    DeleteAData(ADataAddress),
    /// Get a range of entries from an AppendOnlyData object on the network.
    GetADataRange {
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
        range: (ADataIndex, ADataIndex),
    },
    /// Get current indices: data, owners, permissions.
    GetADataIndices(ADataAddress),
    /// Get an entry with the current index.
    GetADataLastEntry(ADataAddress),
    /// Get permissions at the provided index.
    GetADataPermissions {
        address: ADataAddress,
        permissions_index: ADataIndex,
    },
    /// Get permissions for a specified user(s).
    GetPubADataUserPermissions {
        address: ADataAddress,
        permissions_index: ADataIndex,
        user: ADataUser,
    },
    /// Get permissions for a specified public key.
    GetUnpubADataUserPermissions {
        address: ADataAddress,
        permissions_index: ADataIndex,
        public_key: PublicKey,
    },
    /// Get owners at the provided index.
    GetADataOwners {
        address: ADataAddress,
        owners_index: ADataIndex,
    },
    /// Add a new `permissions` entry.
    AddPubADataPermissions {
        address: ADataAddress,
        permissions: ADataPubPermissions,
    },
    /// Add a new `permissions` entry.
    AddUnpubADataPermissions {
        address: ADataAddress,
        permissions: ADataUnpubPermissions,
    },
    /// Add a new `owners` entry. Only the current owner(s) can perform this action.
    SetADataOwner {
        address: ADataAddress,
        owner: ADataOwner,
    },
    AppendSeq {
        append: AppendOperation,
        index: u64,
    },
    AppendUnseq(AppendOperation),
    //
    // ===== Coins =====
    //
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
    GetBalance(XorName),
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
                PutUnseqMData(_) => "Request::PutUnseqMData",
                PutSeqMData(_) => "Request::PutSeqMData",
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
                MutateSeqMDataEntries { .. } => "Request::MutateSeqMDataEntries",
                MutateUnseqMDataEntries { .. } => "Request::MutateUnseqMDataEntries",
                // AData
                PutAData(_) => "Request::PutAData",
                GetAData(_) => "Request::GetAData",
                GetADataShell { .. } => "Request::GetADataShell",
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
                TransferCoins { .. } => "Request::TransferCoins",
                GetTransaction { .. } => "Request::GetTransaction",
                GetBalance(_) => "Request::GetBalance",
                ListAuthKeysAndVersion => "Request::ListAuthKeysAndVersion",
                InsAuthKey { .. } => "Request::InsAuthKey",
                DelAuthKey { .. } => "Request::DelAuthKey",
            }
        )
    }
}
