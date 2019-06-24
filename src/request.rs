// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    ADataAddress, ADataIndex, ADataIndices, ADataOwner, ADataPubPermissionSet, ADataPubPermissions,
    ADataUnpubPermissionSet, ADataUnpubPermissions, ADataUser, AppPermissions,
    AppendOnlyData as AppendOnlyTrait, Coins, Error, IDataAddress, IDataKind, MDataAddress,
    MDataPermissionSet, MDataSeqEntryAction, MDataUnseqEntryAction, PubSeqAppendOnlyData,
    PubUnseqAppendOnlyData, PublicKey, SeqMutableData, UnpubSeqAppendOnlyData,
    UnpubUnseqAppendOnlyData, UnseqMutableData, XorName,
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

    pub fn permissions_index(&self) -> u64 {
        match self {
            AppendOnlyData::PubSeq(data) => data.permissions_index(),
            AppendOnlyData::PubUnseq(data) => data.permissions_index(),
            AppendOnlyData::UnpubSeq(data) => data.permissions_index(),
            AppendOnlyData::UnpubUnseq(data) => data.permissions_index(),
        }
    }

    pub fn owners_index(&self) -> u64 {
        match self {
            AppendOnlyData::PubSeq(data) => data.owners_index(),
            AppendOnlyData::PubUnseq(data) => data.owners_index(),
            AppendOnlyData::UnpubSeq(data) => data.owners_index(),
            AppendOnlyData::UnpubUnseq(data) => data.owners_index(),
        }
    }

    pub fn in_range(&self, start: ADataIndex, end: ADataIndex) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
        match self {
            AppendOnlyData::PubSeq(data) => data.in_range(start, end),
            AppendOnlyData::PubUnseq(data) => data.in_range(start, end),
            AppendOnlyData::UnpubSeq(data) => data.in_range(start, end),
            AppendOnlyData::UnpubUnseq(data) => data.in_range(start, end),
        }
    }

    pub fn indices(&self) -> Result<ADataIndices, Error> {
        match self {
            AppendOnlyData::PubSeq(data) => Ok(ADataIndices::new(
                data.entry_index(),
                data.owners_index(),
                data.permissions_index(),
            )),
            AppendOnlyData::PubUnseq(data) => Ok(ADataIndices::new(
                data.entry_index(),
                data.owners_index(),
                data.permissions_index(),
            )),
            AppendOnlyData::UnpubSeq(data) => Ok(ADataIndices::new(
                data.entry_index(),
                data.owners_index(),
                data.permissions_index(),
            )),
            AppendOnlyData::UnpubUnseq(data) => Ok(ADataIndices::new(
                data.entry_index(),
                data.owners_index(),
                data.permissions_index(),
            )),
        }
    }

    pub fn last_entry(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        match self {
            AppendOnlyData::PubSeq(data) => data.last(),
            AppendOnlyData::PubUnseq(data) => data.last(),
            AppendOnlyData::UnpubSeq(data) => data.last(),
            AppendOnlyData::UnpubUnseq(data) => data.last(),
        }
    }

    pub fn get_owners(&self, idx: u64) -> Option<&ADataOwner> {
        match self {
            AppendOnlyData::PubSeq(data) => data.fetch_owner_at_index(idx),
            AppendOnlyData::PubUnseq(data) => data.fetch_owner_at_index(idx),
            AppendOnlyData::UnpubSeq(data) => data.fetch_owner_at_index(idx),
            AppendOnlyData::UnpubUnseq(data) => data.fetch_owner_at_index(idx),
        }
    }

    pub fn get_pub_user_permissions(
        &self,
        user: ADataUser,
        idx: u64,
    ) -> Result<ADataPubPermissionSet, Error> {
        match self {
            AppendOnlyData::PubSeq(data) => data.fetch_permissions_at_index(idx),
            AppendOnlyData::PubUnseq(data) => data.fetch_permissions_at_index(idx),
            _ => None,
        }
        .and_then(|permissions| permissions.permissions().get(&user))
        .cloned()
        .ok_or(Error::NoSuchEntry)
    }

    pub fn get_unpub_user_permissions(
        &self,
        user: PublicKey,
        idx: u64,
    ) -> Result<ADataUnpubPermissionSet, Error> {
        match self {
            AppendOnlyData::UnpubSeq(data) => data.fetch_permissions_at_index(idx),
            AppendOnlyData::UnpubUnseq(data) => data.fetch_permissions_at_index(idx),
            _ => None,
        }
        .and_then(|permissions| permissions.permissions().get(&user).cloned())
        .ok_or(Error::NoSuchEntry)
    }

    pub fn get_shell(&self, idx: u64) -> Result<Self, Error> {
        use AppendOnlyData::*;
        match self {
            PubSeq(adata) => adata.shell(idx).map(PubSeq),
            PubUnseq(adata) => adata.shell(idx).map(PubUnseq),
            UnpubSeq(adata) => adata.shell(idx).map(UnpubSeq),
            UnpubUnseq(adata) => adata.shell(idx).map(UnpubUnseq),
        }
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
