// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod account_data;

pub use self::account_data::{AccountData, MAX_ACCOUNT_DATA_BYTES};
use crate::{
    AData, ADataAddress, ADataAppend, ADataIndex, ADataOwner, ADataPubPermissions,
    ADataUnpubPermissions, ADataUser, AppPermissions, Coins, IDataAddress, IDataKind, MDataAddress,
    MDataPermissionSet, MDataSeqEntryActions, MDataUnseqEntryActions, PublicKey, SeqMutableData,
    UnseqMutableData, XorName,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub type TransactionId = u64; // TODO: Use the trait UUID

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
        actions: MDataSeqEntryActions,
    },
    MutateUnseqMDataEntries {
        address: MDataAddress,
        actions: MDataUnseqEntryActions,
    },
    //
    // ===== Append Only Data =====
    //
    /// Put a new AppendOnlyData onto the network.
    PutAData(AData),
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
    /// Get transaction
    GetTransaction {
        coins_balance_id: XorName,
        transaction_id: TransactionId,
    },
    /// Get current wallet balance
    GetBalance,
    /// Create a new coin balance
    CreateCoinBalance {
        new_balance_owner: PublicKey,
        amount: Coins,
        transaction_id: TransactionId,
    },
    //
    // ===== Account =====
    //
    CreateAccount(AccountData),
    CreateAccountFor {
        new_account_owner: PublicKey,
        amount: Coins,
        transaction_id: TransactionId,
        new_account: AccountData,
    },
    UpdateAccount(AccountData),
    GetAccount(XorName),
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
                GetBalance => "Request::GetBalance",
                ListAuthKeysAndVersion => "Request::ListAuthKeysAndVersion",
                InsAuthKey { .. } => "Request::InsAuthKey",
                DelAuthKey { .. } => "Request::DelAuthKey",
                CreateCoinBalance { .. } => "Request::CreateCoinBalance",
                CreateAccount { .. } => "Request::CreateAccount",
                CreateAccountFor { .. } => "Request::CreateAccountFor",
                UpdateAccount { .. } => "Request::UpdateAccount",
                GetAccount(..) => "Request::GetAccount",
            }
        )
    }
}
