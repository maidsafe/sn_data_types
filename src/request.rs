// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::appendable_data::{
    self, AppendOnlyDataRef, AppendOnlyKind, Index, Owners, PubPermissions, UnpubPermissions, User,
};
use crate::coins::Coins;
use crate::immutable_data::UnpubImmutableData;
use crate::mutable_data::{
    MutableDataRef, PermissionSet, SeqEntryAction, SeqMutableData, UnseqEntryAction,
    UnseqMutableData,
};
use crate::PublicKey;
use crate::{AppPermissions, MessageId, XorName};
use rust_sodium::crypto::sign;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use threshold_crypto::Signature;

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

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct AppendOperation {
    // Address of an AppendOnlyData object on the network.
    address: AppendOnlyDataRef,
    // A list of entries to append.
    values: Vec<(Vec<u8>, Vec<u8>)>,
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
        address: XorName,
    },
    PutUnpubIData {
        data: UnpubImmutableData,
    },
    DeleteUnpubIData {
        address: XorName,
    },
    //
    // ===== Mutable Data =====
    //
    /// Delete MData from the network.
    DeleteMData {
        // Address of the mutable data to be fetched
        address: MutableDataRef,
    },
    GetUnseqMData {
        // Address of the mutable data to be fetched
        address: MutableDataRef,
    },
    PutUnseqMData {
        // Mutable Data to be stored
        data: UnseqMutableData,
    },

    GetSeqMData {
        address: MutableDataRef,
    },

    PutSeqMData {
        data: SeqMutableData,
    },

    GetSeqMDataShell {
        address: MutableDataRef,
    },

    GetUnseqMDataShell {
        address: MutableDataRef,
    },

    GetMDataVersion {
        address: MutableDataRef,
    },

    ListUnseqMDataEntries {
        address: MutableDataRef,
    },

    ListSeqMDataEntries {
        address: MutableDataRef,
    },

    ListMDataKeys {
        address: MutableDataRef,
    },

    ListUnseqMDataValues {
        address: MutableDataRef,
    },

    ListSeqMDataValues {
        address: MutableDataRef,
    },

    SetMDataUserPermissions {
        address: MutableDataRef,
        user: PublicKey,
        permissions: PermissionSet,
        version: u64,
        requester: Requester,
        message_id: MessageId,
    },

    DelMDataUserPermissions {
        address: MutableDataRef,
        user: PublicKey,
        version: u64,
        requester: Requester,
        message_id: MessageId,
    },

    ListMDataPermissions {
        address: MutableDataRef,
        requester: Requester,
        message_id: MessageId,
    },

    ListMDataUserPermissions {
        address: MutableDataRef,
        user: PublicKey,
        requester: Requester,
        message_id: MessageId,
    },

    MutateSeqMDataEntries {
        address: MutableDataRef,
        actions: BTreeMap<Vec<u8>, SeqEntryAction>,
        requester: Requester,
        message_id: MessageId,
    },

    MutateUnseqMDataEntries {
        address: MutableDataRef,
        actions: BTreeMap<Vec<u8>, UnseqEntryAction>,
        requester: Requester,
        message_id: MessageId,
    },

    GetSeqMDataValue {
        address: MutableDataRef,
        key: Vec<u8>,
        requester: Requester,
    },

    GetUnseqMDataValue {
        address: MutableDataRef,
        key: Vec<u8>,
        requester: Requester,
    },
    //
    // ===== Append Only Data =====
    //
    /// Get a range of entries from an AppendOnlyData object on the network.
    GetADataRange {
        // Type of AppendOnlyData (published/unpublished, sequenced/unsequenced).
        kind: AppendOnlyKind,

        // Address of an AppendOnlyData object on the network.
        address: AppendOnlyDataRef,

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

    /// Get current indexes: data, owners, permissions.
    GetADataIndexes {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
    },

    /// Get an entry with the current index.
    GetADataLastEntry {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
    },

    /// Get permissions at the provided index.
    GetADataPermissions {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
        permissions_index: Index,
    },

    /// Get permissions for a specified user(s).
    GetPubADataUserPermissions {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
        permissions_index: Index,
        user: User,
    },

    /// Get permissions for a specified public key.
    GetUnpubADataUserPermissions {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
        permissions_index: Index,
        user: PublicKey,
    },

    /// Get owners at the provided index.
    GetADataOwners {
        address: AppendOnlyDataRef,
        kind: AppendOnlyKind,
        owners_index: Index,
    },

    /// Add a new `permissions` entry.
    /// The `Permissions` struct instance MUST contain a valid index.
    AddPubADataPermissions {
        address: AppendOnlyDataRef,
        kind: AppendOnlyKind,
        // New permission set
        permissions: PubPermissions,
    },

    /// Add a new `permissions` entry.
    /// The `Permissions` struct instance MUST contain a valid index.
    AddUnpubADataPermissions {
        address: AppendOnlyDataRef,
        kind: AppendOnlyKind,
        // New permission set
        permissions: UnpubPermissions,
    },

    /// Add a new `owners` entry.
    /// The `Owners` struct instance MUST contain a valid index.
    /// Only the current owner(s) can perform this action.
    SetADataOwners {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
        owners: Owners,
    },

    /// Append operations
    AppendPublishedSeq {
        append: AppendOperation,
        index: u64,
    },
    AppendUnpublishedSeq {
        append: AppendOperation,
        index: u64,
    },
    AppendPublishedUnseq(AppendOperation),
    AppendUnpublishedUnseq(AppendOperation),

    /// Put a new AppendOnlyData on the network.
    PutAData {
        // AppendOnlyData to be stored
        data: AppendOnlyData,
    },

    /// Get `AppendOnlyData` shell at a certain point
    /// in history (`index` refers to the list of data).
    GetADataShell {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
        data_index: Index,
    },

    /// Delete an unpublished unsequenced `AppendOnlyData`.
    /// Only the current owner(s) can perform this action.
    DeleteUnseqAData(AppendOnlyDataRef),
    /// Delete an unpublished sequenced `AppendOnlyData`.
    /// This operation MUST return an error if applied to published AppendOnlyData.
    /// Only the current owner(s) can perform this action.
    DeleteSeqAData(AppendOnlyDataRef),

    // -- Coins --
    /// Balance transfer
    TransferCoins {
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
    ListAuthKeysAndVersion(MessageId),
    /// Inserts an authorised key (for an app, user, etc.).
    InsAuthKey {
        /// Authorised key to be inserted
        key: sign::PublicKey,
        /// Incremented version
        version: u64,
        /// Permissions
        permissions: AppPermissions,
    },
    /// Deletes an authorised key.
    DelAuthKey {
        /// Authorised key to be deleted
        key: sign::PublicKey,
        /// Incremented version
        version: u64,
    },
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Request::GetUnpubIData { .. } => "Request::GetUnpubIData",
                Request::PutUnpubIData { .. } => "Request::PutUnpubIData",
                Request::DeleteUnpubIData { .. } => "Request::DeleteUnpubIData",
                Request::GetUnseqMData { .. } => "Request::GetUnseqMData",
                Request::PutUnseqMData { .. } => "Request::PutUnseqMData",
                Request::GetSeqMData { .. } => "Request::GetSeqMData",
                Request::PutSeqMData { .. } => "Request::PutSeqMData",
                Request::GetSeqMDataShell { .. } => "Request::GetSeqMDataShell",
                Request::GetUnseqMDataShell { .. } => "Request::GetUnseqMDataShell",
                Request::GetMDataVersion { .. } => "Request::GetMDataVersion",
                Request::ListUnseqMDataEntries { .. } => "Request::ListUnseqMDataEntries",
                Request::ListSeqMDataEntries { .. } => "Request::ListSeqMDataEntries",
                Request::ListMDataKeys { .. } => "Request::ListMDataKeys",
                Request::ListUnseqMDataValues { .. } => "Request::ListUnseqMDataValues",
                Request::ListSeqMDataValues { .. } => "Request::ListSeqMDataValues",
                Request::SetMDataUserPermissions { .. } => "Request::SetMDataUserPermissions",
                Request::DeleteMData { .. } => "Request::DeleteMData",
                Request::GetADataRange { .. } => "Request::GetADataRange",
                Request::GetADataLastEntry { .. } => "Request::GetADataLastEntry",
                Request::GetADataIndexes { .. } => "Request::GetADataIndexes",
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
