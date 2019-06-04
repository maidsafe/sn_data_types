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
use crate::immutable_data::UnpubImmutableData;
use crate::mutable_data::{MutableDataRef, SeqMutableData, UnseqMutableData};
use crate::MessageId;
use crate::XorName;
use serde::{Deserialize, Serialize};
use std::fmt;
use threshold_crypto::{PublicKey, Signature};

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
    // Requester.
    requester: Requester,
}

/// RPC Request that is sent to vaults
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Request {
    GetUnpubIData(XorName),
    PutUnpubIData(UnpubImmutableData),
    DeleteUnpubIData(XorName),
    DeleteMData {
        // Address of the mutable data to be fetched
        address: MutableDataRef,
        // Requester public key
        requester: threshold_crypto::PublicKey,
        // Unique message Identifier
        message_id: MessageId,
    },
    GetUnseqMData {
        // Address of the mutable data to be fetched
        address: MutableDataRef,
        requester: Requester,
        // Unique message Identifier
        message_id: MessageId,
    },
    PutUnseqMData {
        // Mutable Data to be stored
        data: UnseqMutableData,
        // Requester public key
        requester: Requester,
        // Unique message Identifier
        message_id: MessageId,
    },

    GetSeqMData {
        address: MutableDataRef,
        requester: Requester,
        message_id: MessageId,
    },

    PutSeqMData {
        data: SeqMutableData,
        requester: Requester,
        message_id: MessageId,
    },

    GetSeqMDataShell {
        address: MutableDataRef,
        requester: threshold_crypto::PublicKey,
        message_id: MessageId,
    },

    GetUnseqMDataShell {
        address: MutableDataRef,
        requester: threshold_crypto::PublicKey,
        message_id: MessageId,
    },

    GetMDataVersion {
        address: MutableDataRef,
        requester: threshold_crypto::PublicKey,
        message_id: MessageId,
    },

    ListUnseqMDataEntries {
        address: MutableDataRef,
        requester: threshold_crypto::PublicKey,
        message_id: MessageId,
    },

    ListSeqMDataEntries {
        address: MutableDataRef,
        requester: threshold_crypto::PublicKey,
        message_id: MessageId,
    },

    ListMDataKeys {
        address: MutableDataRef,
        requester: threshold_crypto::PublicKey,
        message_id: MessageId,
    },

    ListUnseqMDataValues {
        address: MutableDataRef,
        requester: threshold_crypto::PublicKey,
        message_id: MessageId,
    },

    ListSeqMDataValues {
        address: MutableDataRef,
        requester: threshold_crypto::PublicKey,
        message_id: MessageId,
    },

    // ===== Append Only Data =====
    // Get a range of entries from an AppendOnlyData object on the network.
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

        // Requester public key
        requester: Requester,
    },

    // Get current indexes: data, owners, permissions.
    GetADataIndexes {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
        requester: Requester,
    },

    // Get an entry with the current index.
    GetADataLastEntry {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
        requester: Requester,
    },

    // Get permissions at the provided index.
    GetADataPermissions {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
        permissions_index: Index,
        requester: Requester,
    },

    // Get permissions for a specified user(s).
    GetPubADataUserPermissions {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
        permissions_index: Index,
        user: User,
        requester: Requester,
    },

    // Get permissions for a specified public key.
    GetUnpubADataUserPermissions {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
        permissions_index: Index,
        user: PublicKey,
        requester: Requester,
    },

    // Get owners at the provided index.
    GetADataOwners {
        address: AppendOnlyDataRef,
        kind: AppendOnlyKind,
        owners_index: Index,
        requester: Requester,
    },

    // Add a new `permissions` entry.
    // The `Permissions` struct instance MUST contain a valid index.
    AddPubADataPermissions {
        address: AppendOnlyDataRef,
        kind: AppendOnlyKind,
        // New permission set
        permissions: PubPermissions,
        requester: Requester,
    },

    // Add a new `permissions` entry.
    // The `Permissions` struct instance MUST contain a valid index.
    AddUnpubADataPermissions {
        address: AppendOnlyDataRef,
        kind: AppendOnlyKind,
        // New permission set
        permissions: UnpubPermissions,
        requester: Requester,
    },

    // Add a new `owners` entry.
    // The `Owners` struct instance MUST contain a valid index.
    // Only the current owner(s) can perform this action.
    SetADataOwners {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
        owners: Owners,
    },

    // Append operations
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

    // Put a new AppendOnlyData on the network.
    PutAData {
        // AppendOnlyData to be stored
        data: AppendOnlyData,
        // Requester public key
        requester: Requester,
    },

    // Get `AppendOnlyData` shell at a certain point
    // in history (`index` refers to the list of data).
    GetADataShell {
        kind: AppendOnlyKind,
        address: AppendOnlyDataRef,
        data_index: Index,
        requester: Requester,
    },

    // Delete an unpublished unsequenced `AppendOnlyData`.
    // Only the current owner(s) can perform this action.
    DeleteUnseqAData(AppendOnlyDataRef),
    // Delete an unpublished sequenced `AppendOnlyData`.
    // This operation MUST return an error if applied to published AppendOnlyData.
    // Only the current owner(s) can perform this action.
    DeleteSeqAData(AppendOnlyDataRef),
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
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
            Request::DeleteMData { .. } => "Request::DeleteMData",
            // TODO
            ref _x => "Request",
        };
        write!(f, "{}", printable)
    }
}
