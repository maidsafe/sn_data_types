// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::errors::Error;
use crate::immutable_data::UnpubImmutableData;
use crate::mutable_data::{PermissionSet, SeqMutableData, UnseqMutableData, Value};
use crate::{MessageId, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// RPC responses from vaults.
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Response {
    //
    // ===== Immutable Data =====
    //
    GetUnpubIData {
        res: Result<UnpubImmutableData, Error>,
        msg_id: MessageId,
    },
    PutUnpubIData {
        res: Result<(), Error>,
        msg_id: MessageId,
    },
    DeleteUnpubIData {
        res: Result<(), Error>,
        msg_id: MessageId,
    },
    //
    // ===== Mutable Data =====
    //
    /// Get unsequenced Mutable Data.
    GetUnseqMData {
        res: Result<UnseqMutableData, Error>,
        msg_id: MessageId,
    },
    PutUnseqMData {
        res: Result<(), Error>,
        msg_id: MessageId,
    },
    GetSeqMData {
        res: Result<SeqMutableData, Error>,
        msg_id: MessageId,
    },
    PutSeqMData {
        res: Result<(), Error>,
        msg_id: MessageId,
    },
    GetSeqMDataShell {
        res: Result<SeqMutableData, Error>,
        msg_id: MessageId,
    },
    GetUnseqMDataShell {
        res: Result<UnseqMutableData, Error>,
        msg_id: MessageId,
    },
    GetMDataVersion {
        res: Result<u64, Error>,
        msg_id: MessageId,
    },
    ListUnseqMDataEntries {
        res: Result<BTreeMap<Vec<u8>, Vec<u8>>, Error>,
        msg_id: MessageId,
    },
    ListSeqMDataEntries {
        res: Result<BTreeMap<Vec<u8>, Value>, Error>,
        msg_id: MessageId,
    },
    ListMDataKeys {
        res: Result<BTreeSet<Vec<u8>>, Error>,
        msg_id: MessageId,
    },
    ListSeqMDataValues {
        res: Result<Vec<Value>, Error>,
        msg_id: MessageId,
    },
    ListUnseqMDataValues {
        res: Result<Vec<Vec<u8>>, Error>,
        msg_id: MessageId,
    },
    DeleteMData {
        res: Result<(), Error>,
        msg_id: MessageId,
    },
    SetMDataUserPermissions {
        res: Result<(), Error>,
        msg_id: MessageId,
    },
    DelMDataUserPermissions {
        res: Result<(), Error>,
        msg_id: MessageId,
    },
    ListMDataUserPermissions {
        res: Result<PermissionSet, Error>,
        msg_id: MessageId,
    },
    ListMDataPermissions {
        res: Result<BTreeMap<PublicKey, PermissionSet>, Error>,
        msg_id: MessageId,
    },
    MutateSeqMDataEntries {
        res: Result<(), Error>,
        msg_id: MessageId,
    },
    MutateUnseqMDataEntries {
        res: Result<(), Error>,
        msg_id: MessageId,
    },
}

use std::fmt;

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Response::GetUnpubIData { .. } => "Response::GetUnpubIData",
                Response::PutUnpubIData { .. } => "Response::PutUnpubIData",
                Response::DeleteUnpubIData { .. } => "Response::DeleteUnpubIData",
                Response::DeleteMData { .. } => "Response::DeleteMData",
                Response::GetUnseqMData { .. } => "Response::GetUnseqMData",
                Response::PutUnseqMData { .. } => "Response::PutUnseqMData",
                Response::GetSeqMData { .. } => "Response::GetSeqMData",
                Response::PutSeqMData { .. } => "Response::PutSeqMData",
                Response::GetSeqMDataShell { .. } => "Response::GetMDataShell",
                Response::GetUnseqMDataShell { .. } => "Response::GetMDataShell",
                Response::GetMDataVersion { .. } => "Response::GetMDataVersion",
                Response::ListUnseqMDataEntries { .. } => "Response::ListUnseqMDataEntries",
                Response::ListSeqMDataEntries { .. } => "Response::ListSeqMDataEntries",
                Response::ListMDataKeys { .. } => "Response::ListMDataKeys",
                Response::ListSeqMDataValues { .. } => "Response::ListSeqMDataValues",
                Response::ListUnseqMDataValues { .. } => "Response::ListUnseqMDataValues",
                Response::SetMDataUserPermissions { .. } => "Response::SetMDataUserPermissions",
                Response::DelMDataUserPermissions { .. } => "Response::DelMDataUserPermissions",
                Response::ListMDataPermissions { .. } => "Response::ListMDataPermissions",
                Response::ListMDataUserPermissions { .. } => "Response::ListMDataUserPermissions",
                Response::MutateSeqMDataEntries { .. } => "Response::MutateSeqMDataEntries",
                Response::MutateUnseqMDataEntries { .. } => "Response::MutateUnseqMDataEntries",
            }
        )
    }
}
