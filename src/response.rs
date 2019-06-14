// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    append_only_data::{
        Indices, PubPermissionSet, PubPermissions, UnpubPermissionSet, UnpubPermissions,
    },
    mutable_data::{PermissionSet, SeqMutableData, UnseqMutableData, Value},
    request::AppendOnlyData,
    AppPermissions, Coins, ImmutableData, PublicKey, Result, UnpubImmutableData,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Safecoin transaction.
#[derive(Copy, Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub enum Transaction {
    /// The associated `CoinBalance` was successfully credited with this `Credit`.
    Success(Coins),
    /// This transaction is not known by the associated `CoinBalance`.  This could be because it was
    /// never known, or is no longer known.
    NoSuchTransaction,
    /// The requested `CoinBalance` doesn't exist.
    NoSuchCoinBalance,
}

/// RPC responses from vaults.
#[allow(clippy::large_enum_variant, clippy::type_complexity)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Response {
    //
    // ===== Immutable Data =====
    //
    GetUnpubIData(Result<UnpubImmutableData>),
    PutUnpubIData(Result<()>),
    DeleteUnpubIData(Result<()>),
    GetPubIData(Result<ImmutableData>),
    PutPubIData(Result<()>),
    //
    // ===== Mutable Data =====
    //
    /// Get unsequenced Mutable Data.
    GetUnseqMData(Result<UnseqMutableData>),
    PutUnseqMData(Result<()>),
    GetSeqMData(Result<SeqMutableData>),
    PutSeqMData(Result<()>),
    GetSeqMDataShell(Result<SeqMutableData>),
    GetUnseqMDataShell(Result<UnseqMutableData>),
    GetMDataVersion(Result<u64>),
    ListUnseqMDataEntries(Result<BTreeMap<Vec<u8>, Vec<u8>>>),
    ListSeqMDataEntries(Result<BTreeMap<Vec<u8>, Value>>),
    ListMDataKeys(Result<BTreeSet<Vec<u8>>>),
    ListSeqMDataValues(Result<Vec<Value>>),
    ListUnseqMDataValues(Result<Vec<Vec<u8>>>),
    DeleteMData(Result<()>),
    SetMDataUserPermissions(Result<()>),
    DelMDataUserPermissions(Result<()>),
    ListMDataUserPermissions(Result<PermissionSet>),
    ListMDataPermissions(Result<BTreeMap<PublicKey, PermissionSet>>),
    MutateSeqMDataEntries(Result<()>),
    MutateUnseqMDataEntries(Result<()>),
    GetSeqMDataValue(Result<Value>),
    GetUnseqMDataValue(Result<Vec<u8>>),
    //
    // ===== AppendOnly Data =====
    //
    PutAData(Result<()>),
    GetAData(Result<AppendOnlyData>),
    GetADataRange(Result<Vec<(Vec<u8>, Vec<u8>)>>),
    GetADataIndices(Result<Indices>),
    GetADataLastEntry(Result<(Vec<u8>, Vec<u8>)>),
    GetUnpubADataPermissionAtIndex(Result<UnpubPermissions>),
    GetPubADataPermissionAtIndex(Result<PubPermissions>),
    GetPubADataUserPermissions(Result<PubPermissionSet>),
    GetUnpubADataUserPermissions(Result<UnpubPermissionSet>),
    AddUnpubADataPermissions(Result<()>),
    AddPubADataPermissions(Result<()>),
    AppendPubSeq(Result<()>),
    AppendUnpubSeq(Result<()>),
    AppendPubUnseq(Result<()>),
    AppendUnpubUnseq(Result<()>),
    DeleteAData(Result<()>),

    //
    // ===== Coins =====
    //
    TransferCoins(Result<()>),
    GetTransaction(Result<Transaction>),
    GetBalance(Result<Coins>),

    // --- Client (Owner) to SrcElders ---
    // ==========================
    /// Returns a list of authorised keys from Elders and the account version.
    ListAuthKeysAndVersion(Result<(BTreeMap<PublicKey, AppPermissions>, u64)>),
    /// Returns a success or failure status of adding an authorised key.
    InsAuthKey(Result<()>),
    /// Returns a success or failure status of deleting an authorised key.
    DelAuthKey(Result<()>),
}

use std::fmt;

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                //
                // Immutable Data
                //
                Response::GetUnpubIData(..) => "Response::GetUnpubIData",
                Response::PutUnpubIData(..) => "Response::PutUnpubIData",
                Response::DeleteUnpubIData(..) => "Response::DeleteUnpubIData",
                Response::GetPubIData(..) => "Response::GetPubIData",
                Response::PutPubIData(..) => "Response::PutPubIData",
                //
                // Mutable Data
                //
                Response::DeleteMData(..) => "Response::DeleteMData",
                Response::GetUnseqMData(..) => "Response::GetUnseqMData",
                Response::PutUnseqMData(..) => "Response::PutUnseqMData",
                Response::GetSeqMData(..) => "Response::GetSeqMData",
                Response::PutSeqMData(..) => "Response::PutSeqMData",
                Response::GetSeqMDataShell(..) => "Response::GetMDataShell",
                Response::GetUnseqMDataShell(..) => "Response::GetMDataShell",
                Response::GetMDataVersion(..) => "Response::GetMDataVersion",
                Response::ListUnseqMDataEntries(..) => "Response::ListUnseqMDataEntries",
                Response::ListSeqMDataEntries(..) => "Response::ListSeqMDataEntries",
                Response::ListMDataKeys(..) => "Response::ListMDataKeys",
                Response::ListSeqMDataValues(..) => "Response::ListSeqMDataValues",
                Response::ListUnseqMDataValues(..) => "Response::ListUnseqMDataValues",
                Response::SetMDataUserPermissions(..) => "Response::SetMDataUserPermissions",
                Response::DelMDataUserPermissions(..) => "Response::DelMDataUserPermissions",
                Response::ListMDataPermissions(..) => "Response::ListMDataPermissions",
                Response::ListMDataUserPermissions(..) => "Response::ListMDataUserPermissions",
                Response::MutateSeqMDataEntries(..) => "Response::MutateSeqMDataEntries",
                Response::MutateUnseqMDataEntries(..) => "Response::MutateUnseqMDataEntries",
                Response::GetSeqMDataValue { .. } => "Response::GetSeqMDataValue",
                Response::GetUnseqMDataValue { .. } => "Response::GetUnseqMDataValue",
                Response::TransferCoins(..) => "Response::TransferCoins",
                Response::GetTransaction(..) => "Response::GetTransaction",
                Response::GetBalance(..) => "Response::GetBalance",
                Response::ListAuthKeysAndVersion(..) => "Response::ListAuthKeysAndVersion",
                Response::InsAuthKey(..) => "Response::InsAuthKey",
                Response::DelAuthKey(..) => "Response::DelAuthKey",
                Response::PutAData(..) => "Response::PutAData",
                Response::GetAData(..) => "Response::GetAData",
                Response::GetADataRange(..) => "Response::GetADataRange",
                Response::GetADataIndices(..) => "Response::GetADataIndices",
                Response::GetADataLastEntry(..) => "Response::GetADataLastEntry",
                Response::GetUnpubADataPermissionAtIndex(..) => {
                    "Response::GetADataPermissionAtIndex"
                }
                Response::GetPubADataPermissionAtIndex(..) => "Response::GetADataPermissionAtIndex",
                Response::GetPubADataUserPermissions(..) => "Response::GetPubADataUserPermissions",
                Response::GetUnpubADataUserPermissions(..) => {
                    "Response::GetUnpubADataUserPermissions"
                }
                Response::AddUnpubADataPermissions(..) => "Response::AddUnpubADataPermissions",
                Response::AddPubADataPermissions(..) => "Response::AddPubADataPermissions",
                Response::AppendUnpubSeq(..) => "Response::AppendUnpubSeq",
                Response::AppendPubUnseq(..) => "Response::AppendPubUnseq",
                Response::AppendPubSeq(..) => "Response::AppendPubSeq",
                Response::AppendUnpubUnseq(..) => "Response::AppendUnpubUnseq",
                Response::DeleteAData(..) => "Response::DeleteAData",
            }
        )
    }
}
