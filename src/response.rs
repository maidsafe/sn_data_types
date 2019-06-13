// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::appendable_data::{
    Indices, PubPermissionSet, PubPermissions, UnpubPermissionSet, UnpubPermissions,
};
use crate::coins::Coins;
use crate::errors::Error;
use crate::immutable_data::{ImmutableData, UnpubImmutableData};
use crate::mutable_data::{PermissionSet, SeqMutableData, UnseqMutableData, Value};
use crate::request::AppendOnlyData;
use crate::{AppPermissions, PublicKey};
use rust_sodium::crypto::sign;
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
    GetUnpubIData(Result<UnpubImmutableData, Error>),
    PutUnpubIData(Result<(), Error>),
    DeleteUnpubIData(Result<(), Error>),
    GetPubIData(Result<ImmutableData, Error>),
    PutPubIData(Result<(), Error>),
    //
    // ===== Mutable Data =====
    //
    /// Get unsequenced Mutable Data.
    GetUnseqMData(Result<UnseqMutableData, Error>),
    PutUnseqMData(Result<(), Error>),
    GetSeqMData(Result<SeqMutableData, Error>),
    PutSeqMData(Result<(), Error>),
    GetSeqMDataShell(Result<SeqMutableData, Error>),
    GetUnseqMDataShell(Result<UnseqMutableData, Error>),
    GetMDataVersion(Result<u64, Error>),
    ListUnseqMDataEntries(Result<BTreeMap<Vec<u8>, Vec<u8>>, Error>),
    ListSeqMDataEntries(Result<BTreeMap<Vec<u8>, Value>, Error>),
    ListMDataKeys(Result<BTreeSet<Vec<u8>>, Error>),
    ListSeqMDataValues(Result<Vec<Value>, Error>),
    ListUnseqMDataValues(Result<Vec<Vec<u8>>, Error>),
    DeleteMData(Result<(), Error>),
    SetMDataUserPermissions(Result<(), Error>),
    DelMDataUserPermissions(Result<(), Error>),
    ListMDataUserPermissions(Result<PermissionSet, Error>),
    ListMDataPermissions(Result<BTreeMap<PublicKey, PermissionSet>, Error>),
    MutateSeqMDataEntries(Result<(), Error>),
    MutateUnseqMDataEntries(Result<(), Error>),
    GetSeqMDataValue(Result<Value, Error>),
    GetUnseqMDataValue(Result<Vec<u8>, Error>),
    //
    // ===== AppendOnly Data =====
    //
    PutAData(Result<(), Error>),
    GetAData(Result<AppendOnlyData, Error>),
    GetADataRange(Result<Vec<(Vec<u8>, Vec<u8>)>, Error>),
    GetADataIndices(Result<Indices, Error>),
    GetADataLastEntry(Result<(Vec<u8>, Vec<u8>), Error>),
    GetUnpubADataPermissionAtIndex(Result<UnpubPermissions, Error>),
    GetPubADataPermissionAtIndex(Result<PubPermissions, Error>),
    GetPubADataUserPermissions(Result<PubPermissionSet, Error>),
    GetUnpubADataUserPermissions(Result<UnpubPermissionSet, Error>),
    AddUnpubADataPermissions(Result<(), Error>),
    AddPubADataPermissions(Result<(), Error>),
    AppendPubSeq(Result<(), Error>),
    AppendUnpubSeq(Result<(), Error>),
    AppendPubUnseq(Result<(), Error>),
    AppendUnpubUnseq(Result<(), Error>),
    DeleteAData(Result<(), Error>),

    //
    // ===== Coins =====
    //
    TransferCoins(Result<(), Error>),
    GetTransaction(Result<Transaction, Error>),
    GetBalance(Result<Coins, Error>),

    // --- Client (Owner) to SrcElders ---
    // ==========================
    /// Returns a list of authorised keys from Elders and the account version.
    ListAuthKeysAndVersion(Result<(BTreeMap<PublicKey, AppPermissions>, u64), Error>),
    /// Returns a success or failure status of adding an authorised key.
    InsAuthKey(Result<(), Error>),
    /// Returns a success or failure status of deleting an authorised key.
    DelAuthKey(Result<(), Error>),
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
