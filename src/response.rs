// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    request::AppendOnlyData, ADataIndices, ADataPubPermissionSet, ADataPubPermissions,
    ADataUnpubPermissionSet, ADataUnpubPermissions, AppPermissions, Coins, IDataKind,
    MDataPermissionSet, MDataValue, PublicKey, Result, SeqMutableData, UnseqMutableData,
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
#[allow(clippy::large_enum_variant, clippy::type_complexity, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Response {
    //
    // ===== Immutable Data =====
    //
    GetIData(Result<IDataKind>),
    PutIData(Result<()>),
    DeleteUnpubIData(Result<()>),
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
    ListSeqMDataEntries(Result<BTreeMap<Vec<u8>, MDataValue>>),
    ListMDataKeys(Result<BTreeSet<Vec<u8>>>),
    ListSeqMDataValues(Result<Vec<MDataValue>>),
    ListUnseqMDataValues(Result<Vec<Vec<u8>>>),
    DeleteMData(Result<()>),
    SetMDataUserPermissions(Result<()>),
    DelMDataUserPermissions(Result<()>),
    ListMDataUserPermissions(Result<MDataPermissionSet>),
    ListMDataPermissions(Result<BTreeMap<PublicKey, MDataPermissionSet>>),
    MutateSeqMDataEntries(Result<()>),
    MutateUnseqMDataEntries(Result<()>),
    GetSeqMDataValue(Result<MDataValue>),
    GetUnseqMDataValue(Result<Vec<u8>>),
    //
    // ===== Append Only Data =====
    //
    PutAData(Result<()>),
    GetAData(Result<AppendOnlyData>),
    GetADataRange(Result<Vec<(Vec<u8>, Vec<u8>)>>),
    GetADataIndices(Result<ADataIndices>),
    GetADataLastEntry(Result<(Vec<u8>, Vec<u8>)>),
    GetUnpubADataPermissionAtIndex(Result<ADataUnpubPermissions>),
    GetPubADataPermissionAtIndex(Result<ADataPubPermissions>),
    GetPubADataUserPermissions(Result<ADataPubPermissionSet>),
    GetUnpubADataUserPermissions(Result<ADataUnpubPermissionSet>),
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
    //
    // ===== Client (Owner) to SrcElders =====
    //
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
        use Response::*;
        write!(
            f,
            "{}",
            match *self {
                // IData
                GetIData(..) => "Response::GetIData",
                PutIData(..) => "Response::PutIData",
                DeleteUnpubIData(..) => "Response::DeleteUnpubIData",
                // MData
                DeleteMData(..) => "Response::DeleteMData",
                GetUnseqMData(..) => "Response::GetUnseqMData",
                PutUnseqMData(..) => "Response::PutUnseqMData",
                GetSeqMData(..) => "Response::GetSeqMData",
                PutSeqMData(..) => "Response::PutSeqMData",
                GetSeqMDataShell(..) => "Response::GetMDataShell",
                GetUnseqMDataShell(..) => "Response::GetMDataShell",
                GetMDataVersion(..) => "Response::GetMDataVersion",
                ListUnseqMDataEntries(..) => "Response::ListUnseqMDataEntries",
                ListSeqMDataEntries(..) => "Response::ListSeqMDataEntries",
                ListMDataKeys(..) => "Response::ListMDataKeys",
                ListSeqMDataValues(..) => "Response::ListSeqMDataValues",
                ListUnseqMDataValues(..) => "Response::ListUnseqMDataValues",
                SetMDataUserPermissions(..) => "Response::SetMDataUserPermissions",
                DelMDataUserPermissions(..) => "Response::DelMDataUserPermissions",
                ListMDataPermissions(..) => "Response::ListMDataPermissions",
                ListMDataUserPermissions(..) => "Response::ListMDataUserPermissions",
                MutateSeqMDataEntries(..) => "Response::MutateSeqMDataEntries",
                MutateUnseqMDataEntries(..) => "Response::MutateUnseqMDataEntries",
                GetSeqMDataValue(..) => "Response::GetSeqMDataValue",
                GetUnseqMDataValue(..) => "Response::GetUnseqMDataValue",
                TransferCoins(..) => "Response::TransferCoins",
                GetTransaction(..) => "Response::GetTransaction",
                GetBalance(..) => "Response::GetBalance",
                ListAuthKeysAndVersion(..) => "Response::ListAuthKeysAndVersion",
                InsAuthKey(..) => "Response::InsAuthKey",
                DelAuthKey(..) => "Response::DelAuthKey",
                PutAData(..) => "Response::PutAData",
                GetAData(..) => "Response::GetAData",
                GetADataRange(..) => "Response::GetADataRange",
                GetADataIndices(..) => "Response::GetADataIndices",
                GetADataLastEntry(..) => "Response::GetADataLastEntry",
                GetUnpubADataPermissionAtIndex(..) => "Response::GetADataPermissionAtIndex",
                GetPubADataPermissionAtIndex(..) => "Response::GetADataPermissionAtIndex",
                GetPubADataUserPermissions(..) => "Response::GetPubADataUserPermissions",
                GetUnpubADataUserPermissions(..) => "Response::GetUnpubADataUserPermissions",
                AddUnpubADataPermissions(..) => "Response::AddUnpubADataPermissions",
                AddPubADataPermissions(..) => "Response::AddPubADataPermissions",
                AppendUnpubSeq(..) => "Response::AppendUnpubSeq",
                AppendPubUnseq(..) => "Response::AppendPubUnseq",
                AppendPubSeq(..) => "Response::AppendPubSeq",
                AppendUnpubUnseq(..) => "Response::AppendUnpubUnseq",
                DeleteAData(..) => "Response::DeleteAData",
            }
        )
    }
}
