// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    AData, ADataIndices, ADataOwner, ADataPubPermissionSet, ADataPubPermissions,
    ADataUnpubPermissionSet, ADataUnpubPermissions, AppPermissions, Coins, Entries, IDataKind,
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
    //
    // ===== Mutable Data =====
    //
    /// Get unsequenced Mutable Data.
    GetUnseqMData(Result<UnseqMutableData>),
    GetSeqMData(Result<SeqMutableData>),
    GetSeqMDataShell(Result<SeqMutableData>),
    GetUnseqMDataShell(Result<UnseqMutableData>),
    GetMDataVersion(Result<u64>),
    ListUnseqMDataEntries(Result<BTreeMap<Vec<u8>, Vec<u8>>>),
    ListSeqMDataEntries(Result<BTreeMap<Vec<u8>, MDataValue>>),
    ListMDataKeys(Result<BTreeSet<Vec<u8>>>),
    ListSeqMDataValues(Result<Vec<MDataValue>>),
    ListUnseqMDataValues(Result<Vec<Vec<u8>>>),
    ListMDataUserPermissions(Result<MDataPermissionSet>),
    ListMDataPermissions(Result<BTreeMap<PublicKey, MDataPermissionSet>>),
    GetSeqMDataValue(Result<MDataValue>),
    GetUnseqMDataValue(Result<Vec<u8>>),
    //
    // ===== Append Only Data =====
    //
    GetAData(Result<AData>),
    GetADataShell(Result<AData>),
    GetADataOwners(Result<ADataOwner>),
    GetADataRange(Result<Entries>),
    GetADataIndices(Result<ADataIndices>),
    GetADataLastEntry(Result<(Vec<u8>, Vec<u8>)>),
    GetUnpubADataPermissionAtIndex(Result<ADataUnpubPermissions>),
    GetPubADataPermissionAtIndex(Result<ADataPubPermissions>),
    GetPubADataUserPermissions(Result<ADataPubPermissionSet>),
    GetUnpubADataUserPermissions(Result<ADataUnpubPermissionSet>),
    //
    // ===== Coins =====
    //
    GetTransaction(Result<Transaction>),
    GetBalance(Result<Coins>),
    //
    // ===== Client (Owner) to SrcElders =====
    //
    /// Returns a list of authorised keys from Elders and the account version.
    ListAuthKeysAndVersion(Result<(BTreeMap<PublicKey, AppPermissions>, u64)>),
    //
    // ===== Account =====
    //
    /// Returns an encrypted account packet
    GetAccount(Result<Vec<u8>>),
    //
    /// Returns a success or failure status for a mutation operation.
    Mutation(Result<()>),
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
                // MData
                GetUnseqMData(..) => "Response::GetUnseqMData",
                GetSeqMData(..) => "Response::GetSeqMData",
                GetSeqMDataShell(..) => "Response::GetMDataShell",
                GetUnseqMDataShell(..) => "Response::GetMDataShell",
                GetMDataVersion(..) => "Response::GetMDataVersion",
                ListUnseqMDataEntries(..) => "Response::ListUnseqMDataEntries",
                ListSeqMDataEntries(..) => "Response::ListSeqMDataEntries",
                ListMDataKeys(..) => "Response::ListMDataKeys",
                ListSeqMDataValues(..) => "Response::ListSeqMDataValues",
                ListUnseqMDataValues(..) => "Response::ListUnseqMDataValues",
                ListMDataPermissions(..) => "Response::ListMDataPermissions",
                ListMDataUserPermissions(..) => "Response::ListMDataUserPermissions",
                GetSeqMDataValue(..) => "Response::GetSeqMDataValue",
                GetUnseqMDataValue(..) => "Response::GetUnseqMDataValue",
                GetTransaction(..) => "Response::GetTransaction",
                GetBalance(..) => "Response::GetBalance",
                ListAuthKeysAndVersion(..) => "Response::ListAuthKeysAndVersion",
                GetAData(..) => "Response::GetAData",
                GetADataRange(..) => "Response::GetADataRange",
                GetADataIndices(..) => "Response::GetADataIndices",
                GetADataLastEntry(..) => "Response::GetADataLastEntry",
                GetUnpubADataPermissionAtIndex(..) => "Response::GetADataPermissionAtIndex",
                GetPubADataPermissionAtIndex(..) => "Response::GetADataPermissionAtIndex",
                GetPubADataUserPermissions(..) => "Response::GetPubADataUserPermissions",
                GetUnpubADataUserPermissions(..) => "Response::GetUnpubADataUserPermissions",
                GetADataShell(..) => "Response::GetADataShell",
                GetADataOwners(..) => "Response::GetADataOwners",
                GetAccount(..) => "Response::GetAccount",
                Mutation(..) => "Response::Mutation",
            }
        )
    }
}
