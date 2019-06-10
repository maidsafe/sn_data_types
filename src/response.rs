// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::coins::Coins;
use crate::errors::Error;
use crate::immutable_data::UnpubImmutableData;
use crate::mutable_data::{PermissionSet, SeqMutableData, UnseqMutableData, Value};
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
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Response {
    //
    // ===== Immutable Data =====
    //
    GetUnpubIData(Result<UnpubImmutableData, Error>),
    PutUnpubIData(Result<(), Error>),
    DeleteUnpubIData(Result<(), Error>),
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

    //
    // ===== Coins =====
    //
    TransferCoins(Result<(), Error>),
    GetTransaction(Result<Transaction, Error>),
    GetBalance(Result<Coins, Error>),

    // --- Client (Owner) to SrcElders ---
    // ==========================
    /// Returns a list of authorised keys from Elders and the account version.
    ListAuthKeysAndVersion(Result<(BTreeMap<sign::PublicKey, AppPermissions>, u64), Error>),
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
                Response::GetUnpubIData(..) => "Response::GetUnpubIData",
                Response::PutUnpubIData(..) => "Response::PutUnpubIData",
                Response::DeleteUnpubIData(..) => "Response::DeleteUnpubIData",
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
                Response::TransferCoins(..) => "Response::TransferCoins",
                Response::GetTransaction(..) => "Response::GetTransaction",
                Response::GetBalance(..) => "Response::GetBalance",
                Response::ListAuthKeysAndVersion(..) => "Response::ListAuthKeysAndVersion",
                Response::InsAuthKey(..) => "Response::InsAuthKey",
                Response::DelAuthKey(..) => "Response::DelAuthKey",
            }
        )
    }
}
