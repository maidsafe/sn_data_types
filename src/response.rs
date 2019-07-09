// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    errors::ErrorDebug, AData, ADataEntries, ADataIndices, ADataOwner, ADataPubPermissionSet,
    ADataPubPermissions, ADataUnpubPermissionSet, ADataUnpubPermissions, AppPermissions, Coins,
    IData, MData, MDataPermissionSet, MDataValue, PublicKey, Result, Signature, Transaction,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// RPC responses from vaults.
#[allow(clippy::large_enum_variant, clippy::type_complexity, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Response {
    //
    // ===== Immutable Data =====
    //
    GetIData(Result<IData>),
    //
    // ===== Mutable Data =====
    //
    GetMData(Result<MData>),
    GetMDataShell(Result<MData>),
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
    GetADataRange(Result<ADataEntries>),
    GetADataIndices(Result<ADataIndices>),
    GetADataLastEntry(Result<(Vec<u8>, Vec<u8>)>),
    GetUnpubADataPermissionAtIndex(Result<ADataUnpubPermissions>),
    GetPubADataPermissionAtIndex(Result<ADataPubPermissions>),
    GetPubADataUserPermissions(Result<ADataPubPermissionSet>),
    GetUnpubADataUserPermissions(Result<ADataUnpubPermissionSet>),
    //
    // ===== Coins =====
    //
    GetBalance(Result<Coins>),
    Transaction(Result<Transaction>),
    //
    // ===== Client (Owner) to SrcElders =====
    //
    /// Returns a list of authorised keys from Elders and the account version.
    ListAuthKeysAndVersion(Result<(BTreeMap<PublicKey, AppPermissions>, u64)>),
    //
    // ===== Login Packet =====
    //
    /// Returns an encrypted login packet
    GetLoginPacket(Result<(Vec<u8>, Signature)>),
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
                GetIData(ref res) => format!("Response::GetIData({:?})", ErrorDebug(res)),
                // MData
                GetMData(ref res) => format!("Response::GetMData({:?})", ErrorDebug(res)),
                GetMDataShell(ref res) => format!("Response::GetMDataShell({:?})", ErrorDebug(res)),
                GetMDataVersion(ref res) => {
                    format!("Response::GetMDataVersion({:?})", ErrorDebug(res))
                }
                ListUnseqMDataEntries(ref res) => {
                    format!("Response::ListUnseqMDataEntries({:?})", ErrorDebug(res))
                }
                ListSeqMDataEntries(ref res) => {
                    format!("Response::ListSeqMDataEntries({:?})", ErrorDebug(res))
                }
                ListMDataKeys(ref res) => format!("Response::ListMDataKeys({:?})", ErrorDebug(res)),
                ListSeqMDataValues(ref res) => {
                    format!("Response::ListSeqMDataValues({:?})", ErrorDebug(res))
                }
                ListUnseqMDataValues(ref res) => {
                    format!("Response::ListUnseqMDataValues({:?})", ErrorDebug(res))
                }
                ListMDataPermissions(ref res) => {
                    format!("Response::ListMDataPermissions({:?})", ErrorDebug(res))
                }
                ListMDataUserPermissions(ref res) => {
                    format!("Response::ListMDataUserPermissions({:?})", ErrorDebug(res))
                }
                GetSeqMDataValue(ref res) => {
                    format!("Response::GetSeqMDataValue({:?})", ErrorDebug(res))
                }
                GetUnseqMDataValue(ref res) => {
                    format!("Response::GetUnseqMDataValue({:?})", ErrorDebug(res))
                }
                Transaction(ref res) => format!("Response::Transaction({:?})", ErrorDebug(res)),
                GetBalance(ref res) => format!("Response::GetBalance({:?})", ErrorDebug(res)),
                ListAuthKeysAndVersion(ref res) => {
                    format!("Response::ListAuthKeysAndVersion({:?})", ErrorDebug(res))
                }
                GetAData(ref res) => format!("Response::GetAData({:?})", ErrorDebug(res)),
                GetADataRange(ref res) => format!("Response::GetADataRange({:?})", ErrorDebug(res)),
                GetADataIndices(ref res) => {
                    format!("Response::GetADataIndices({:?})", ErrorDebug(res))
                }
                GetADataLastEntry(ref res) => {
                    format!("Response::GetADataLastEntry({:?})", ErrorDebug(res))
                }
                GetUnpubADataPermissionAtIndex(ref res) => format!(
                    "Response::GetUnpubADataPermissionAtIndex({:?})",
                    ErrorDebug(res)
                ),
                GetPubADataPermissionAtIndex(ref res) => format!(
                    "Response::GetPubADataPermissionAtIndex({:?})",
                    ErrorDebug(res)
                ),
                GetPubADataUserPermissions(ref res) => format!(
                    "Response::GetPubADataUserPermissions({:?})",
                    ErrorDebug(res)
                ),
                GetUnpubADataUserPermissions(ref res) => format!(
                    "Response::GetUnpubADataUserPermissions({:?})",
                    ErrorDebug(res)
                ),
                GetADataShell(ref res) => format!("Response::GetADataShell({:?})", ErrorDebug(res)),
                GetADataOwners(ref res) => {
                    format!("Response::GetADataOwners({:?})", ErrorDebug(res))
                }
                GetLoginPacket(ref res) => {
                    format!("Response::GetLoginPacket({:?})", ErrorDebug(res))
                }
                Mutation(ref res) => format!("Response::Mutation({:?})", ErrorDebug(res)),
            }
        )
    }
}

#[test]
fn debug_format() {
    let response = Response::Mutation(Ok(()));
    assert_eq!(format!("{:?}", response), "Response::Mutation(Success)");
    use crate::Error;
    let errored_response = Response::GetADataShell(Err(Error::AccessDenied));
    assert_eq!(
        format!("{:?}", errored_response),
        "Response::GetADataShell(AccessDenied)"
    );
}
