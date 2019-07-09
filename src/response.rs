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
        match self {
            // IData
            GetIData(res) => write!(f, "Response::GetIData({:?})", ErrorDebug(res)),
            // MData
            GetMData(res) => write!(f, "Response::GetMData({:?})", ErrorDebug(res)),
            GetMDataShell(res) => write!(f, "Response::GetMDataShell({:?})", ErrorDebug(res)),
            GetMDataVersion(res) => write!(f, "Response::GetMDataVersion({:?})", ErrorDebug(res)),
            ListUnseqMDataEntries(res) => {
                write!(f, "Response::ListUnseqMDataEntries({:?})", ErrorDebug(res))
            }
            ListSeqMDataEntries(res) => {
                write!(f, "Response::ListSeqMDataEntries({:?})", ErrorDebug(res))
            }
            ListMDataKeys(res) => write!(f, "Response::ListMDataKeys({:?})", ErrorDebug(res)),
            ListSeqMDataValues(res) => {
                write!(f, "Response::ListSeqMDataValues({:?})", ErrorDebug(res))
            }
            ListUnseqMDataValues(res) => {
                write!(f, "Response::ListUnseqMDataValues({:?})", ErrorDebug(res))
            }
            ListMDataPermissions(res) => {
                write!(f, "Response::ListMDataPermissions({:?})", ErrorDebug(res))
            }
            ListMDataUserPermissions(res) => write!(
                f,
                "Response::ListMDataUserPermissions({:?})",
                ErrorDebug(res)
            ),
            GetSeqMDataValue(res) => write!(f, "Response::GetSeqMDataValue({:?})", ErrorDebug(res)),
            GetUnseqMDataValue(res) => {
                write!(f, "Response::GetUnseqMDataValue({:?})", ErrorDebug(res))
            }
            Transaction(res) => write!(f, "Response::Transaction({:?})", ErrorDebug(res)),
            GetBalance(res) => write!(f, "Response::GetBalance({:?})", ErrorDebug(res)),
            ListAuthKeysAndVersion(res) => {
                write!(f, "Response::ListAuthKeysAndVersion({:?})", ErrorDebug(res))
            }
            GetAData(res) => write!(f, "Response::GetAData({:?})", ErrorDebug(res)),
            GetADataRange(res) => write!(f, "Response::GetADataRange({:?})", ErrorDebug(res)),
            GetADataIndices(res) => write!(f, "Response::GetADataIndices({:?})", ErrorDebug(res)),
            GetADataLastEntry(res) => {
                write!(f, "Response::GetADataLastEntry({:?})", ErrorDebug(res))
            }
            GetUnpubADataPermissionAtIndex(res) => write!(
                f,
                "Response::GetUnpubADataPermissionAtIndex({:?})",
                ErrorDebug(res)
            ),
            GetPubADataPermissionAtIndex(res) => write!(
                f,
                "Response::GetPubADataPermissionAtIndex({:?})",
                ErrorDebug(res)
            ),
            GetPubADataUserPermissions(res) => write!(
                f,
                "Response::GetPubADataUserPermissions({:?})",
                ErrorDebug(res)
            ),
            GetUnpubADataUserPermissions(res) => write!(
                f,
                "Response::GetUnpubADataUserPermissions({:?})",
                ErrorDebug(res)
            ),
            GetADataShell(res) => write!(f, "Response::GetADataShell({:?})", ErrorDebug(res)),
            GetADataOwners(res) => write!(f, "Response::GetADataOwners({:?})", ErrorDebug(res)),
            GetLoginPacket(res) => write!(f, "Response::GetLoginPacket({:?})", ErrorDebug(res)),
            Mutation(res) => write!(f, "Response::Mutation({:?})", ErrorDebug(res)),
        }
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
