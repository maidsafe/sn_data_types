// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    errors::ErrorDebug,
    AppPermissions,
    BlobData,
    Coins,
    Error,
    ExpectedIndices,
    MapAuth,
    MapData, // MapEntries, MapPermissionSet, MapValue, MapValues,
    Owner,
    PrivatePermissions,
    PublicKey,
    PublicPermissions,
    Result,
    SequenceAuth,
    SequenceData,
    SequenceEntry,
    SequenceValues,
    Signature,
    Transaction,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    fmt,
};

/// RPC responses from vaults.
#[allow(clippy::large_enum_variant, clippy::type_complexity, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Response {
    //
    // ===== Blob =====
    //
    GetBlob(Result<BlobData>),
    //
    // ===== Map =====
    //
    GetMap(Result<MapData>),
    GetMapShell(Result<MapData>),
    GetMapVersion(Result<u64>),
    //ListMapEntries(Result<MapEntries>),
    ListMapKeys(Result<BTreeSet<Vec<u8>>>),
    //ListMapValues(Result<MapValues>),
    //ListMapUserPermissions(Result<MapPermissionSet>),
    //ListMapPermissions(Result<BTreeMap<PublicKey, MapPermissionSet>>),
    //GetMapValue(Result<MapValue>),
    GetMapOwner(Result<Owner>),
    GetMapAuthorization(Result<MapAuth>),
    GetPublicMapUserPermissions(Result<PublicPermissions>),
    GetPrivateMapUserPermissions(Result<PrivatePermissions>),
    //
    // ===== Sequence =====
    //
    GetSequence(Result<SequenceData>),
    GetSequenceShell(Result<SequenceData>),
    GetSequenceOwner(Result<Owner>),
    GetSequenceRange(Result<SequenceValues>),
    GetSequenceValue(Result<Vec<u8>>),
    GetExpectedIndices(Result<ExpectedIndices>),
    GetSequenceCurrentEntry(Result<SequenceEntry>),
    GetSequenceAuthorization(Result<SequenceAuth>),
    GetPublicSequenceUserPermissions(Result<PublicPermissions>),
    GetPrivateSequenceUserPermissions(Result<PrivatePermissions>),
    //
    // ===== Coins =====
    //
    GetBalance(Result<Coins>),
    Transaction(Result<Transaction>),
    //
    // ===== Login Packet =====
    //
    /// Returns an encrypted login packet
    GetLoginPacket(Result<(Vec<u8>, Signature)>),
    //
    // ===== Client (Owner) to SrcElders =====
    //
    /// Returns a list of authorised keys and the version of the auth keys container from Elders.
    ListAuthKeysAndVersion(Result<(BTreeMap<PublicKey, AppPermissions>, u64)>),
    //
    // ===== Mutation =====
    //
    /// Returns a success or failure status for a mutation operation.
    Mutation(Result<()>),
}

#[derive(Debug, PartialEq)]
pub enum TryFromError {
    WrongType,
    Response(Error),
}

macro_rules! try_from {
    ($ok_type:ty, $($variant:ident),*) => {
        impl TryFrom<Response> for $ok_type {
            type Error = TryFromError;
            fn try_from(response: Response) -> std::result::Result<Self, Self::Error> {
                match response {
                    $(
                        Response::$variant(Ok(data)) => Ok(data),
                        Response::$variant(Err(error)) => Err(TryFromError::Response(error)),
                    )*
                    _ => Err(TryFromError::WrongType),
                }
            }
        }
    };
}

try_from!(BlobData, GetBlob);
try_from!(MapData, GetMap, GetMapShell);
try_from!(u64, GetMapVersion);
//try_from!(MapEntries, ListMapEntries);
try_from!(BTreeSet<Vec<u8>>, ListMapKeys);
//try_from!(MapValues, ListMapValues);
//try_from!(MapPermissionSet, ListMapUserPermissions);
//try_from!(BTreeMap<PublicKey, MapPermissionSet>, ListMapPermissions);
//try_from!(MapValue, GetMapValue);
try_from!(Vec<u8>, GetSequenceValue);
try_from!(SequenceData, GetSequence, GetSequenceShell);
// try_from!(Owner, GetMapOwner); // hm conflicting impl
try_from!(Owner, GetSequenceOwner);
try_from!(SequenceValues, GetSequenceRange);
try_from!(ExpectedIndices, GetExpectedIndices);
try_from!(SequenceEntry, GetSequenceCurrentEntry);
try_from!(SequenceAuth, GetSequenceAuthorization);
try_from!(PublicPermissions, GetPublicSequenceUserPermissions);
try_from!(PrivatePermissions, GetPrivateSequenceUserPermissions);
try_from!(Coins, GetBalance);
try_from!(Transaction, Transaction);
try_from!(
    (BTreeMap<PublicKey, AppPermissions>, u64),
    ListAuthKeysAndVersion
);
try_from!((Vec<u8>, Signature), GetLoginPacket);
try_from!((), Mutation);

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Response::*;
        match self {
            // Blob
            GetBlob(res) => write!(f, "Response::GetBlob({:?})", ErrorDebug(res)),
            // Map
            GetMap(res) => write!(f, "Response::GetMap({:?})", ErrorDebug(res)),
            GetMapShell(res) => write!(f, "Response::GetMapShell({:?})", ErrorDebug(res)),
            GetMapVersion(res) => write!(f, "Response::GetMapVersion({:?})", ErrorDebug(res)),
            //ListMapEntries(res) => write!(f, "Response::ListMapEntries({:?})", ErrorDebug(res)),
            ListMapKeys(res) => write!(f, "Response::ListMapKeys({:?})", ErrorDebug(res)),
            //ListMapValues(res) => write!(f, "Response::ListMapValues({:?})", ErrorDebug(res)),
            // ListMapPermissions(res) => {
            //     write!(f, "Response::ListMapPermissions({:?})", ErrorDebug(res))
            // }
            // ListMapUserPermissions(res) => write!(
            //     f,
            //     "Response::ListMapUserPermissions({:?})",
            //     ErrorDebug(res)
            // ),
            // GetMapValue(res) => write!(f, "Response::GetMapValue({:?})", ErrorDebug(res)),
            GetMapAuthorization(res) => {
                write!(f, "Response::GetMapAuthorization({:?})", ErrorDebug(res))
            }
            GetPublicMapUserPermissions(res) => write!(
                f,
                "Response::GetPublicMapUserPermissions({:?})",
                ErrorDebug(res)
            ),
            GetPrivateMapUserPermissions(res) => write!(
                f,
                "Response::GetPrivateMapUserPermissions({:?})",
                ErrorDebug(res)
            ),
            // Sequence
            GetSequence(res) => write!(f, "Response::GetSequence({:?})", ErrorDebug(res)),
            GetSequenceValue(res) => write!(f, "Response::GetSequenceValue({:?})", ErrorDebug(res)),
            GetSequenceRange(res) => write!(f, "Response::GetSequenceRange({:?})", ErrorDebug(res)),
            GetExpectedIndices(res) => {
                write!(f, "Response::GetExpectedIndices({:?})", ErrorDebug(res))
            }
            GetSequenceCurrentEntry(res) => write!(
                f,
                "Response::GetSequenceCurrentEntry({:?})",
                ErrorDebug(res)
            ),
            GetSequenceAuthorization(res) => write!(
                f,
                "Response::GetSequenceAuthorization({:?})",
                ErrorDebug(res)
            ),
            GetPublicSequenceUserPermissions(res) => write!(
                f,
                "Response::GetPublicSequenceUserPermissions({:?})",
                ErrorDebug(res)
            ),
            GetPrivateSequenceUserPermissions(res) => write!(
                f,
                "Response::GetPrivateSequenceUserPermissions({:?})",
                ErrorDebug(res)
            ),
            GetSequenceShell(res) => write!(f, "Response::GetSequenceShell({:?})", ErrorDebug(res)),
            GetMapOwner(res) => write!(f, "Response::GetMapOwner({:?})", ErrorDebug(res)),
            GetSequenceOwner(res) => write!(f, "Response::GetSequenceOwner({:?})", ErrorDebug(res)),
            // Coins
            GetBalance(res) => write!(f, "Response::GetBalance({:?})", ErrorDebug(res)),
            Transaction(res) => write!(f, "Response::Transaction({:?})", ErrorDebug(res)),
            // Login Packet
            GetLoginPacket(res) => write!(f, "Response::GetLoginPacket({:?})", ErrorDebug(res)),
            // Client (Owner) to SrcElders
            ListAuthKeysAndVersion(res) => {
                write!(f, "Response::ListAuthKeysAndVersion({:?})", ErrorDebug(res))
            }
            // Mutation
            Mutation(res) => write!(f, "Response::Mutation({:?})", ErrorDebug(res)),
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::{PublicBlob, UnseqMutableData};
//     use std::convert::{TryFrom, TryInto};
//     use unwrap::{unwrap, unwrap_err};

//     #[test]
//     fn debug_format() {
//         let response = Response::Mutation(Ok(()));
//         assert_eq!(format!("{:?}", response), "Response::Mutation(Success)");
//         use crate::Error;
//         let errored_response = Response::GetSequenceShell(Err(Error::AccessDenied));
//         assert_eq!(
//             format!("{:?}", errored_response),
//             "Response::GetSequenceShell(AccessDenied)"
//         );
//     }

//     #[test]
//     fn try_from() {
//         use Response::*;

//         let i_data = Blob::Pub(PublicBlob::new(vec![1, 3, 1, 4]));
//         let e = Error::AccessDenied;
//         assert_eq!(i_data, unwrap!(GetBlob(Ok(i_data.clone())).try_into()));
//         assert_eq!(
//             TryFromError::Response(e.clone()),
//             unwrap_err!(Blob::try_from(GetBlob(Err(e.clone()))))
//         );
//         assert_eq!(
//             TryFromError::WrongType,
//             unwrap_err!(Blob::try_from(Mutation(Ok(()))))
//         );

//         let mut data = BTreeMap::new();
//         let _ = data.insert(vec![1], vec![10]);
//         let owners = PublicKey::Bls(threshold_crypto::SecretKey::random().public_key());
//         let m_data = Map::Unseq(UnseqMutableData::new_with_data(
//             *i_data.name(),
//             1,
//             data.clone(),
//             BTreeMap::new(),
//             owners,
//         ));
//         assert_eq!(m_data, unwrap!(GetMap(Ok(m_data.clone())).try_into()));
//         assert_eq!(
//             TryFromError::Response(e.clone()),
//             unwrap_err!(Map::try_from(GetMap(Err(e))))
//         );
//         assert_eq!(
//             TryFromError::WrongType,
//             unwrap_err!(Map::try_from(Mutation(Ok(()))))
//         );
//     }
// }
