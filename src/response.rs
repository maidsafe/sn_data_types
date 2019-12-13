// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    errors::ErrorDebug, AppPermissions, BlobData, Coins, Error, ExpectedVersions, Key,
    MapAccessList, MapData, MapEntries, MapKeyHistories, MapValue, MapValues, Owner,
    PrivateAccessList, PrivateUserAccess, PublicAccessList, PublicKey, PublicUserAccess, Result,
    SequenceAccessList, SequenceData, SequenceEntry, SequenceValues, Signature, Transaction,
    Value as SequenceValue,
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
    GetMapExpectedVersions(Result<ExpectedVersions>),
    GetMapValue(Result<MapValue>),   // The value of a key
    GetMapValueAt(Result<MapValue>), // The value of a key as of a version.
    GetMapValues(Result<MapValues>), // All current values of map
    GetMapEntries(Result<MapEntries>),
    GetMapKeys(Result<BTreeSet<Key>>),
    GetMapKeyHistories(Result<MapKeyHistories>),
    GetMapKeyHistory(Result<MapValues>),
    GetMapKeyHistoryRange(Result<MapValues>),
    GetMapOwner(Result<Owner>),
    GetMapOwnerAt(Result<Owner>),
    GetMapOwnerHistory(Result<Vec<Owner>>),
    GetMapOwnerHistoryRange(Result<Vec<Owner>>),
    GetPublicMapAccessListHistory(Result<Vec<PublicAccessList>>),
    GetPublicMapAccessListHistoryRange(Result<Vec<PublicAccessList>>),
    GetPrivateMapAccessListHistory(Result<Vec<PrivateAccessList>>),
    GetPrivateMapAccessListHistoryRange(Result<Vec<PrivateAccessList>>),
    GetMapAccessList(Result<MapAccessList>),
    GetMapAccessListAt(Result<MapAccessList>),
    GetPublicMapUserPermissions(Result<PublicUserAccess>),
    GetPrivateMapUserPermissions(Result<PrivateUserAccess>),
    GetPublicMapUserPermissionsAt(Result<PublicUserAccess>),
    GetPrivateMapUserPermissionsAt(Result<PrivateUserAccess>),
    //
    // ===== Sequence =====
    //
    GetSequence(Result<SequenceData>),
    GetSequenceShell(Result<SequenceData>),
    GetSequenceOwner(Result<Owner>),
    GetSequenceOwnerAt(Result<Owner>),
    GetSequenceOwnerHistory(Result<Vec<Owner>>),
    GetSequenceOwnerHistoryRange(Result<Vec<Owner>>),
    GetSequenceRange(Result<SequenceValues>),
    GetSequenceValue(Result<SequenceValue>),
    GetSequenceExpectedVersions(Result<ExpectedVersions>),
    GetSequenceCurrentEntry(Result<SequenceEntry>),
    GetSequenceAccessList(Result<SequenceAccessList>),
    GetSequenceAccessListAt(Result<SequenceAccessList>),
    GetPublicSequenceAccessListHistory(Result<Vec<PublicAccessList>>),
    GetPublicSequenceAccessListHistoryRange(Result<Vec<PublicAccessList>>),
    GetPrivateSequenceAccessListHistory(Result<Vec<PrivateAccessList>>),
    GetPrivateSequenceAccessListHistoryRange(Result<Vec<PrivateAccessList>>),
    GetPublicSequenceUserPermissions(Result<PublicUserAccess>),
    GetPrivateSequenceUserPermissions(Result<PrivateUserAccess>),
    GetPublicSequenceUserPermissionsAt(Result<PublicUserAccess>),
    GetPrivateSequenceUserPermissionsAt(Result<PrivateUserAccess>),
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

// todo: add missing try_from!:s
try_from!(BlobData, GetBlob);
try_from!(MapData, GetMap, GetMapShell);
try_from!(u64, GetMapVersion);
try_from!(MapEntries, GetMapEntries);
try_from!(BTreeSet<Key>, GetMapKeys);
try_from!(MapValues, GetMapValues);
try_from!(MapValue, GetMapValue);
try_from!(SequenceValue, GetSequenceValue);
try_from!(SequenceData, GetSequence, GetSequenceShell);
try_from!(Owner, GetMapOwner, GetSequenceOwner);
try_from!(
    ExpectedVersions,
    GetMapExpectedVersions,
    GetSequenceExpectedVersions
);
try_from!(SequenceValues, GetSequenceRange);
try_from!(SequenceEntry, GetSequenceCurrentEntry);
try_from!(MapAccessList, GetMapAccessList);
try_from!(SequenceAccessList, GetSequenceAccessList);
try_from!(
    PublicUserAccess,
    GetPublicMapUserPermissions,
    GetPublicSequenceUserPermissions
);
try_from!(
    PrivateUserAccess,
    GetPrivateMapUserPermissions,
    GetPrivateSequenceUserPermissions
);
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
            GetMapExpectedVersions(res) => {
                write!(f, "Response::GetMapExpectedVersions({:?})", ErrorDebug(res))
            }
            GetMapKeyHistory(res) => write!(f, "Response::GetMapKeyHistory({:?})", ErrorDebug(res)),
            GetMapKeyHistoryRange(res) => {
                write!(f, "Response::GetMapKeyHistoryRange({:?})", ErrorDebug(res))
            }
            GetMapKeyHistories(res) => {
                write!(f, "Response::GetMapKeyHistories({:?})", ErrorDebug(res))
            }
            GetMapEntries(res) => write!(f, "Response::GetMapEntries({:?})", ErrorDebug(res)),
            GetMapKeys(res) => write!(f, "Response::GetMapKeys({:?})", ErrorDebug(res)),
            GetMapValue(res) => write!(f, "Response::GetMapValue({:?})", ErrorDebug(res)),
            GetMapValueAt(res) => write!(f, "Response::GetMapValueAt({:?})", ErrorDebug(res)),
            GetMapValues(res) => write!(f, "Response::GetMapValues({:?})", ErrorDebug(res)),
            GetMapOwner(res) => write!(f, "Response::GetMapOwner({:?})", ErrorDebug(res)),
            GetMapOwnerAt(res) => write!(f, "Response::GetMapOwnerAt({:?})", ErrorDebug(res)),
            GetMapOwnerHistory(res) => {
                write!(f, "Response::GetMapOwnerHistory({:?})", ErrorDebug(res))
            }
            GetMapOwnerHistoryRange(res) => write!(
                f,
                "Response::GetMapOwnerHistoryRange({:?})",
                ErrorDebug(res)
            ),
            GetMapAccessList(res) => write!(f, "Response::GetMapAccessList({:?})", ErrorDebug(res)),
            GetMapAccessListAt(res) => {
                write!(f, "Response::GetMapAccessListAt({:?})", ErrorDebug(res))
            }
            GetPublicMapAccessListHistory(res) => write!(
                f,
                "Response::GetPublicMapAccessListHistory({:?})",
                ErrorDebug(res)
            ),
            GetPublicMapAccessListHistoryRange(res) => write!(
                f,
                "Response::GetPublicMapAccessListHistoryRange({:?})",
                ErrorDebug(res)
            ),
            GetPrivateMapAccessListHistory(res) => write!(
                f,
                "Response::GetPrivateMapAccessListHistory({:?})",
                ErrorDebug(res)
            ),
            GetPrivateMapAccessListHistoryRange(res) => write!(
                f,
                "Response::GetPrivateMapAccessListHistoryRange({:?})",
                ErrorDebug(res)
            ),
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
            GetPublicMapUserPermissionsAt(res) => write!(
                f,
                "Response::GetPublicMapUserPermissionsAt({:?})",
                ErrorDebug(res)
            ),
            GetPrivateMapUserPermissionsAt(res) => write!(
                f,
                "Response::GetPrivateMapUserPermissionsAt({:?})",
                ErrorDebug(res)
            ),
            // Sequence
            GetSequence(res) => write!(f, "Response::GetSequence({:?})", ErrorDebug(res)),
            GetSequenceShell(res) => write!(f, "Response::GetSequenceShell({:?})", ErrorDebug(res)),
            GetSequenceValue(res) => write!(f, "Response::GetSequenceValue({:?})", ErrorDebug(res)),
            GetSequenceRange(res) => write!(f, "Response::GetSequenceRange({:?})", ErrorDebug(res)),
            GetSequenceExpectedVersions(res) => {
                write!(f, "Response::GetExpectedVersions({:?})", ErrorDebug(res))
            }
            GetSequenceCurrentEntry(res) => write!(
                f,
                "Response::GetSequenceCurrentEntry({:?})",
                ErrorDebug(res)
            ),
            GetSequenceOwner(res) => write!(f, "Response::GetSequenceOwner({:?})", ErrorDebug(res)),
            GetSequenceOwnerAt(res) => {
                write!(f, "Response::GetSequenceOwnerAt({:?})", ErrorDebug(res))
            }
            GetSequenceOwnerHistory(res) => write!(
                f,
                "Response::GetSequenceOwnerHistory({:?})",
                ErrorDebug(res)
            ),
            GetSequenceOwnerHistoryRange(res) => write!(
                f,
                "Response::GetSequenceOwnerHistoryRange({:?})",
                ErrorDebug(res)
            ),
            GetSequenceAccessList(res) => {
                write!(f, "Response::GetSequenceAccessList({:?})", ErrorDebug(res))
            }
            GetSequenceAccessListAt(res) => write!(
                f,
                "Response::GetSequenceAccessListAt({:?})",
                ErrorDebug(res)
            ),
            GetPublicSequenceAccessListHistory(res) => write!(
                f,
                "Response::GetPublicSequenceAccessListHistory({:?})",
                ErrorDebug(res)
            ),
            GetPublicSequenceAccessListHistoryRange(res) => write!(
                f,
                "Response::GetPublicSequenceAccessListHistoryRange({:?})",
                ErrorDebug(res)
            ),
            GetPrivateSequenceAccessListHistory(res) => write!(
                f,
                "Response::GetPrivateSequenceAccessListHistory({:?})",
                ErrorDebug(res)
            ),
            GetPrivateSequenceAccessListHistoryRange(res) => write!(
                f,
                "Response::GetPrivateSequenceAccessListHistoryRange({:?})",
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
            GetPublicSequenceUserPermissionsAt(res) => write!(
                f,
                "Response::GetPublicSequenceUserPermissionsAt({:?})",
                ErrorDebug(res)
            ),
            GetPrivateSequenceUserPermissionsAt(res) => write!(
                f,
                "Response::GetPrivateSequenceUserPermissionsAt({:?})",
                ErrorDebug(res)
            ),
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
