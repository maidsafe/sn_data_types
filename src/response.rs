// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    errors::ErrorDebug, AData, ADataEntries, ADataEntry, ADataIndices, ADataOwner,
    ADataPermissions, ADataPubPermissionSet, ADataUnpubPermissionSet, AppPermissions, Coins, Error,
    IData, MData, MDataEntries, MDataPermissionSet, MDataValue, MDataValues, PublicKey, Result,
    Signature, Transaction,
};
use routing::OrderedConnectionInfo;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    fmt,
};

/// RPC responses from vaults.
#[allow(clippy::large_enum_variant, clippy::type_complexity)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Response {
    //
    // ===== Immutable Data =====
    //
    /// Get ImmutableData.
    GetIData(Result<IData>),
    //
    // ===== Mutable Data =====
    //
    /// Get MutableData.
    GetMData(Result<MData>),
    /// Get MutableData shell.
    GetMDataShell(Result<MData>),
    /// Get MutableData version.
    GetMDataVersion(Result<u64>),
    /// List all MutableData entries (key-value pairs).
    ListMDataEntries(Result<MDataEntries>),
    /// List all MutableData keys.
    ListMDataKeys(Result<BTreeSet<Vec<u8>>>),
    /// List all MutableData values.
    ListMDataValues(Result<MDataValues>),
    /// Get MutableData permissions for a user.
    ListMDataUserPermissions(Result<MDataPermissionSet>),
    /// List all MutableData permissions.
    ListMDataPermissions(Result<BTreeMap<PublicKey, MDataPermissionSet>>),
    /// Get MutableData value.
    GetMDataValue(Result<MDataValue>),
    //
    // ===== Append Only Data =====
    //
    /// Get AppendOnlyData.
    GetAData(Result<AData>),
    /// Get AppendOnlyData shell.
    GetADataShell(Result<AData>),
    /// Get AppendOnlyData owners.
    GetADataOwners(Result<ADataOwner>),
    /// Get AppendOnlyData.
    GetADataRange(Result<ADataEntries>),
    /// Get AppendOnlyData value.
    GetADataValue(Result<Vec<u8>>),
    /// Get AppendOnlyData indices.
    GetADataIndices(Result<ADataIndices>),
    /// Get AppendOnlyData last entry.
    GetADataLastEntry(Result<ADataEntry>),
    /// List all AppendOnlyData permissions at the provided index.
    GetADataPermissions(Result<ADataPermissions>),
    /// Get published AppendOnlyData permissions for a user.
    GetPubADataUserPermissions(Result<ADataPubPermissionSet>),
    /// Get unpublished AppendOnlyData permissions for a user..
    GetUnpubADataUserPermissions(Result<ADataUnpubPermissionSet>),
    //
    // ===== Coins =====
    //
    /// Get coin balance.
    GetBalance(Result<Coins>),
    /// Return the result of a transaction.
    Transaction(Result<Transaction>),
    //
    // ===== Login Packet =====
    //
    /// Get an encrypted login packet.
    GetLoginPacket(Result<(Vec<u8>, Signature)>),
    //
    // ===== Client (Owner) to SrcElders =====
    //
    /// Get a list of authorised keys and the version of the auth keys container from Elders.
    ListAuthKeysAndVersion(Result<(BTreeMap<PublicKey, AppPermissions>, u64)>),
    //
    // ===== Mutation =====
    //
    /// Return a success or failure status for a mutation operation.
    Mutation(Result<()>),
    //
    // ===== Netwrok =====
    //
    /// Returns a list of vaults' connection infos.
    ConnectionInfoResponse(Result<Vec<OrderedConnectionInfo>>),
}

/// Error type for an attempted conversion from `Response` to a type implementing
/// `TryFrom<Response>`.
#[derive(Debug, PartialEq)]
pub enum TryFromError {
    /// Wrong variant found in `Response`.
    WrongType,
    /// The `Response` contained an error.
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

try_from!(IData, GetIData);
try_from!(MData, GetMData, GetMDataShell);
try_from!(u64, GetMDataVersion);
try_from!(MDataEntries, ListMDataEntries);
try_from!(BTreeSet<Vec<u8>>, ListMDataKeys);
try_from!(MDataValues, ListMDataValues);
try_from!(MDataPermissionSet, ListMDataUserPermissions);
try_from!(BTreeMap<PublicKey, MDataPermissionSet>, ListMDataPermissions);
try_from!(MDataValue, GetMDataValue);
try_from!(Vec<u8>, GetADataValue);
try_from!(AData, GetAData, GetADataShell);
try_from!(ADataOwner, GetADataOwners);
try_from!(ADataEntries, GetADataRange);
try_from!(ADataIndices, GetADataIndices);
try_from!(ADataEntry, GetADataLastEntry);
try_from!(ADataPermissions, GetADataPermissions);
try_from!(ADataPubPermissionSet, GetPubADataUserPermissions);
try_from!(ADataUnpubPermissionSet, GetUnpubADataUserPermissions);
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
            // IData
            GetIData(res) => write!(f, "Response::GetIData({:?})", ErrorDebug(res)),
            // MData
            GetMData(res) => write!(f, "Response::GetMData({:?})", ErrorDebug(res)),
            GetMDataShell(res) => write!(f, "Response::GetMDataShell({:?})", ErrorDebug(res)),
            GetMDataVersion(res) => write!(f, "Response::GetMDataVersion({:?})", ErrorDebug(res)),
            ListMDataEntries(res) => write!(f, "Response::ListMDataEntries({:?})", ErrorDebug(res)),
            ListMDataKeys(res) => write!(f, "Response::ListMDataKeys({:?})", ErrorDebug(res)),
            ListMDataValues(res) => write!(f, "Response::ListMDataValues({:?})", ErrorDebug(res)),
            ListMDataPermissions(res) => {
                write!(f, "Response::ListMDataPermissions({:?})", ErrorDebug(res))
            }
            ListMDataUserPermissions(res) => write!(
                f,
                "Response::ListMDataUserPermissions({:?})",
                ErrorDebug(res)
            ),
            GetMDataValue(res) => write!(f, "Response::GetMDataValue({:?})", ErrorDebug(res)),
            // AData
            GetAData(res) => write!(f, "Response::GetAData({:?})", ErrorDebug(res)),
            GetADataValue(res) => write!(f, "Response::GetADataValue({:?})", ErrorDebug(res)),
            GetADataRange(res) => write!(f, "Response::GetADataRange({:?})", ErrorDebug(res)),
            GetADataIndices(res) => write!(f, "Response::GetADataIndices({:?})", ErrorDebug(res)),
            GetADataLastEntry(res) => {
                write!(f, "Response::GetADataLastEntry({:?})", ErrorDebug(res))
            }
            GetADataPermissions(res) => {
                write!(f, "Response::GetADataPermissions({:?})", ErrorDebug(res))
            }
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
            // Network
            ConnectionInfoResponse(res) => {
                write!(f, "Response::ConnectionInfoResponse({:?})", ErrorDebug(res))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PubImmutableData, UnseqMutableData};
    use std::convert::{TryFrom, TryInto};
    use unwrap::{unwrap, unwrap_err};

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

    #[test]
    fn try_from() {
        use Response::*;

        let i_data = IData::Pub(PubImmutableData::new(vec![1, 3, 1, 4]));
        let e = Error::AccessDenied;
        assert_eq!(i_data, unwrap!(GetIData(Ok(i_data.clone())).try_into()));
        assert_eq!(
            TryFromError::Response(e.clone()),
            unwrap_err!(IData::try_from(GetIData(Err(e.clone()))))
        );
        assert_eq!(
            TryFromError::WrongType,
            unwrap_err!(IData::try_from(Mutation(Ok(()))))
        );

        let mut data = BTreeMap::new();
        let _ = data.insert(vec![1], vec![10]);
        let owners = PublicKey::Bls(threshold_crypto::SecretKey::random().public_key());
        let m_data = MData::Unseq(UnseqMutableData::new_with_data(
            *i_data.name(),
            1,
            data,
            BTreeMap::new(),
            owners,
        ));
        assert_eq!(m_data, unwrap!(GetMData(Ok(m_data.clone())).try_into()));
        assert_eq!(
            TryFromError::Response(e.clone()),
            unwrap_err!(MData::try_from(GetMData(Err(e))))
        );
        assert_eq!(
            TryFromError::WrongType,
            unwrap_err!(MData::try_from(Mutation(Ok(()))))
        );
    }
}
