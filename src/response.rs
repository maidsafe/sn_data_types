// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    errors::ErrorDebug, AppPermissions, DebitAgreementProof, Error, IData, MData, MDataEntries,
    MDataPermissionSet, MDataValue, MDataValues, Money, PublicKey, ReplicaEvent,
    ReplicaPublicKeySet, Result, SData, SDataEntries, SDataEntry, SDataOwner, SDataPermissions,
    SDataUserPermissions, Signature, TransferRegistered, TransferValidated,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    fmt,
};

/// RPC responses from vaults.
#[allow(clippy::large_enum_variant, clippy::type_complexity)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
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
    // ===== Sequence Data =====
    //
    /// Get Sequence.
    GetSData(Result<SData>),
    /// Get Sequence owners.
    GetSDataOwner(Result<SDataOwner>),
    /// Get Sequence entries from a range.
    GetSDataRange(Result<SDataEntries>),
    /// Get Sequence last entry.
    GetSDataLastEntry(Result<(u64, SDataEntry)>),
    /// List all Sequence permissions at the provided index.
    GetSDataPermissions(Result<SDataPermissions>),
    /// Get Sequence permissions for a user.
    GetSDataUserPermissions(Result<SDataUserPermissions>),
    //
    // ===== Money =====
    //
    /// Get replica keys
    GetReplicaKeys(Result<ReplicaPublicKeySet>),
    /// Get key balance.
    GetBalance(Result<Money>),
    /// Get key transfer history.
    GetHistory(Result<Vec<ReplicaEvent>>),
    /// Return the result of a ValidateTransfer cmd.
    TransferValidation(Result<TransferValidated>),
    /// An aggregate response created client side
    /// (for upper Client layers) out of multiple TransferValidation responses.
    TransferDebitAgreementProof(Result<DebitAgreementProof>),
    /// Return the result of a RegisterTransfer cmd.
    TransferRegistration(Result<TransferRegistered>),
    /// Return the result of propagation of TransferRegistered event.
    TransferPropagation(Result<()>),
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
    // ===== Write =====
    //
    /// Return a success or failure status for a write operation.
    Write(Result<()>),
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
try_from!(SData, GetSData);
try_from!(SDataOwner, GetSDataOwner);
try_from!(SDataEntries, GetSDataRange);
try_from!((u64, SDataEntry), GetSDataLastEntry);
try_from!(SDataPermissions, GetSDataPermissions);
try_from!(SDataUserPermissions, GetSDataUserPermissions);
try_from!(Money, GetBalance);
try_from!(ReplicaPublicKeySet, GetReplicaKeys);
try_from!(Vec<ReplicaEvent>, GetHistory);
try_from!(TransferRegistered, TransferRegistration);
try_from!(TransferValidated, TransferValidation);
try_from!((), TransferPropagation, Write);
try_from!(
    (BTreeMap<PublicKey, AppPermissions>, u64),
    ListAuthKeysAndVersion
);
try_from!((Vec<u8>, Signature), GetLoginPacket);

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
            // SData
            GetSData(res) => write!(f, "Response::GetSData({:?})", ErrorDebug(res)),
            GetSDataRange(res) => write!(f, "Response::GetSDataRange({:?})", ErrorDebug(res)),
            GetSDataLastEntry(res) => {
                write!(f, "Response::GetSDataLastEntry({:?})", ErrorDebug(res))
            }
            GetSDataPermissions(res) => {
                write!(f, "Response::GetSDataPermissions({:?})", ErrorDebug(res))
            }
            GetSDataUserPermissions(res) => write!(
                f,
                "Response::GetSDataUserPermissions({:?})",
                ErrorDebug(res)
            ),
            GetSDataOwner(res) => write!(f, "Response::GetSDataOwner({:?})", ErrorDebug(res)),
            // Money
            GetReplicaKeys(res) => write!(f, "Response::GetReplicaKeys({:?})", ErrorDebug(res)),
            GetBalance(res) => write!(f, "Response::GetBalance({:?})", ErrorDebug(res)),
            GetHistory(res) => write!(f, "Response::GetHistory({:?})", ErrorDebug(res)),
            TransferValidation(res) => {
                write!(f, "Response::TransferValidation({:?})", ErrorDebug(res))
            }
            TransferDebitAgreementProof(res) => write!(
                f,
                "Response::TransferDebitAgreementProof({:?})",
                ErrorDebug(res)
            ),
            TransferRegistration(res) => {
                write!(f, "Response::TransferRegistration({:?})", ErrorDebug(res))
            }
            TransferPropagation(res) => {
                write!(f, "Response::TransferPropagation({:?})", ErrorDebug(res))
            }
            // Login Packet
            GetLoginPacket(res) => write!(f, "Response::GetLoginPacket({:?})", ErrorDebug(res)),
            // Client (Owner) to SrcElders
            ListAuthKeysAndVersion(res) => {
                write!(f, "Response::ListAuthKeysAndVersion({:?})", ErrorDebug(res))
            }
            // Write
            Write(res) => write!(f, "Response::Write({:?})", ErrorDebug(res)),
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
        let response = Response::Write(Ok(()));
        assert_eq!(format!("{:?}", response), "Response::Write(Success)");
        use crate::Error;
        let errored_response = Response::GetSData(Err(Error::AccessDenied));
        assert_eq!(
            format!("{:?}", errored_response),
            "Response::GetSData(AccessDenied)"
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
            unwrap_err!(IData::try_from(Write(Ok(()))))
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
            unwrap_err!(MData::try_from(Write(Ok(()))))
        );
    }
}
