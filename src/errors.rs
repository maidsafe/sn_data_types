// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::PublicKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
    result,
};

use thiserror::Error;

/// A specialised `Result` type for safecoin.
pub type Result<T> = result::Result<T, Error>;

/// Error debug struct
pub struct ErrorDebug<'a, T>(pub &'a Result<T>);

impl<'a, T> Debug for ErrorDebug<'a, T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if let Err(error) = self.0 {
            write!(f, "{:?}", error)
        } else {
            write!(f, "Success")
        }
    }
}

/// Main error type for the crate.
#[derive(Error, Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// Access denied for supplied PublicKey
    #[error("Access denied for PublicKey: {0}")]
    AccessDenied(PublicKey),
    /// Serialization error
    #[error("Serialisation error: {0}")]
    Serialisation(String),

    /// Entry already exists. Contains the current entry Key.
    #[error("Entry already exists {0}")]
    EntryExists(u8),

    /// Supplied actions are not valid
    #[error("Some entry actions are not valid")]
    InvalidEntryActions(BTreeMap<Vec<u8>, Error>),

    /// Entry could not be found on the data
    #[error("Requested entry not found")]
    NoSuchEntry,

    /// Key does not exist
    #[error("Key does not exist")]
    NoSuchKey,

    /// The list of owner keys is invalid
    #[error("Invalid owner keys")]
    InvalidOwners,

    /// Owner is not valid
    #[error("Owner is not a PublicKeySet")]
    InvalidOwnerNotPublicKeySet,

    /// No Policy has been set to the data
    #[error("No policy has been set for this data")]
    PolicyNotSet,
    /// Invalid version for performing a given mutating operation. Contains the
    /// current data version.
    #[error("Invalid version provided: {0}")]
    InvalidSuccessor(u64),

    /// Invalid mutating operation as it causality dependency is currently not satisfied
    #[error("Operation is not causally ready. Ensure you have the full history of operations.")]
    OpNotCausallyReady,

    /// Invalid Operation such as a POST on ImmutableData
    #[error("Invalid operation")]
    InvalidOperation,
    /// Mismatch between key type and signature type.
    #[error("Sign key and signature type do not match")]
    SigningKeyTypeMismatch,
    /// Failed signature validation.
    #[error("Invalid signature")]
    InvalidSignature,
    /// While parsing, precision would be lost.
    #[error("Lost precision on the number of coins during parsing")]
    LossOfPrecision,
    /// The amount would exceed the maximum value for `Token` (u64::MAX).
    #[error("The token amount would exceed the maximum value (u64::MAX)")]
    ExcessiveValue,
    /// Failed to parse a string.
    #[error("Failed to parse: {0}")]
    FailedToParse(String),
    /// Inexistent recipient balance.
    // TODO: this should not be possible
    #[error("No such recipient key balance")]
    NoSuchRecipient,

    /// Expected data size exceeded.
    #[error("Size of the structure exceeds the limit")]
    ExceededSize,
    /// The operation has not been signed by an actor PK and so cannot be validated.
    #[error("CRDT operation missing actor signature")]
    CrdtMissingOpSignature,
    /// The data for a given policy could not be located, so CRDT operations cannot be applied.
    #[error("CRDT data is in an unexpected and/or inconsistent state. No data found for current policy.")]
    CrdtUnexpectedState,
}

pub(crate) fn convert_bincode_error(err: bincode::Error) -> Error {
    Error::Serialisation(err.as_ref().to_string())
}
