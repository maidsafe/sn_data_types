// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error;
use std::fmt::{self, Display, Formatter};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Error {
    /// Access is denied for a given requester
    AccessDenied,
    /// /// SAFE Account does not exist for client
    NoSuchAccount,
    /// Attempt to take an account network name that already exists
    AccountExists,
    /// Requested data not found
    NoSuchData,
    /// Attempt to create a mutable data when data with such a name already exists
    DataExists,
    /// Requested entry not found
    NoSuchEntry,
    /// Exceeded a limit on a number of entries
    TooManyEntries,
    /// Some entry actions are not valid.
    InvalidEntryActions(BTreeMap<Vec<u8>, EntryError>),
    /// Key does not exist
    NoSuchKey,
    /// The list of owner keys is invalid
    InvalidOwners,
    /// Invalid version for performing a given mutating operation. Contains the
    /// current data version.
    InvalidSuccessor(u64),
    /// Invalid version for performing a given mutating operation. Contains the
    /// current owners version.
    InvalidOwnersSuccessor(u64),
    /// Invalid version for performing a given mutating operation. Contains the
    /// current permissions version.
    InvalidPermissionsSuccessor(u64),
    /// Invalid Operation such as a POST on ImmutableData
    InvalidOperation,
    /// Mismatch between key type and signature type.
    SigningKeyTypeMismatch,
    /// Failed signature validation.
    InvalidSignature,
    /// Network error occurring at Vault level which has no bearing on clients, e.g. serialisation
    /// failure or database failure
    NetworkOther(String),
}

impl<T: Into<String>> From<T> for Error {
    fn from(err: T) -> Self {
        Error::NetworkOther(err.into())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Error::AccessDenied => write!(f, "Access denied"),
            Error::NoSuchAccount => write!(f, "Account does not exist for client"),
            Error::AccountExists => write!(f, "Account already exists for client"),
            Error::NoSuchData => write!(f, "Requested data not found"),
            Error::DataExists => write!(f, "Data given already exists"),
            Error::NoSuchEntry => write!(f, "Requested entry not found"),
            Error::TooManyEntries => write!(f, "Exceeded a limit on a number of entries"),
            Error::InvalidEntryActions(ref errors) => {
                write!(f, "Entry actions are invalid: {:?}", errors)
            }
            Error::NoSuchKey => write!(f, "Key does not exists"),
            Error::InvalidOwners => write!(f, "The list of owner keys is invalid"),
            Error::InvalidOperation => write!(f, "Requested operation is not allowed"),
            Error::InvalidSuccessor(_) => {
                write!(f, "Data given is not a valid successor of stored data")
            }
            Error::InvalidOwnersSuccessor(_) => {
                // TODO
                write!(f, "Data given is not a valid successor of stored data")
            }
            Error::InvalidPermissionsSuccessor(_) => {
                // TODO
                write!(f, "Data given is not a valid successor of stored data")
            }
            Error::SigningKeyTypeMismatch => {
                write!(f, "Mismatch between key type and signature type")
            }
            Error::InvalidSignature => write!(f, "Failed signature validation"),
            Error::NetworkOther(ref error) => write!(f, "Error on Vault network: {}", error),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::AccessDenied => "Access denied",
            Error::NoSuchAccount => "No such account",
            Error::AccountExists => "Account exists",
            Error::NoSuchData => "No such data",
            Error::DataExists => "Data exists",
            Error::NoSuchEntry => "No such entry",
            Error::TooManyEntries => "Too many entries",
            Error::InvalidEntryActions(_) => "Invalid entry actions",
            Error::NoSuchKey => "No such key",
            Error::InvalidOwners => "Invalid owners",
            Error::InvalidSuccessor(_) => "Invalid data successor",
            Error::InvalidOwnersSuccessor(_) => "Invalid owners successor",
            Error::InvalidPermissionsSuccessor(_) => "Invalid permissions successor",
            Error::InvalidOperation => "Invalid operation",
            Error::SigningKeyTypeMismatch => "Key type and signature type mismatch",
            Error::InvalidSignature => "Invalid signature",
            Error::NetworkOther(ref error) => error,
        }
    }
}

/// Entry error for `Error::InvalidEntryActions`.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum EntryError {
    /// Entry does not exists.
    NoSuchEntry,
    /// Entry already exists. Contains the current entry Key.
    EntryExists(u8),
    /// Invalid version when updating an entry. Contains the current entry Key.
    InvalidSuccessor(u8),
}
