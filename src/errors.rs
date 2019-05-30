// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum DataError {
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
    /// Invalid Operation such as a POST on ImmutableData
    InvalidOperation,
    /// Network error occurring at Vault level which has no bearing on clients, e.g. serialisation
    /// failure or database failure
    NetworkOther(String),
}

impl<T: Into<String>> From<T> for DataError {
    fn from(err: T) -> Self {
        DataError::NetworkOther(err.into())
    }
}

impl Display for DataError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            DataError::AccessDenied => write!(f, "Access denied"),
            DataError::NoSuchAccount => write!(f, "Account does not exist for client"),
            DataError::AccountExists => write!(f, "Account already exists for client"),
            DataError::NoSuchData => write!(f, "Requested data not found"),
            DataError::DataExists => write!(f, "Data given already exists"),
            DataError::NoSuchEntry => write!(f, "Requested entry not found"),
            DataError::TooManyEntries => write!(f, "Exceeded a limit on a number of entries"),
            DataError::InvalidEntryActions(ref errors) => {
                write!(f, "Entry actions are invalid: {:?}", errors)
            }
            DataError::NoSuchKey => write!(f, "Key does not exists"),
            DataError::InvalidOwners => write!(f, "The list of owner keys is invalid"),
            DataError::InvalidOperation => write!(f, "Requested operation is not allowed"),
            DataError::InvalidSuccessor(_) => {
                write!(f, "Data given is not a valid successor of stored data")
            }
            DataError::NetworkOther(ref error) => write!(f, "Error on Vault network: {}", error),
        }
    }
}

impl Error for DataError {
    fn description(&self) -> &str {
        match *self {
            DataError::AccessDenied => "Access denied",
            DataError::NoSuchAccount => "No such account",
            DataError::AccountExists => "Account exists",
            DataError::NoSuchData => "No such data",
            DataError::DataExists => "Data exists",
            DataError::NoSuchEntry => "No such entry",
            DataError::TooManyEntries => "Too many entries",
            DataError::InvalidEntryActions(_) => "Invalid entry actions",
            DataError::NoSuchKey => "No such key",
            DataError::InvalidOwners => "Invalid owners",
            DataError::InvalidSuccessor(_) => "Invalid data successor",
            DataError::InvalidOperation => "Invalid operation",
            DataError::NetworkOther(ref error) => error,
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
