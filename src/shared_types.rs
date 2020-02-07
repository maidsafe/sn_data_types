// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{utils, PublicKey, Result, XorName};
use multibase::Decodable;
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::ops::Range;

/// A Key used to relate to a value.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default, Debug)]
pub struct Key(Vec<u8>);

impl Key {
    /// Returns the underlying implementation, a byte array.
    pub fn get(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Deref for Key {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for Key {
    fn from(vec: Vec<u8>) -> Self {
        Key(vec)
    }
}

/// A value stored in a data type.
pub type Value = Vec<u8>;
/// A list of values.
pub type Values = Vec<Value>;
/// A list of keys.
pub type Keys = Vec<Key>;

/// Represents users of the network.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub enum User {
    /// The category representing any user.
    Anyone,
    /// The category representing a specific user.
    Specific(PublicKey),
}

/// The current version is defined as the last entry in the vector.
pub const CURRENT_VERSION: Version = Version::FromEnd(1);

/// Enum to represent a specific version of data.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Version {
    /// Absolute index
    FromStart(u64),
    /// Relative Version - start counting from the end
    FromEnd(u64),
}

impl From<u64> for Version {
    fn from(version: u64) -> Self {
        Version::FromStart(version)
    }
}

/// Set of data, owners, permissions versions.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExpectedVersions {
    /// Expected data version.
    pub data_version: u64,
    /// Expected owners version.
    pub owners_version: u64,
    /// Expected access list version.
    pub access_list_version: u64,
}

/// Represents an owner of a data instance,
/// at a specific data and access list version.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Owner {
    /// The public key of the user being the owner.
    pub public_key: PublicKey,
    /// The expected Version of the data at the time this ownership change is to become valid.
    pub expected_data_version: u64,
    /// The expected Version of the permissions at the time this ownership change is to become valid.
    pub expected_access_list_version: u64,
}

/// The scope of the data type.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Scope {
    /// Public means data is perpetual.
    Public,
    /// Private means data can be deleted, if desired.
    Private,
}

impl Scope {
    /// Returns true if the data type scope is public.
    pub fn is_public(self) -> bool {
        self == Scope::Public
    }

    /// Returns true if the data type is private.
    pub fn is_private(self) -> bool {
        !self.is_public()
    }

    /// Creates `Scope` from `public` flag.
    pub fn from_flag(public: bool) -> Self {
        if public {
            Scope::Public
        } else {
            Scope::Private
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum DataAddress {
    Map(Address),
    Sequence(Address),
}

/// The address of a data type.
/// Each scope has its own address space.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    /// Address in the public namespace.
    Public {
        /// Name.
        name: XorName,
        /// Type tag.
        tag: u64,
    },
    /// Address in the private namespace.
    Private {
        /// Name.
        name: XorName,
        /// Type tag.
        tag: u64,
    },
}

impl Address {
    /// Returns an Address instance for the specified data type scope.
    pub fn from_scope(scope: Scope, name: XorName, tag: u64) -> Self {
        match scope {
            Scope::Public => Address::Public { name, tag },
            Scope::Private => Address::Private { name, tag },
        }
    }

    /// Returns the scope of data type that this address space represents.
    pub fn scope(&self) -> Scope {
        match self {
            Address::Public { .. } => Scope::Public,
            Address::Private { .. } => Scope::Private,
        }
    }

    /// Returns the XorName that the data is located by
    /// within its address space.
    pub fn name(&self) -> &XorName {
        match self {
            Address::Public { ref name, .. } | Address::Private { ref name, .. } => name,
        }
    }

    /// Returns the tag that denotes a specific address space.
    pub fn tag(&self) -> u64 {
        match self {
            Address::Public { tag, .. } | Address::Private { tag, .. } => *tag,
        }
    }

    /// Returns true if the address is for a public data type.
    pub fn is_public(&self) -> bool {
        self.scope().is_public()
    }

    /// Returns true if the address is for a private data type.
    pub fn is_private(&self) -> bool {
        self.scope().is_private()
    }

    /// Returns the Address serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Creates from z-base-32 encoded string.
    pub fn decode_from_zbase32<I: Decodable>(encoded: I) -> Result<Self> {
        utils::decode(encoded)
    }
}

pub fn to_absolute_version(version: Version, count: usize) -> Option<usize> {
    match version {
        Version::FromStart(version) if (version as usize) <= count => Some(version as usize),
        Version::FromStart(_) => None,
        Version::FromEnd(version) => count.checked_sub(version as usize),
    }
}

pub fn to_absolute_range(start: Version, end: Version, count: usize) -> Option<Range<usize>> {
    let start = to_absolute_version(start, count)?;
    let end = to_absolute_version(end, count)?;

    if start <= end {
        Some(start..end)
    } else {
        None
    }
}
