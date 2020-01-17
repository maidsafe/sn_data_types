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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default, Debug)]
pub struct Key(Vec<u8>);

impl Key {
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

pub type Value = Vec<u8>;
pub type KeyValuePair = (Key, Value);
pub type Values = Vec<Value>;
pub type Keys = Vec<Key>;

/// Marker for Guarded data.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Guarded;

/// Marker for non-Guarded data.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct NonGuarded;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub enum User {
    Anyone,
    Specific(PublicKey),
}

/// The current version is defined as the last entry in the vector.
pub const CURRENT_VERSION: Version = Version::FromEnd(1); // Shouldn't last entry be accessed with 0 ?

#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Version {
    FromStart(u64), // Absolute index
    FromEnd(u64),   // Relative Version - start counting from the end
}

impl From<u64> for Version {
    fn from(version: u64) -> Self {
        Version::FromStart(version)
    }
}

// Set of data, owners, permissions versions.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExpectedVersions {
    expected_data_version: u64,
    expected_owners_version: u64,
    expected_access_list_version: u64,
}

impl ExpectedVersions {
    pub fn new(
        expected_data_version: u64,
        expected_owners_version: u64,
        expected_access_list_version: u64,
    ) -> Self {
        ExpectedVersions {
            expected_data_version,
            expected_owners_version,
            expected_access_list_version,
        }
    }

    pub fn expected_data_version(&self) -> u64 {
        self.expected_data_version
    }

    pub fn expected_owners_version(&self) -> u64 {
        self.expected_owners_version
    }

    pub fn expected_access_list_version(&self) -> u64 {
        self.expected_access_list_version
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Owner {
    pub public_key: PublicKey,
    /// The expected Version of the data at the time this ownership change is to become valid.
    pub expected_data_version: u64,
    /// The expected Version of the permissions at the time this ownership change is to become valid.
    pub expected_access_list_version: u64,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    PublicGuarded,
    Public,
    PrivateGuarded,
    Private,
}

impl Kind {
    pub fn is_public(self) -> bool {
        self == Kind::PublicGuarded || self == Kind::Public
    }

    pub fn is_private(self) -> bool {
        !self.is_public()
    }

    pub fn is_guarded(self) -> bool {
        self == Kind::PublicGuarded || self == Kind::PrivateGuarded
    }

    /// Creates `Kind` from `public` and `guarded` flags.
    pub fn from_flags(public: bool, guarded: bool) -> Self {
        match (public, guarded) {
            (true, true) => Kind::PublicGuarded,
            (true, false) => Kind::Public,
            (false, true) => Kind::PrivateGuarded,
            (false, false) => Kind::Private,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum DataAddress {
    Map(Address),
    Sequence(Address),
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    PublicGuarded { name: XorName, tag: u64 },
    Public { name: XorName, tag: u64 },
    PrivateGuarded { name: XorName, tag: u64 },
    Private { name: XorName, tag: u64 },
}

impl Address {
    pub fn from_kind(kind: Kind, name: XorName, tag: u64) -> Self {
        match kind {
            Kind::PublicGuarded => Address::PublicGuarded { name, tag },
            Kind::Public => Address::Public { name, tag },
            Kind::PrivateGuarded => Address::PrivateGuarded { name, tag },
            Kind::Private => Address::Private { name, tag },
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            Address::PublicGuarded { .. } => Kind::PublicGuarded,
            Address::Public { .. } => Kind::Public,
            Address::PrivateGuarded { .. } => Kind::PrivateGuarded,
            Address::Private { .. } => Kind::Private,
        }
    }

    pub fn name(&self) -> &XorName {
        match self {
            Address::PublicGuarded { ref name, .. }
            | Address::Public { ref name, .. }
            | Address::PrivateGuarded { ref name, .. }
            | Address::Private { ref name, .. } => name,
        }
    }

    pub fn tag(&self) -> u64 {
        match self {
            Address::PublicGuarded { tag, .. }
            | Address::Public { tag, .. }
            | Address::PrivateGuarded { tag, .. }
            | Address::Private { tag, .. } => *tag,
        }
    }

    pub fn is_public(&self) -> bool {
        self.kind().is_public()
    }

    pub fn is_private(&self) -> bool {
        self.kind().is_private()
    }

    pub fn is_guarded(&self) -> bool {
        self.kind().is_guarded()
    }

    /// Returns the Address serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Create from z-base-32 encoded string.
    pub fn decode_from_zbase32<I: Decodable>(encoded: I) -> Result<Self> {
        utils::decode(encoded)
    }
}

pub fn to_absolute_version(version: Version, count: usize) -> Option<usize> {
    match version {
        Version::FromStart(version) if version as usize <= count => Some(version as usize),
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
