// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#![allow(dead_code)] // for the draft PR only

use crate::{utils, PublicKey, Result, XorName};
use multibase::Decodable;
use serde::{Deserialize, Serialize};
use std::ops::Range;

pub type Key = Vec<u8>;
pub type Value = Vec<u8>;
pub type KvPair = (Key, Value);
pub type Values = Vec<Value>;
pub type Keys = Vec<Key>;

/// Marker for sentried data.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Sentried;

/// Marker for non-sentried data.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct NonSentried;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub enum User {
    Anyone,
    Specific(PublicKey),
}

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
    PublicSentried,
    Public,
    PrivateSentried,
    Private,
}

impl Kind {
    pub fn is_public(self) -> bool {
        self == Kind::PublicSentried || self == Kind::Public
    }

    pub fn is_private(self) -> bool {
        !self.is_public()
    }

    pub fn is_sentried(self) -> bool {
        self == Kind::PublicSentried || self == Kind::PrivateSentried
    }

    /// Creates `Kind` from `public` and `sentried` flags.
    pub fn from_flags(public: bool, sentried: bool) -> Self {
        match (public, sentried) {
            (true, true) => Kind::PublicSentried,
            (true, false) => Kind::Public,
            (false, true) => Kind::PrivateSentried,
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
    PublicSentried { name: XorName, tag: u64 },
    Public { name: XorName, tag: u64 },
    PrivateSentried { name: XorName, tag: u64 },
    Private { name: XorName, tag: u64 },
}

impl Address {
    pub fn from_kind(kind: Kind, name: XorName, tag: u64) -> Self {
        match kind {
            Kind::PublicSentried => Address::PublicSentried { name, tag },
            Kind::Public => Address::Public { name, tag },
            Kind::PrivateSentried => Address::PrivateSentried { name, tag },
            Kind::Private => Address::Private { name, tag },
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            Address::PublicSentried { .. } => Kind::PublicSentried,
            Address::Public { .. } => Kind::Public,
            Address::PrivateSentried { .. } => Kind::PrivateSentried,
            Address::Private { .. } => Kind::Private,
        }
    }

    pub fn name(&self) -> &XorName {
        match self {
            Address::PublicSentried { ref name, .. }
            | Address::Public { ref name, .. }
            | Address::PrivateSentried { ref name, .. }
            | Address::Private { ref name, .. } => name,
        }
    }

    pub fn tag(&self) -> u64 {
        match self {
            Address::PublicSentried { tag, .. }
            | Address::Public { tag, .. }
            | Address::PrivateSentried { tag, .. }
            | Address::Private { tag, .. } => *tag,
        }
    }

    pub fn is_public(&self) -> bool {
        self.kind().is_public()
    }

    pub fn is_private(&self) -> bool {
        self.kind().is_private()
    }

    pub fn is_sentried(&self) -> bool {
        self.kind().is_sentried()
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
