// Copyright 2019 MaidSafe.net limited.
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
use std::ops::Range;

pub type Key = Vec<u8>;
pub type Value = Vec<u8>;
pub type KvPair = (Key, Value);

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
pub enum Index {
    FromStart(u64), // Absolute index
    FromEnd(u64),   // Relative index - start counting from the end
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Version {
    FromStart(u64), // Absolute index
    FromEnd(u64),   // Relative index - start counting from the end
}

impl From<u64> for Index {
    fn from(index: u64) -> Self {
        Index::FromStart(index)
    }
}

// Set of data, owners, permissions Indices.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExpectedIndices {
    expected_data_index: u64,
    expected_owners_index: u64,
    expected_auth_index: u64,
}

impl ExpectedIndices {
    pub fn new(
        expected_data_index: u64,
        expected_owners_index: u64,
        expected_auth_index: u64,
    ) -> Self {
        ExpectedIndices {
            expected_data_index,
            expected_owners_index,
            expected_auth_index,
        }
    }

    pub fn expected_data_index(&self) -> u64 {
        self.expected_data_index
    }

    pub fn expected_owners_index(&self) -> u64 {
        self.expected_owners_index
    }

    pub fn expected_auth_index(&self) -> u64 {
        self.expected_auth_index
    }
}

// pub enum OwnerKind {
//     Map(Owner),
//     Sequence(Owner),
//     Index(Owner),
//     Wallet(Owner),
// }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Owner {
    pub public_key: PublicKey,
    /// The expected index of the data at the time this ownership change is to become valid.
    pub expected_data_index: u64,
    /// The expected index of the permissions at the time this ownership change is to become valid.
    pub expected_auth_index: u64,
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
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum DataAddress {
    Map(Address),
    Sequence(Address),
    // Blob(Address),
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

pub fn to_absolute_index(index: Index, count: usize) -> Option<usize> {
    match index {
        Index::FromStart(index) if index as usize <= count => Some(index as usize),
        Index::FromStart(_) => None,
        Index::FromEnd(index) => count.checked_sub(index as usize),
    }
}

pub fn to_absolute_range(start: Index, end: Index, count: usize) -> Option<Range<usize>> {
    let start = to_absolute_index(start, count)?;
    let end = to_absolute_index(end, count)?;

    if start <= end {
        Some(start..end)
    } else {
        None
    }
}
