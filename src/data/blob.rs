// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{utils, Error, PublicKey, XorName};
use bincode::serialized_size;
use multibase::Decodable;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{self, Debug, Formatter},
    u64,
};
use tiny_keccak;

/// Maximum allowed size for a serialised blob (ID) to grow to.
pub const MAX_BLOB_SIZE_IN_BYTES: u64 = 1024 * 1024 + 10 * 1024;

/// PrivateBlob: an immutable chunk of data which can be deleted. Can only be fetched
/// by the listed owner.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone)]
pub struct PrivateBlob {
    /// Network address. Omitted when serialising and calculated from the `value` when
    /// deserialising.
    address: Address,
    /// Contained data.
    value: Vec<u8>,
    /// Contains a owner of this data. DataHandlers enforce that a DELETE or OWNED-GET type
    /// of request is coming from the ClientHandler of the owners.
    owner: PublicKey,
}

impl PrivateBlob {
    /// Creates a new instance of `PrivateBlob`
    pub fn new(value: Vec<u8>, owner: PublicKey) -> Self {
        let hash_of_value = tiny_keccak::sha3_256(&value);
        let serialised_contents = utils::serialise(&(hash_of_value, &owner));
        let address = Address::Private(XorName(tiny_keccak::sha3_256(&serialised_contents)));

        Self {
            address,
            value,
            owner,
        }
    }

    /// Returns the value.
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    /// Returns the owner.
    pub fn is_owner(&self, user: PublicKey) -> bool {
        self.owner == user
    }

    /// Returns the owner.
    pub fn owner(&self) -> &PublicKey {
        &self.owner
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        self.address.name()
    }

    /// Returns size of contained value.
    pub fn payload_size(&self) -> usize {
        self.value.len()
    }

    /// Returns size of this Blob after serialisation.
    pub fn serialised_size(&self) -> u64 {
        serialized_size(self).unwrap_or(u64::MAX)
    }

    /// Returns true if the size is valid
    pub fn has_valid_size(&self) -> bool {
        self.serialised_size() <= MAX_BLOB_SIZE_IN_BYTES
    }
}

impl Serialize for PrivateBlob {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        (&self.value, &self.owner).serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PrivateBlob {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (value, owner): (Vec<u8>, PublicKey) = Deserialize::deserialize(deserializer)?;
        Ok(PrivateBlob::new(value, owner))
    }
}

impl Debug for PrivateBlob {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        // TODO: Output owners?
        write!(formatter, "PrivateBlob {:?}", self.name())
    }
}

/// An immutable chunk of data which cannot be deleted.
#[derive(Hash, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PublicBlob {
    /// Network address. Omitted when serialising and calculated from the `value` when
    /// deserialising.
    address: Address,
    /// Contained data.
    value: Vec<u8>,
}

impl PublicBlob {
    /// Creates a new instance of `PublicBlob`
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            address: Address::Public(XorName(tiny_keccak::sha3_256(&value))),
            value,
        }
    }

    /// Returns the value.
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        self.address.name()
    }

    /// Returns size of contained value.
    pub fn payload_size(&self) -> usize {
        self.value.len()
    }

    /// Returns size of this Blob after serialisation.
    pub fn serialised_size(&self) -> u64 {
        serialized_size(self).unwrap_or(u64::MAX)
    }

    /// Returns true if the size is valid
    pub fn has_valid_size(&self) -> bool {
        self.serialised_size() <= MAX_BLOB_SIZE_IN_BYTES
    }
}

impl Serialize for PublicBlob {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PublicBlob {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Ok(PublicBlob::new(value))
    }
}

impl Debug for PublicBlob {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicBlob {:?}", self.name())
    }
}

/// The Kind indicates whether a Blob is Public or Private.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    /// Denotes a blob as private.
    Private,
    /// Denotes a blob as public.
    Public,
}

impl Kind {
    /// Returns true if public.
    pub fn is_public(self) -> bool {
        self == Kind::Public
    }

    /// Returns true if private.
    pub fn is_private(self) -> bool {
        !self.is_public()
    }

    /// Creates `Kind` from a `public` flag.
    pub fn from_flag(public: bool) -> Self {
        if public {
            Kind::Public
        } else {
            Kind::Private
        }
    }
}

/// A Blob address, where public and private are two different address spaces.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    /// Describes an address in the private namespace.
    Private(XorName),
    /// Describes an address in the public namespace.
    Public(XorName),
}

impl Address {
    /// Constructs an `Address` given `kind` and `name`.
    pub fn from_kind(kind: Kind, name: XorName) -> Self {
        match kind {
            Kind::Public => Address::Public(name),
            Kind::Private => Address::Private(name),
        }
    }

    /// Returns the kind.
    pub fn kind(&self) -> Kind {
        match self {
            Address::Private(_) => Kind::Private,
            Address::Public(_) => Kind::Public,
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        match self {
            Address::Private(ref name) | Address::Public(ref name) => name,
        }
    }

    /// Returns true if public.
    pub fn is_public(&self) -> bool {
        self.kind().is_public()
    }

    /// Returns true if private.
    pub fn is_private(&self) -> bool {
        self.kind().is_private()
    }

    /// Returns the Address serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Creates from z-base-32 encoded string.
    pub fn decode_from_zbase32<T: Decodable>(encoded: T) -> Result<Self, Error> {
        utils::decode(encoded)
    }
}

/// Object storing a Blob variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Blob {
    /// Private blob.
    Private(PrivateBlob),
    /// Public blob.
    Public(PublicBlob),
}

impl Blob {
    /// Returns the address.
    pub fn address(&self) -> &Address {
        match self {
            Blob::Private(data) => data.address(),
            Blob::Public(data) => data.address(),
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        self.address().name()
    }

    /// Returns the kind.
    pub fn kind(&self) -> Kind {
        self.address().kind()
    }

    /// Returns true if public.
    pub fn is_public(&self) -> bool {
        self.kind().is_public()
    }

    /// Returns true if private.
    pub fn is_private(&self) -> bool {
        self.kind().is_private()
    }

    /// Returns the value.
    pub fn value(&self) -> &Vec<u8> {
        match self {
            Blob::Private(data) => data.value(),
            Blob::Public(data) => data.value(),
        }
    }

    /// Returns `true` if the size is valid.
    pub fn has_valid_size(&self) -> bool {
        match self {
            Blob::Private(data) => data.has_valid_size(),
            Blob::Public(data) => data.has_valid_size(),
        }
    }

    /// Returns size of this data after serialisation.
    pub fn serialised_size(&self) -> u64 {
        match self {
            Blob::Private(data) => data.serialised_size(),
            Blob::Public(data) => data.serialised_size(),
        }
    }
}

impl From<PrivateBlob> for Blob {
    fn from(data: PrivateBlob) -> Self {
        Blob::Private(data)
    }
}

impl From<PublicBlob> for Blob {
    fn from(data: PublicBlob) -> Self {
        Blob::Public(data)
    }
}
