// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{utils, Error, PublicKey, XorName};
use bincode::serialized_size;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{self, Debug, Formatter},
    u64,
};

/// Maximum allowed size for a serialised Blob to grow to.
pub const MAX_BLOB_SIZE_IN_BYTES: u64 = 1024 * 1024 + 10 * 1024;

/// Private Blob: an immutable chunk of data which can be deleted. Can only be fetched
/// by the listed owner.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone)]
pub struct PrivateData {
    /// Network address. Omitted when serialising and calculated from the `value` and `owner` when
    /// deserialising.
    address: Address,
    /// Contained data.
    value: Vec<u8>,
    /// Contains a set of owners of this data. DataManagers enforce that a DELETE or OWNED-GET type
    /// of request is coming from the MaidManager Authority of the owners.
    owner: PublicKey,
}

impl PrivateData {
    /// Creates a new instance of `PrivateData`.
    pub fn new(value: Vec<u8>, owner: PublicKey) -> crate::Result<Self> {
        let hash_of_value = tiny_keccak::sha3_256(&value);
        let serialised_contents = utils::serialise(&(hash_of_value, &owner))?;
        let address = Address::Private(XorName(tiny_keccak::sha3_256(&serialised_contents)));

        Ok(Self {
            address,
            value,
            owner,
        })
    }

    /// Returns the value.
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    /// Returns the set of owners.
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

    /// Returns size of this data after serialisation.
    pub fn serialised_size(&self) -> u64 {
        serialized_size(self).unwrap_or(u64::MAX)
    }

    /// Returns `true` if the size is valid.
    pub fn validate_size(&self) -> bool {
        self.serialised_size() <= MAX_BLOB_SIZE_IN_BYTES
    }
}

impl Serialize for PrivateData {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        (&self.address, &self.value, &self.owner).serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PrivateData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (address, value, owner): (Address, Vec<u8>, PublicKey) =
            Deserialize::deserialize(deserializer)?;
        Ok(Self {
            address,
            value,
            owner,
        })
    }
}

impl Debug for PrivateData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        // TODO: Output owners?
        write!(formatter, "PrivateBlob {:?}", self.name())
    }
}

/// Public Blob: an immutable chunk of data which cannot be deleted.
#[derive(Hash, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PublicData {
    /// Network address. Omitted when serialising and calculated from the `value` when
    /// deserialising.
    address: Address,
    /// Contained data.
    value: Vec<u8>,
}

impl PublicData {
    /// Creates a new instance of `Blob`.
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

    /// Returns size of this data after serialisation.
    pub fn serialised_size(&self) -> u64 {
        serialized_size(self).unwrap_or(u64::MAX)
    }

    /// Returns true if the size is valid.
    pub fn validate_size(&self) -> bool {
        self.serialised_size() <= MAX_BLOB_SIZE_IN_BYTES
    }
}

impl Serialize for PublicData {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PublicData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Ok(PublicData::new(value))
    }
}

impl Debug for PublicData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicBlob {:?}", self.name())
    }
}

/// Kind of an Blob.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    /// Private.
    Private,
    /// Public.
    Pub,
}

impl Kind {
    /// Creates `Kind` from a `published` flag.
    pub fn from_flag(published: bool) -> Self {
        if published {
            Kind::Pub
        } else {
            Kind::Private
        }
    }

    /// Returns true if published.
    pub fn is_pub(self) -> bool {
        self == Kind::Pub
    }

    /// Returns true if unpublished.
    pub fn is_unpub(self) -> bool {
        !self.is_pub()
    }
}

/// Address of an Blob.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    /// Private namespace.
    Private(XorName),
    /// Public namespace.
    Public(XorName),
}

impl Address {
    /// Constructs an `Address` given `kind` and `name`.
    pub fn from_kind(kind: Kind, name: XorName) -> Self {
        match kind {
            Kind::Pub => Address::Public(name),
            Kind::Private => Address::Private(name),
        }
    }

    /// Returns the kind.
    pub fn kind(&self) -> Kind {
        match self {
            Address::Private(_) => Kind::Private,
            Address::Public(_) => Kind::Pub,
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        match self {
            Address::Private(ref name) | Address::Public(ref name) => name,
        }
    }

    /// Returns true if published.
    pub fn is_pub(&self) -> bool {
        self.kind().is_pub()
    }

    /// Returns true if unpublished.
    pub fn is_unpub(&self) -> bool {
        self.kind().is_unpub()
    }

    /// Returns the Address serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> Result<String, Error> {
        utils::encode(&self)
    }

    /// Creates from z-base-32 encoded string.
    pub fn decode_from_zbase32<T: AsRef<str>>(encoded: T) -> Result<Self, Error> {
        utils::decode(encoded)
    }
}

/// Object storing an Blob variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    /// Private Blob.
    Private(PrivateData),
    /// Public Blob.
    Public(PublicData),
}

impl Data {
    /// Returns the address.
    pub fn address(&self) -> &Address {
        match self {
            Data::Private(data) => data.address(),
            Data::Public(data) => data.address(),
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        self.address().name()
    }

    /// Returns the owner if private blob.
    pub fn owner(&self) -> Option<&PublicKey> {
        match self {
            Data::Private(data) => Some(data.owner()),
            _ => None,
        }
    }

    /// Returns the kind.
    pub fn kind(&self) -> Kind {
        self.address().kind()
    }

    /// Returns true if published.
    pub fn is_pub(&self) -> bool {
        self.kind().is_pub()
    }

    /// Returns true if unpublished.
    pub fn is_unpub(&self) -> bool {
        self.kind().is_unpub()
    }

    /// Returns the value.
    pub fn value(&self) -> &Vec<u8> {
        match self {
            Data::Private(data) => data.value(),
            Data::Public(data) => data.value(),
        }
    }

    /// Returns `true` if the size is valid.
    pub fn validate_size(&self) -> bool {
        match self {
            Data::Private(data) => data.validate_size(),
            Data::Public(data) => data.validate_size(),
        }
    }

    /// Returns size of this data after serialisation.
    pub fn serialised_size(&self) -> u64 {
        match self {
            Data::Private(data) => data.serialised_size(),
            Data::Public(data) => data.serialised_size(),
        }
    }
}

impl From<PrivateData> for Data {
    fn from(data: PrivateData) -> Self {
        Data::Private(data)
    }
}

impl From<PublicData> for Data {
    fn from(data: PublicData) -> Self {
        Data::Public(data)
    }
}

#[cfg(test)]
mod tests {
    use super::{Address, PrivateData, PublicData, PublicKey, XorName};
    use crate::{utils, Result};
    use hex::encode;
    use rand::{self, Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::{env, iter, thread};
    use threshold_crypto::SecretKey;

    #[test]
    fn deterministic_name() -> Result<()> {
        let data1 = b"Hello".to_vec();
        let data2 = b"Goodbye".to_vec();

        let owner1 = PublicKey::Bls(SecretKey::random().public_key());
        let owner2 = PublicKey::Bls(SecretKey::random().public_key());

        let idata1 = PrivateData::new(data1.clone(), owner1)?;
        let idata2 = PrivateData::new(data1, owner2)?;
        let idata3 = PrivateData::new(data2.clone(), owner1)?;
        let idata3_clone = PrivateData::new(data2, owner1)?;

        assert_eq!(idata3, idata3_clone);

        assert_ne!(idata1.name(), idata2.name());
        assert_ne!(idata1.name(), idata3.name());
        assert_ne!(idata2.name(), idata3.name());
        Ok(())
    }

    #[test]
    fn deterministic_test() {
        let value = "immutable data value".to_owned().into_bytes();
        let blob = PublicData::new(value);
        let blob_name = encode(blob.name().0.as_ref());
        let expected_name = "fac2869677ee06277633c37ac7e8e5c655f3d652f707c7a79fab930d584a3016";

        assert_eq!(&expected_name, &blob_name);
    }

    #[test]
    fn serialisation() -> Result<()> {
        let mut rng = get_rng();
        let len = rng.gen_range(1, 10_000);
        let value = iter::repeat_with(|| rng.gen()).take(len).collect();
        let blob = PublicData::new(value);
        let serialised = utils::serialise(&blob)?;
        let parsed = utils::deserialise(&serialised)?;
        assert_eq!(blob, parsed);
        Ok(())
    }

    fn get_rng() -> XorShiftRng {
        let env_var_name = "RANDOM_SEED";
        let seed = env::var(env_var_name)
            .map(|res| res.parse::<u64>().unwrap_or_else(|_| rand::random()))
            .unwrap_or_else(|_| rand::random());
        println!(
            "To replay this '{}', set env var {}={}",
            thread::current().name().unwrap_or(""),
            env_var_name,
            seed
        );
        XorShiftRng::seed_from_u64(seed)
    }

    #[test]
    fn zbase32_encode_decode_idata_address() -> Result<()> {
        let name = XorName(rand::random());
        let address = Address::Public(name);
        let encoded = address.encode_to_zbase32()?;
        let decoded = self::Address::decode_from_zbase32(&encoded)?;
        assert_eq!(address, decoded);
        Ok(())
    }
}
