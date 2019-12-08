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
use multibase::Decodable;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{self, Debug, Formatter},
    u64,
};
use tiny_keccak;

/// Maximum allowed size for a serialised blob (ID) to grow to
pub const MAX_BLOB_SIZE_IN_BYTES: u64 = 1024 * 1024 + 10 * 1024;

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone)]
pub struct PrivateBlob {
    /// Address.
    address: Address,
    /// Contained data.
    value: Vec<u8>,
    /// Contains a set of owners of this data. DataHandlers enforce that a DELETE or OWNED-GET type
    /// of request is coming from the MaidManager Authority of the owners.
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

    /// Returns size of this BlobData after serialisation.
    pub fn serialised_size(&self) -> u64 {
        serialized_size(self).unwrap_or(u64::MAX)
    }

    /// Return true if the size is valid
    pub fn valid_size(&self) -> bool {
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

/// An immutable chunk of data.
///
/// Note that the `name` member is omitted when serialising `Blob` and is calculated from
/// the `value` when deserialising.
#[derive(Hash, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PublicBlob {
    address: Address,
    value: Vec<u8>,
}

impl PublicBlob {
    /// Creates a new instance of `ImmutableData`
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

    /// Returns size of this BlobData after serialisation.
    pub fn serialised_size(&self) -> u64 {
        serialized_size(self).unwrap_or(u64::MAX)
    }

    /// Return true if the size is valid
    pub fn valid_size(&self) -> bool {
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

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    Private,
    Public,
}

impl Kind {
    pub fn is_public(self) -> bool {
        self == Kind::Public
    }

    pub fn is_private(self) -> bool {
        !self.is_public()
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    Private(XorName),
    Public(XorName),
}

impl Address {
    pub fn from_kind(kind: Kind, name: XorName) -> Self {
        match kind {
            Kind::Public => Address::Public(name),
            Kind::Private => Address::Private(name),
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            Address::Private(_) => Kind::Private,
            Address::Public(_) => Kind::Public,
        }
    }

    pub fn name(&self) -> &XorName {
        match self {
            Address::Private(ref name) | Address::Public(ref name) => name,
        }
    }

    pub fn is_public(&self) -> bool {
        self.kind().is_public()
    }

    pub fn is_private(&self) -> bool {
        self.kind().is_private()
    }

    /// Returns the Address serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Create from z-base-32 encoded string.
    pub fn decode_from_zbase32<T: Decodable>(encoded: T) -> Result<Self, Error> {
        utils::decode(encoded)
    }
}

/// Object storing an blob variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum BlobData {
    Private(PrivateBlob),
    Public(PublicBlob),
}

impl BlobData {
    pub fn address(&self) -> &Address {
        match self {
            BlobData::Private(data) => data.address(),
            BlobData::Public(data) => data.address(),
        }
    }

    pub fn name(&self) -> &XorName {
        self.address().name()
    }

    pub fn kind(&self) -> Kind {
        self.address().kind()
    }

    pub fn is_public(&self) -> bool {
        self.kind().is_public()
    }

    pub fn is_private(&self) -> bool {
        self.kind().is_private()
    }

    pub fn value(&self) -> &Vec<u8> {
        match self {
            BlobData::Private(data) => data.value(),
            BlobData::Public(data) => data.value(),
        }
    }

    pub fn valid_size(&self) -> bool {
        match self {
            BlobData::Private(data) => data.valid_size(),
            BlobData::Public(data) => data.valid_size(),
        }
    }

    pub fn serialised_size(&self) -> u64 {
        match self {
            BlobData::Private(data) => data.serialised_size(),
            BlobData::Public(data) => data.serialised_size(),
        }
    }
}

impl From<PrivateBlob> for BlobData {
    fn from(data: PrivateBlob) -> Self {
        BlobData::Private(data)
    }
}

impl From<PublicBlob> for BlobData {
    fn from(data: PublicBlob) -> Self {
        BlobData::Public(data)
    }
}

#[cfg(test)]
mod tests {
    use super::{utils, Address, PrivateBlob, PublicBlob, PublicKey, XorName};
    use bincode::deserialize as deserialise;
    use hex::encode;
    use rand::{self, Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::{env, iter, thread};
    use threshold_crypto::SecretKey;
    use unwrap::unwrap;

    #[test]
    fn deterministic_name() {
        let data1 = b"Hello".to_vec();
        let data2 = b"Goodbye".to_vec();

        let owner1 = PublicKey::Bls(SecretKey::random().public_key());
        let owner2 = PublicKey::Bls(SecretKey::random().public_key());

        let idata1 = PrivateBlob::new(data1.clone(), owner1);
        let idata2 = PrivateBlob::new(data1, owner2);
        let idata3 = PrivateBlob::new(data2.clone(), owner1);
        let idata3_clone = PrivateBlob::new(data2, owner1);

        assert_eq!(idata3, idata3_clone);

        assert_ne!(idata1.name(), idata2.name());
        assert_ne!(idata1.name(), idata3.name());
        assert_ne!(idata2.name(), idata3.name());
    }

    #[test]
    fn deterministic_test() {
        let value = "immutable data value".to_owned().into_bytes();
        let blob = PublicBlob::new(value);
        let blob_name = encode(blob.name().0.as_ref());
        let expected_name = "fac2869677ee06277633c37ac7e8e5c655f3d652f707c7a79fab930d584a3016";

        assert_eq!(&expected_name, &blob_name);
    }

    #[test]
    fn serialisation() {
        let mut rng = get_rng();
        let len = rng.gen_range(1, 10_000);
        let value = iter::repeat_with(|| rng.gen()).take(len).collect();
        let blob = PublicBlob::new(value);
        let serialised = utils::serialise(&blob);
        let parsed = unwrap!(deserialise(&serialised));
        assert_eq!(blob, parsed);
    }

    fn get_rng() -> XorShiftRng {
        let env_var_name = "RANDOM_SEED";
        let seed = env::var(env_var_name)
            .ok()
            .map(|value| {
                unwrap!(
                    value.parse::<u64>(),
                    "Env var 'RANDOM_SEED={}' is not a valid u64.",
                    value
                )
            })
            .unwrap_or_else(rand::random);
        println!(
            "To replay this '{}', set env var {}={}",
            unwrap!(thread::current().name()),
            env_var_name,
            seed
        );
        XorShiftRng::seed_from_u64(seed)
    }

    #[test]
    fn zbase32_encode_decode_blob_address() {
        let name = XorName(rand::random());
        let address = Address::Public(name);
        let encoded = address.encode_to_zbase32();
        let decoded = unwrap!(self::Address::decode_from_zbase32(&encoded));
        assert_eq!(address, decoded);
    }
}
