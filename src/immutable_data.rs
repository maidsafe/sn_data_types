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

/// Maximum allowed size for a serialised Immutable Data (ID) to grow to
pub const MAX_IMMUTABLE_DATA_SIZE_IN_BYTES: u64 = 1024 * 1024 + 10 * 1024;

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone)]
pub struct UnpubImmutableData {
    /// Address.
    address: Address,
    /// Contained data.
    value: Vec<u8>,
    /// Contains a set of owners of this data. DataManagers enforce that a DELETE or OWNED-GET type
    /// of request is coming from the MaidManager Authority of the owners.
    owner: PublicKey,
}

impl UnpubImmutableData {
    /// Creates a new instance of `UnpubImmutableData`
    pub fn new(value: Vec<u8>, owner: PublicKey) -> Self {
        let hash_of_value = tiny_keccak::sha3_256(&value);
        let serialised_contents = utils::serialise(&(hash_of_value, &owner));
        let address = Address::Unpub(XorName(tiny_keccak::sha3_256(&serialised_contents)));

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

    /// Returns size of this data after serialisation.
    pub fn serialised_size(&self) -> u64 {
        serialized_size(self).unwrap_or(u64::MAX)
    }

    /// Return true if the size is valid
    pub fn validate_size(&self) -> bool {
        self.serialised_size() <= MAX_IMMUTABLE_DATA_SIZE_IN_BYTES
    }
}

impl Serialize for UnpubImmutableData {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        (&self.value, &self.owner).serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for UnpubImmutableData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (value, owner): (Vec<u8>, PublicKey) = Deserialize::deserialize(deserializer)?;
        Ok(UnpubImmutableData::new(value, owner))
    }
}

impl Debug for UnpubImmutableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        // TODO: Output owners?
        write!(formatter, "UnpubImmutableData {:?}", self.name())
    }
}

/// An immutable chunk of data.
///
/// Note that the `name` member is omitted when serialising `ImmutableData` and is calculated from
/// the `value` when deserialising.
#[derive(Hash, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PubImmutableData {
    address: Address,
    value: Vec<u8>,
}

impl PubImmutableData {
    /// Creates a new instance of `ImmutableData`
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            address: Address::Pub(XorName(tiny_keccak::sha3_256(&value))),
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

    /// Return true if the size is valid
    pub fn validate_size(&self) -> bool {
        self.serialised_size() <= MAX_IMMUTABLE_DATA_SIZE_IN_BYTES
    }
}

impl Serialize for PubImmutableData {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PubImmutableData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Ok(PubImmutableData::new(value))
    }
}

impl Debug for PubImmutableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PubImmutableData {:?}", self.name())
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    Unpub,
    Pub,
}

impl Kind {
    pub fn is_pub(self) -> bool {
        self == Kind::Pub
    }

    pub fn is_unpub(self) -> bool {
        !self.is_pub()
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    Unpub(XorName),
    Pub(XorName),
}

impl Address {
    pub fn from_kind(kind: Kind, name: XorName) -> Self {
        match kind {
            Kind::Pub => Address::Pub(name),
            Kind::Unpub => Address::Unpub(name),
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            Address::Unpub(_) => Kind::Unpub,
            Address::Pub(_) => Kind::Pub,
        }
    }

    pub fn name(&self) -> &XorName {
        match self {
            Address::Unpub(ref name) | Address::Pub(ref name) => name,
        }
    }

    pub fn is_pub(&self) -> bool {
        self.kind().is_pub()
    }

    pub fn is_unpub(&self) -> bool {
        self.kind().is_unpub()
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

/// Object storing an immutable data variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    Unpub(UnpubImmutableData),
    Pub(PubImmutableData),
}

impl Data {
    pub fn address(&self) -> &Address {
        match self {
            Data::Unpub(data) => data.address(),
            Data::Pub(data) => data.address(),
        }
    }

    pub fn name(&self) -> &XorName {
        self.address().name()
    }

    pub fn kind(&self) -> Kind {
        self.address().kind()
    }

    pub fn is_pub(&self) -> bool {
        self.kind().is_pub()
    }

    pub fn is_unpub(&self) -> bool {
        self.kind().is_unpub()
    }
}

impl From<UnpubImmutableData> for Data {
    fn from(data: UnpubImmutableData) -> Self {
        Data::Unpub(data)
    }
}

impl From<PubImmutableData> for Data {
    fn from(data: PubImmutableData) -> Self {
        Data::Pub(data)
    }
}

#[cfg(test)]
mod tests {
    use super::{utils, Address, PubImmutableData, PublicKey, UnpubImmutableData, XorName};
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

        let idata1 = UnpubImmutableData::new(data1.clone(), owner1);
        let idata2 = UnpubImmutableData::new(data1, owner2);
        let idata3 = UnpubImmutableData::new(data2.clone(), owner1);
        let idata3_clone = UnpubImmutableData::new(data2, owner1);

        assert_eq!(idata3, idata3_clone);

        assert_ne!(idata1.name(), idata2.name());
        assert_ne!(idata1.name(), idata3.name());
        assert_ne!(idata2.name(), idata3.name());
    }

    #[test]
    fn deterministic_test() {
        let value = "immutable data value".to_owned().into_bytes();
        let immutable_data = PubImmutableData::new(value);
        let immutable_data_name = encode(immutable_data.name().0.as_ref());
        let expected_name = "fac2869677ee06277633c37ac7e8e5c655f3d652f707c7a79fab930d584a3016";

        assert_eq!(&expected_name, &immutable_data_name);
    }

    #[test]
    fn serialisation() {
        let mut rng = get_rng();
        let len = rng.gen_range(1, 10_000);
        let value = iter::repeat_with(|| rng.gen()).take(len).collect();
        let immutable_data = PubImmutableData::new(value);
        let serialised = utils::serialise(&immutable_data);
        let parsed = unwrap!(deserialise(&serialised));
        assert_eq!(immutable_data, parsed);
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
    fn zbase32_encode_decode_idata_address() {
        let name = XorName(rand::random());
        let address = Address::Pub(name);
        let encoded = address.encode_to_zbase32();
        let decoded = unwrap!(self::Address::decode_from_zbase32(&encoded));
        assert_eq!(address, decoded);
    }
}
