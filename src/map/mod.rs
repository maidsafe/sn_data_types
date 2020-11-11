// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod map_crdt;

pub use crate::metadata::{
    Action, Address, Index, Kind, Perm, Permissions, Policy, PrivatePermissions, PrivatePolicy,
    PublicPermissions, PublicPolicy, User,
};
use crate::{Error, PublicKey, Result};
use crdts::lseq::Op as LSeqOp;
use map_crdt::{CrdtDataOperation, CrdtPolicyOperation, MapCrdt};
pub use map_crdt::{Entries, Key, Keys, Op, Value, Values};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
    hash::Hash,
};
use xor_name::XorName;

// Type of data used for the 'Actor' in CRDT vector clocks
type ActorType = PublicKey;

/// Map Permissions
pub type MapPermissions = Permissions;
/// Map Public Permissions
pub type MapPublicPermissions = PublicPermissions;
/// Map Private Permissions
pub type MapPrivatePermissions = PrivatePermissions;
/// Map Private Permissions Policy
pub type MapPrivatePolicy = PrivatePolicy;
/// Map Public Permissions Policy
pub type MapPublicPolicy = PublicPolicy;

/// Data mutation operation to apply to Map.
pub type DataWriteOp = CrdtDataOperation<ActorType>;

/// Policy mutation operation to apply to Map.
pub type PolicyWriteOp<T> = CrdtPolicyOperation<ActorType, T>;

/// Public Map.
pub type PublicMapData = MapCrdt<ActorType, PublicPolicy>;
/// Private Map.
pub type PrivateMapData = MapCrdt<ActorType, PrivatePolicy>;

impl Debug for PublicMapData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PubMap {:?}", self.address().name())
    }
}

impl Debug for PrivateMapData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivMap {:?}", self.address().name())
    }
}

/// Object storing a Map variant.
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    /// Public Map Data.
    Public(PublicMapData),
    /// Private Map Data.
    Private(PrivateMapData),
}

impl Data {
    /// Constructs a new Public Map Data.
    pub fn new_public(actor: ActorType, name: XorName, tag: u64) -> Self {
        Self::Public(PublicMapData::new(actor, Address::Public { name, tag }))
    }

    /// Constructs a new Private Map Data.
    pub fn new_private(actor: ActorType, name: XorName, tag: u64) -> Self {
        Self::Private(PrivateMapData::new(actor, Address::Private { name, tag }))
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        match self {
            Data::Public(data) => data.address(),
            Data::Private(data) => data.address(),
        }
    }

    /// Returns the kind.
    pub fn kind(&self) -> Kind {
        self.address().kind()
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        self.address().name()
    }

    /// Returns the tag.
    pub fn tag(&self) -> u64 {
        self.address().tag()
    }

    /// Returns `true` if public.
    pub fn is_pub(&self) -> bool {
        self.kind().is_pub()
    }

    /// Returns `true` if private.
    pub fn is_private(&self) -> bool {
        self.kind().is_private()
    }

    /// Checks permissions for given `action` for the provided user.
    ///
    /// Returns:
    /// `Ok(())` if the permissions are valid,
    /// `Err::InvalidOwners` if the last owner is invalid,
    /// `Err::AccessDenied` if the action is not allowed.
    pub fn check_permission(&self, action: Action, requester: PublicKey) -> Result<()> {
        macro_rules! check_perm {
            ($data: ident, $requester: ident, $action: ident) => {
                $data
                    .policy(Index::FromEnd(1))
                    .ok_or(Error::AccessDenied)?
                    .is_action_allowed($requester, $action)
            };
        }

        match self {
            Data::Public(data) => check_perm!(data, requester, action),
            Data::Private(data) => check_perm!(data, requester, action),
        }
    }

    /// Returns the length of the map.
    pub fn len(&self) -> u64 {
        match self {
            Data::Public(data) => data.len(),
            Data::Private(data) => data.len(),
        }
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the version of last Policy.
    pub fn policy_version(&self) -> u64 {
        match self {
            Data::Public(data) => data.policy_index(),
            Data::Private(data) => data.policy_index(),
        }
    }

    // /// Gets a list of items which are within the given indices.
    // pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
    //     match self {
    //         Data::Public(data) => data.in_range(start, end),
    //         Data::Private(data) => data.in_range(start, end),
    //     }
    // }

    /// Returns a value at 'key', if present.
    pub fn get(&self, key: Key) -> Option<Value> {
        match self {
            Data::Public(data) => data.get(&key),
            Data::Private(data) => data.get(&key),
        }
    }

    // /// Returns the last entry, if present.
    // pub fn last_entry(&self) -> Option<&Entry> {
    //     match self {
    //         Data::Public(data) => data.last_entry(),
    //         Data::Private(data) => data.last_entry(),
    //     }
    // }

    /// Update or insert value at key.
    pub fn update(&mut self, key: Key, value: Value) -> Result<DataWriteOp> {
        match self {
            Data::Public(data) => data.update(key, value),
            Data::Private(data) => data.update(key, value),
        }
    }

    /// Update or insert value at key.
    pub fn keys(self) -> Result<Keys> {
        let keys = match self {
            Data::Public(data) => data.keys(),
            Data::Private(data) => data.keys(),
        }?;

        Ok(keys)
    }

    /// Apply a data CRDT operation.
    pub fn apply_data_op(&mut self, op: DataWriteOp) -> Result<()> {
        match self {
            Data::Public(data) => data.apply_data_op(op),
            Data::Private(data) => data.apply_data_op(op),
        }
    }

    /// Sets the new policy for Public Map.
    pub fn set_public_policy(
        &mut self,
        owner: PublicKey,
        permissions: BTreeMap<User, PublicPermissions>,
    ) -> Result<PolicyWriteOp<PublicPolicy>> {
        match self {
            Data::Public(data) => data.set_policy(PublicPolicy { owner, permissions }),
            Data::Private(_) => Err(Error::InvalidOperation),
        }
    }

    /// Sets the new policy for Private Map.
    pub fn set_private_policy(
        &mut self,
        owner: PublicKey,
        permissions: BTreeMap<PublicKey, PrivatePermissions>,
    ) -> Result<PolicyWriteOp<PrivatePolicy>> {
        match self {
            Data::Private(data) => data.set_policy(PrivatePolicy { owner, permissions }),
            Data::Public(_) => Err(Error::InvalidOperation),
        }
    }

    /// Apply Public Policy CRDT operation.
    pub fn apply_public_policy_op(&mut self, op: PolicyWriteOp<PublicPolicy>) -> Result<()> {
        match (self, &op.crdt_op) {
            (Data::Public(data), LSeqOp::Insert { .. }) => data.apply_policy_op(op),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Apply Private Policy CRDT operation.
    pub fn apply_private_policy_op(&mut self, op: PolicyWriteOp<PrivatePolicy>) -> Result<()> {
        match self {
            Data::Private(data) => data.apply_policy_op(op),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Returns user permissions, if applicable.
    pub fn permissions(&self, user: User, version: impl Into<Index>) -> Result<Permissions> {
        let user_perm = match self {
            Data::Public(data) => data
                .policy(version)
                .ok_or(Error::NoSuchEntry)?
                .permissions(user)
                .ok_or(Error::NoSuchEntry)?,
            Data::Private(data) => data
                .policy(version)
                .ok_or(Error::NoSuchEntry)?
                .permissions(user)
                .ok_or(Error::NoSuchEntry)?,
        };

        Ok(user_perm)
    }

    /// Returns public policy, if applicable.
    pub fn public_policy(&self, version: impl Into<Index>) -> Result<&PublicPolicy> {
        let perms = match self {
            Data::Public(data) => data.policy(version),
            Data::Private(_) => return Err(Error::InvalidOperation),
        };
        perms.ok_or(Error::NoSuchEntry)
    }

    /// Returns private policy, if applicable.
    pub fn private_policy(&self, version: impl Into<Index>) -> Result<&PrivatePolicy> {
        let perms = match self {
            Data::Private(data) => data.policy(version),
            Data::Public(_) => return Err(Error::InvalidOperation),
        };
        perms.ok_or(Error::NoSuchEntry)
    }
}

impl From<PublicMapData> for Data {
    fn from(data: PublicMapData) -> Self {
        Data::Public(data)
    }
}

impl From<PrivateMapData> for Data {
    fn from(data: PrivateMapData) -> Self {
        Data::Private(data)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Error, Keypair, Kind, Map, MapAddress, MapKey, MapPermissions, MapPolicyWriteOp,
        MapPrivatePermissions, MapPublicPermissions, MapPublicPolicy, MapValue, MapWriteOp,
        PublicKey, Result, User,
    };
    use proptest::prelude::*;
    use rand::rngs::OsRng;
    use rand::seq::SliceRandom;
    use std::collections::{BTreeMap, BTreeSet};
    use xor_name::XorName;

    // TODO: DRY THIS
    fn generate_public_key() -> PublicKey {
        let keypair = Keypair::new_ed25519(&mut OsRng);
        keypair.public_key()
    }

    // verify data convergence on a set of replicas and with the expected length
    fn verify_data_convergence(replicas: Vec<Map>, expected_len: usize) -> Result<()> {
        // verify replicas have the expected length
        for r in &replicas {
            assert_eq!(r.len(), expected_len as u64);
        }

        let keys = &replicas[0].clone().keys()?;
        // now verify that the items are the same in all replicas
        for i in 0..expected_len - 1 {
            // -1 as usize one is index 0 in the vec
            let key = &keys[i];
            let r0_entry = &replicas[0].get(key.to_vec()).ok_or("No key found")?;

            for r in &replicas {
                assert_eq!(r0_entry, &r.get(key.to_vec()).ok_or("No key found")?);
            }
        }

        Ok(())
    }

    // Generate a Map entry
    fn generate_map_kv_pair() -> impl Strategy<Value = (Vec<u8>, Vec<u8>)> {
        (
            "\\PC*".prop_map(|s| s.into_bytes()),
            "\\PC*".prop_map(|s| s.into_bytes()),
        )
    }

    // Generate a vec of Sequence entries
    fn generate_dataset(max_quantity: usize) -> impl Strategy<Value = Vec<(Vec<u8>, Vec<u8>)>> {
        prop::collection::vec(generate_map_kv_pair(), 1..max_quantity + 1)
    }

    proptest! {
        #[test]
        fn proptest_map_doesnt_crash_with_random_data(
            (k,v) in generate_map_kv_pair()
        ) {
            let actor1 = generate_public_key();
            let map_name = XorName::random();

            let tag = 43_001u64;

            // Instantiate the same Map on two replicas
            let mut replica1 = Map::new_public(actor1, map_name, tag);
            let mut replica2 = Map::new_public(actor1, map_name, tag);

            // Set Actor1 as the owner
            let perms = BTreeMap::default();
            let owner_op = replica1.set_public_policy(actor1, perms)?;
            replica2.apply_public_policy_op(owner_op)?;

            // Add an item on replicas
            let append_op = replica1.update(k,v)?;
            replica2.apply_data_op(append_op.clone())?;

            verify_data_convergence(vec![replica1, replica2], 1)?;

        }


        #[test]
        fn proptest_map_converges_with_many_random_data(
            dataset in generate_dataset(1000)
        ) {

            let actor1 = generate_public_key();
            let map_name = XorName::random();

            let tag = 43_001u64;

            // Instantiate the same Map on two replicas
            let mut replica1 = Map::new_public(actor1, map_name, tag);
            let mut replica2 = Map::new_public(actor1, map_name, tag);


            // Set Actor1 as the owner
            let perms = BTreeMap::default();
            let owner_op = replica1.set_public_policy(actor1, perms)?;
            replica2.apply_public_policy_op(owner_op)?;

            let mut key_count_set = BTreeSet::new();

            // insert our data at replicas
            for (k,v) in dataset {
                // Update an item on replica1
                let append_op = replica1.update(k.clone(),v)?;

                // we count keys in a set, incase several operations write to the same key + value
                let _ = key_count_set.insert(k);

                // now apply that op to replica 2
                replica2.apply_data_op(append_op)?;
            }

            verify_data_convergence(vec![replica1, replica2], key_count_set.len())?;

        }
    }
}
