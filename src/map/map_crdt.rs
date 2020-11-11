// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::metadata::{Action, Address, Index, Perm};
use crate::{Error, PublicKey, Result};
pub use crdts::{lseq::Op as LseqOp, map::Op, Actor, LWWReg, MVReg};
use crdts::{
    lseq::{ident::Identifier, Entry as LSeqEntry, LSeq},
    CmRDT, Map,
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering::{Equal, Greater, Less},
    collections::BTreeMap,
    fmt::{self, Display},
    hash::Hash,
};

// /// An action on Data data type.
// #[derive(Clone, Copy, Eq, PartialEq)]
// pub enum Action {
//     /// Read from the data.
//     Read,
//     /// Update key to the data.
//     Update,
//     /// Remove key from the data
//     Remove,
//     /// Manage permissions.
//     Admin,
// }

// /// List of entries.
// pub type Entries = Vec<Entry>;

/// An entry in a Data.
pub type Key = Vec<u8>;
pub type Keys = Vec<Vec<u8>>;
pub type Value = Vec<u8>;
pub type Values = Vec<Vec<u8>>;
pub type Entries = Vec<(Key, Vec<u8>)>;

// type TestActor = u8;
// Version key needs to increment per version... Do we also need a tie break similar to Id here?
// type VersionKey = u8;
type MapValue<A> = MVReg<Value, A>;
type TheActualMap<A> = Map<Key, MapValue<A>, A>;

/// Since in most of the cases it will be append operations, having a small
/// boundary will make the Identifiers' length to be shorter.
const LSEQ_BOUNDARY: u64 = 1;
/// Again, we are going to be dealing with append operations most of the time,
/// thus a large arity be benefitial to keep Identifiers' length short.
const LSEQ_TREE_BASE: u8 = 10; // arity of 1024 at root

/// CRDT Data operation applicable to other Sequence replica.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub struct CrdtDataOperation<A: Actor + Display + std::fmt::Debug> {
    /// Address of a Sequence object on the network.
    pub address: Address,
    /// The data operation to apply.
    pub crdt_op: Op<Key, MapValue<A>, A>,
    /// The context (policy) this operation depends on
    pub ctx: Identifier<A>,
}

type DataVersion = usize;
// type DataVersion = (Key, Version);

/// CRDT Policy operation applicable to other Sequence replica.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub struct CrdtPolicyOperation<A: Actor + Display + std::fmt::Debug, P> {
    /// Address of a Sequence object on the network.
    pub address: Address,
    /// The policy operation to apply.
    pub crdt_op: LseqOp<(P, DataVersion), A>,
    /// The context (previous policy) this operation depends on
    /// // TODO: make second identifier unique for map, based on LSeq versin of a given key (last added)
    /// we probably need a last op field to ensure this...
    pub ctx: Option<(Identifier<A>, DataVersion)>,
}

/// Map data type as a CRDT with Access Control
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd)]
pub struct MapCrdt<A, P>
where
    A: Actor + Display + std::fmt::Debug,
    P: Perm + Hash + Clone,
{
    /// Address on the network of this piece of data
    address: Address,
    /// CRDT to store the actual data, i.e. the items of the Sequence.
    /// We keep different Maps (diverted copies) for each Policy, which allows us to create
    /// branches of the Map when data ops that depend on old policies are applied.
    /// Contents of this map _could_ be configurable down the line...
    data: BTreeMap<Identifier<A>, TheActualMap<A>>,
    /// History of the Policy matrix, each entry representing a version of the Policy matrix
    /// and the last data op the Map when this Policy was applied.
    // TODO: Use something better than DataVersion
    policy: LSeq<(P, DataVersion), A>,
    /// Number of Data Operations applied at this replica
    data_version: DataVersion,
}

impl<A, P> Display for MapCrdt<A, P>
where
    A: Actor + Display + std::fmt::Debug,
    P: Perm + Hash + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        if let Some(map) = self.current_map() {
            for (i, key_read_ctx) in map.keys().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                let the_key = key_read_ctx.val;
                let the_reg = map.get(the_key).val.expect("Listed key contains no value");
                // .ok_or_else(|| std::fmt::Error ("Could not read map value".to_string()))?;
                // TODO sort this for non MVreg
                write!(f, "<{}>", String::from_utf8_lossy(&the_reg.read().val[0]),)?;
            }
        }
        write!(f, "]")
    }
}

impl<A, P> MapCrdt<A, P>
where
    A: Actor + Display + std::fmt::Debug,
    P: Perm + Hash + Clone,
{
    /// Constructs a new 'MapCrdt'.
    pub fn new(actor: A, address: Address) -> Self {
        Self {
            address,
            data: BTreeMap::default(),
            policy: LSeq::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY),
            data_version: 0,
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the length of the sequence.
    pub fn len(&self) -> u64 {
        if let Some(map) = self.current_map() {
            map.len().val as u64
        } else {
            0
        }
    }

    /// Returns the last policy index.
    pub fn policy_index(&self) -> u64 {
        self.policy.len() as u64
    }

    /// Append a new item to the MapCrdt and returns the CRDT operation
    pub fn update(&mut self, key: Key, value: Value) -> Result<CrdtDataOperation<A>> {
        // Retrieve the LSeq corresponding to the current Policy,
        // or create and insert one if there is none.
        let address = *self.address();

        // Let's retrieve current Policy
        match self.policy.last_entry() {
            None => Err(Error::InvalidOperation),
            Some(cur_policy) => match self.data.get_mut(&cur_policy.id) {
                None => Err(Error::Unexpected(
                    "The data is an unexpected or inconsistent state".to_string(),
                )),
                Some(map) => {
                    // TODO: Is this the correct actor here? Should it be from the req itself?
                    let add_ctx = map.read_ctx().derive_add_ctx(self.policy.actor());

                    // Append the entry to the Map corresponding to current Policy
                    let crdt_op = map.update(key, add_ctx, |val, actor| val.write(value, actor));

                    // apply the op locally
                    map.apply(crdt_op.clone());

                    // We return the operation as it may need to be broadcasted to other replicas
                    Ok(CrdtDataOperation {
                        address,
                        crdt_op,
                        ctx: cur_policy.id.clone(),
                    })
                }
            },
        }
    }

    /// Apply a remote data CRDT operation to this replica of the Sequence.
    pub fn apply_data_op(&mut self, op: CrdtDataOperation<A>) -> Result<()> {
        let policy_id = op.ctx.clone();

        // TODO: Save data ops for replay / versioning... do some

        if self.policy.find_entry(&policy_id).is_some() {
            // We have to apply the op to all branches/copies of the Sequence as it may
            // be an old operation which appends an item to the master branch of items
            for LSeqEntry {
                id,
                val: (_, data_version),
                ..
            } in self.policy.iter_entries()
            {
                // We should apply the op to this branch/copy if the Identifier of
                // this Policy is either:
                // - equal to the Policy the op depends on
                // - or greater than the Policy the data op depends on, and if this Policy
                //   depends on a greater or equal item Identifier than the Id of the data op
                let should_apply_op = match id.cmp(&policy_id) {
                    Equal => true,
                    Less => false,
                    // TODO: is version identifier too simplistic + insecure here
                    Greater => true,
                };

                if should_apply_op {
                    // Retrieve the Map corresponding this Policy
                    let map = self.data.get_mut(id).ok_or_else(|| {
                        Error::Unexpected(
                            "The data is an unexpected inconsistent state".to_string(),
                        )
                    })?;

                    // Apply the CRDT operation to the LSeq data
                    map.apply(op.crdt_op.clone());
                }
            }

            Ok(())
        } else {
            // Operation is not causally ready as depends on a policy
            // version we aren't aware of yet.
            // Return error so sender can retry later and/or send the missing policy op/s
            // TODO: perhaps send the last Policy Identifier as a reference to the sender
            Err(Error::OpNotCausallyReady)
        }
    }

    /// Sets a new Policy keeping the current one in the history.
    pub fn set_policy(&mut self, policy: P) -> Result<CrdtPolicyOperation<A, P>> {
        let (new_map, prev_data_version) = match self.policy.last_entry() {
            None => {
                // Create an empty LSeq since there are no items yet for this Policy
                let actor = self.policy.actor();
                (
                    // TODO where does actor fit in here?
                    Map::new(),
                    0,
                )
            }
            Some(cur_policy) => match self.data.get(&cur_policy.id) {
                Some(map) => (map.clone(), cur_policy.val.1),
                None => {
                    // Create an empty LSeq since there are no items yet for this Policy
                    let actor = self.policy.actor();
                    (
                        // TODO where does actor fit in here?
                        Map::new(),
                        cur_policy.val.1,
                    )
                }
            },
        };

        // Last item added to the current Sequence to be used as causal info for new Policy
        // this could be an op
        // or if we have lseq per entry, then the index in the lseq for a given key.
        // as things stand, we'll use the last data op as policy context
        // TODO: THIS IS BROKEN: use a unique and deterministic identifier here.
        let cur_last_item = self.data_version;

        // Append the new Policy to the history
        let crdt_op = self.policy.append((policy, cur_last_item.clone()));

        let policy_id = crdt_op.id().clone();
        let _ = self.data.insert(policy_id.clone(), new_map);

        // Causality info for this Policy op includes current Policy and item Identifiers
        let ctx = Some((policy_id, prev_data_version));

        // We return the operation as it may need to be broadcasted to other replicas
        Ok(CrdtPolicyOperation {
            address: *self.address(),
            crdt_op,
            ctx,
        })
    }

    /// Apply a remote policy CRDT operation to this replica.
    pub fn apply_policy_op(&mut self, op: CrdtPolicyOperation<A, P>) -> Result<()> {
        let new_map = if let Some((policy_id, data_version)) = op.ctx {
            // policy op has a context/causality info,
            // let's check we're not at the first version, and if so, that the op is causally ready for applying
            if data_version > 0 && self.policy.find_entry(&policy_id).is_none() {
                // The policy is not causally ready, return an error
                // so the sender can retry later and/or send the missing ops
                return Err(Error::OpNotCausallyReady);
            } else {
                // Retrieve the Map corresponding to the Policy this op depends on,
                let map: TheActualMap<A> = match self.data.get(&policy_id) {
                    Some(data) => Ok(data.clone()),
                    None => {
                        // if we just instantiated this data
                        if data_version == 0 {
                            Ok(Map::new())
                        } else {
                            Err(Error::Unexpected(
                                "The data is an unexpected or inconsistent state".to_string(),
                            ))
                        }
                    }
                }?;

                // FIXME: Check that we actually have perms to be adding a new policy here, based on prev one...

                match &data_version {
                    0 => {
                        // The Policy doesn't depend on any item thus we return Map
                        map
                    }
                    _ => {
                        // TODO: What do we need to do here for Map...

                        // The Policy depends on specific item Id, create a copy with only
                        // items which Identifier is less than or equal to such Id.
                        // Note this logic is essentially copying the Sequence and undoing
                        // some Append ops which shall be filtered out based on their Id.
                        let actor = self.policy.actor();
                        let mut new_map = Map::new();

                        // map.iter_entries().for_each(|entry| {
                        //     if entry.id <= id {
                        //         let op = Op::Insert {
                        //             id: entry.id.clone(),
                        //             dot: entry.dot.clone(),
                        //             val: entry.val.clone(),
                        //         };
                        //         new_map.apply(op);
                        //     }
                        // });

                        new_map
                    }
                }
            }
        } else {
            // Create an empty Map since there are no items yet for this Policy
            let actor = self.policy.actor();
            Map::new()
        };

        let policy_id = op.crdt_op.id();
        if !self.data.contains_key(policy_id) {
            let _ = self.data.insert(policy_id.clone(), new_map);
        }

        // Apply the CRDT operation to the local replica of the policy
        self.policy.apply(op.crdt_op);

        Ok(())
    }

    /// Gets the entry at `index` if it exists. (Will retrieve the last version of this entry)
    pub fn get(&self, key: &Key) -> Option<Vec<u8>> {
        //TODO: offer api for past versions...
        // and figure out how version keys work...)
        self.current_map().and_then(|map| {
            if let Some(the_map) = map.get(key).val {
                // arbitrary choice from multi value reg... you'd need a tie breaker.
                // but LSEQ is really what we want here... So this should be changed once we have traits there.
                Some(the_map.read().val[0].clone())
            } else {
                None
            }
        })
    }

    /// Retrieve current the keys of the map
    pub fn keys(self) -> Result<Keys> {
        let current_map = self.current_map();

        let current_map = current_map.ok_or("No map found to be current.")?;

        let mut keys = vec![];

        for key in current_map.keys() {
            keys.push(key.val.clone())
        }

        Ok(keys)
    }

    /// Retrieve current the values of the map
    pub fn values(self) -> Result<Values> {
        let current_map = self.current_map();

        let current_map = current_map.ok_or("No map found to be current.")?;

        let mut values = vec![];

        for value in current_map.values() {
            // TODO: rework when versioning
            values.push(value.val.read().val[0].clone())
        }

        Ok(values)
    }

    /// Retrieve current the keys of the map
    pub fn entries(self) -> Result<Entries> {
        let current_map = self.current_map();

        let current_map = current_map.ok_or("No map found to be current.")?;

        let mut entries = vec![];

        for key in current_map.keys() {
            let key = key.val.clone();
            let value = current_map
                .get(&key)
                .val
                .ok_or("Could not get value for given key")?
                .read()
                .val[0]
                .clone();
            entries.push((key, value));
        }

        Ok(entries)
    }

    // /// Gets the last entry.
    // pub fn last_entry(&self) -> Option<&Entry> {
    //     self.current_map().and_then(|lseq| lseq.last())
    // }

    /// Gets a policy from the history at `index` if it exists.
    pub fn policy(&self, index: impl Into<Index>) -> Option<&P> {
        let i = to_absolute_index(index.into(), self.policy.len())?;
        self.policy.get(i).map(|p| &p.0)
    }

    // /// Gets a list of items which are within the given indices.
    // pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
    //     let start_index = to_absolute_index(start, self.len() as usize)?;
    //     let num_items = to_absolute_index(end, self.len() as usize)?; // end_index

    //     self.current_map().map(|lseq| {
    //         lseq.iter()
    //             .take(num_items)
    //             .enumerate()
    //             .take_while(|(i, _)| i >= &start_index)
    //             .map(|(_, entry)| entry.clone())
    //             .collect::<Entries>()
    //     })
    // }

    // Private helper to return the Map correspondng to current/last Policy and Id
    fn current_map(&self) -> Option<&TheActualMap<A>> {
        self.policy
            .last_entry()
            .and_then(|cur_policy| self.data.get(&cur_policy.id))
    }
}

// Private helpers
// TODO: DRY this out
fn to_absolute_index(index: Index, count: usize) -> Option<usize> {
    match index {
        Index::FromStart(index) if index as usize <= count => Some(index as usize),
        Index::FromStart(_) => None,
        Index::FromEnd(index) => count.checked_sub(index as usize),
    }
}
