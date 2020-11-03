// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::metadata::{Address, Entries, Entry, Index, Perm};
use crate::{Error, Result};
pub use crdts::{map::Op, Actor};
// use crdts::{
//     map::{ident::Identifier, Entry as MapEntry, Map},
//     CmRDT,
// };
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering::{Equal, Greater, Less},
    collections::BTreeMap,
    fmt::{self, Display},
    hash::Hash,
};

// /// Since in most of the cases it will be append operations, having a small
// /// boundary will make the Identifiers' length to be shorter.
// const LSEQ_BOUNDARY: u64 = 1;
// /// Again, we are going to be dealing with append operations most of the time,
// /// thus a large arity be benefitial to keep Identifiers' length short.
// const LSEQ_TREE_BASE: u8 = 10; // arity of 1024 at root

/// CRDT Data operation applicable to other Map replicas.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub struct CrdtDataOperation<A: Actor + Display + std::fmt::Debug, T> {
    /// Address of a Map object on the network.
    pub address: Address,
    /// The data operation to apply.
    pub crdt_op: Op<T, A>,
    /// The context (policy) this operation depends on
    pub ctx: Identifier<A>,
}

/// CRDT Policy operation applicable to other Map replica.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub struct CrdtPolicyOperation<A: Actor + Display + std::fmt::Debug, P> {
    /// Address of a Map object on the network.
    pub address: Address,
    /// The policy operation to apply.
    pub crdt_op: Op<(P, Option<Identifier<A>>), A>,
    /// The context (previous policy) this operation depends on
    pub ctx: Option<(Identifier<A>, Option<Identifier<A>>)>,
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
    /// CRDT to store the actual data, i.e. the items of the Map.
    /// We keep different Maps (diverted copies) for each Policy, which allows us to create
    /// branches of the Map when data ops that depend on old policies are applied.
    data: BTreeMap<Identifier<A>, Map<Entry, A>>,
    /// History of the Policy matrix, each entry representing a version of the Policy matrix
    /// and the last item in the Map when this Policy was applied.
    policy: Map<(P, Option<Identifier<A>>), A>,
}

impl<A, P> Display for MapCrdt<A, P>
where
    A: Actor + Display + std::fmt::Debug,
    P: Perm + Hash + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        if let Some(map) = self.current_map() {
            for (i, entry) in map.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "<{}>", String::from_utf8_lossy(&entry),)?;
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
            policy: Map::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY),
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the length of the sequence.
    pub fn len(&self) -> u64 {
        if let Some(map) = self.current_map() {
            map.len() as u64
        } else {
            0
        }
    }

    /// Returns the last policy index.
    pub fn policy_index(&self) -> u64 {
        self.policy.len() as u64
    }

    /// Append a new item to the MapCrdt and returns the CRDT operation
    pub fn append(&mut self, entry: Entry) -> Result<CrdtDataOperation<A, Entry>> {
        // Retrieve the Map corresponding to the current Policy,
        // or create and insert one if there is none.
        let address = *self.address();

        // Let's retrieve current Policy
        match self.policy.last_entry() {
            None => Err(Error::InvalidOperation),
            Some(cur_policy) => match self.data.get_mut(&cur_policy.id) {
                None => Err(Error::Unexpected(
                    "The data is an unexpected inconsistent state".to_string(),
                )),
                Some(map) => {
                    // Append the entry to the Map corresponding to current Policy
                    let crdt_op = map.append(entry);

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

    /// Apply a remote data CRDT operation to this replica of the Map.
    pub fn apply_data_op(&mut self, op: CrdtDataOperation<A, Entry>) -> Result<()> {
        let policy_id = op.ctx.clone();

        if self.policy.find_entry(&policy_id).is_some() {
            // We have to apply the op to all branches/copies of the Map as it may
            // be an old operation which appends an item to the master branch of items
            for MapEntry {
                id,
                val: (_, item_id),
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
                    Greater => match item_id {
                        None => true,
                        Some(item_id) => item_id >= op.crdt_op.id(),
                    },
                };

                if should_apply_op {
                    // Retrieve the Map corresponding this Policy
                    let map = self.data.get_mut(id).ok_or_else(|| {
                        Error::Unexpected(
                            "The data is an unexpected inconsistent state".to_string(),
                        )
                    })?;

                    // Apply the CRDT operation to the Map data
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
        let (new_map, prev_policy_id) = match self.policy.last_entry() {
            None => {
                // Create an empty Map since there are no items yet for this Policy
                let actor = self.policy.actor();
                (
                    Map::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY),
                    None,
                )
            }
            Some(cur_policy) => match self.data.get(&cur_policy.id) {
                Some(map) => (map.clone(), Some(cur_policy.id.clone())),
                None => {
                    // Create an empty Map since there are no items yet for this Policy
                    let actor = self.policy.actor();
                    (
                        Map::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY),
                        Some(cur_policy.id.clone()),
                    )
                }
            },
        };

        // Last item in current Map to be used as causal info for new Policy
        let cur_last_item = new_map.last_entry().map(|entry| entry.id.clone());

        // Append the new Policy to the history
        let crdt_op = self.policy.append((policy, cur_last_item.clone()));

        let policy_id = crdt_op.id().clone();
        let _ = self.data.insert(policy_id, new_map);

        // Causality info for this Policy op includes current Policy and item Identifiers
        let ctx = prev_policy_id.map(|policy_id| (policy_id, cur_last_item));

        // We return the operation as it may need to be broadcasted to other replicas
        Ok(CrdtPolicyOperation {
            address: *self.address(),
            crdt_op,
            ctx,
        })
    }

    /// Apply a remote policy CRDT operation to this replica.
    pub fn apply_policy_op(&mut self, op: CrdtPolicyOperation<A, P>) -> Result<()> {
        let new_map = if let Some((policy_id, item_id)) = op.ctx {
            // policy op has a context/causality info,
            // let's check it's causally ready for applying
            if self.policy.find_entry(&policy_id).is_none() {
                // The policy is not causally ready, return an error
                // so the sender can retry later and/or send the missing ops
                return Err(Error::OpNotCausallyReady);
            } else {
                // Retrieve the Map corresponding to the Policy this op depends on,
                let map = self.data.get(&policy_id).ok_or_else(|| {
                    Error::Unexpected("The data is an unexpected inconsistent state".to_string())
                })?;

                // FIXME: Check that we actually have perms to be adding a new policy here, based on prev one...

                match item_id {
                    None => {
                        // The Policy doesn't depend on any item thus we copy the entire Map
                        map.clone()
                    }
                    Some(id) => {
                        // The Policy depends on specific item Id, create a copy with only
                        // items which Identifier is less than or equal to such Id.
                        // Note this logic is essentially copying the Map and undoing
                        // some Append ops which shall be filtered out based on their Id.
                        let actor = self.policy.actor();
                        let mut new_map =
                            Map::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY);

                        map.iter_entries().for_each(|entry| {
                            if entry.id <= id {
                                let op = Op::Insert {
                                    id: entry.id.clone(),
                                    dot: entry.dot.clone(),
                                    val: entry.val.clone(),
                                };
                                new_map.apply(op);
                            }
                        });

                        new_map
                    }
                }
            }
        } else {
            // Create an empty Map since there are no items yet for this Policy
            let actor = self.policy.actor();
            Map::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY)
        };

        let policy_id = op.crdt_op.id();
        if !self.data.contains_key(policy_id) {
            let _ = self.data.insert(policy_id.clone(), new_map);
        }

        // Apply the CRDT operation to the local replica of the policy
        self.policy.apply(op.crdt_op);

        Ok(())
    }

    /// Gets the entry at `index` if it exists.
    pub fn get(&self, index: Index) -> Option<&Entry> {
        let i = to_absolute_index(index, self.len() as usize)?;
        self.current_map().and_then(|map| map.get(i))
    }

    /// Gets the last entry.
    pub fn last_entry(&self) -> Option<&Entry> {
        self.current_map().and_then(|map| map.last())
    }

    /// Gets a policy from the history at `index` if it exists.
    pub fn policy(&self, index: impl Into<Index>) -> Option<&P> {
        let i = to_absolute_index(index.into(), self.policy.len())?;
        self.policy.get(i).map(|p| &p.0)
    }

    /// Gets a list of items which are within the given indices.
    pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
        let start_index = to_absolute_index(start, self.len() as usize)?;
        let num_items = to_absolute_index(end, self.len() as usize)?; // end_index

        self.current_map().map(|map| {
            map.iter()
                .take(num_items)
                .enumerate()
                .take_while(|(i, _)| i >= &start_index)
                .map(|(_, entry)| entry.clone())
                .collect::<Entries>()
        })
    }

    // Private helper to return the Map correspondng to current/last Policy and Id
    fn current_map(&self) -> Option<&Map<Entry, A>> {
        self.policy
            .last_entry()
            .and_then(|cur_policy| self.data.get(&cur_policy.id))
    }
}

// Private helpers

fn to_absolute_index(index: Index, count: usize) -> Option<usize> {
    match index {
        Index::FromStart(index) if index as usize <= count => Some(index as usize),
        Index::FromStart(_) => None,
        Index::FromEnd(index) => count.checked_sub(index as usize),
    }
}
