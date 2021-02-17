// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::metadata::{Address, Entries, Entry, Index, Perm};
use crate::Signature;
use crate::{utils, Error, PublicKey, Result};
pub use crdts::list::Op;
use crdts::{
    list::{Identifier, List},
    CmRDT,
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering::{Equal, Greater, Less},
    collections::BTreeMap,
    fmt::{self, Debug, Display},
    hash::Hash,
};

/// CRDT Data operation applicable to other Sequence replica.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrdtDataOperation<A, T> {
    /// Address of a Sequence object on the network.
    pub address: Address,
    /// The data operation to apply.
    pub crdt_op: Op<T, A>,
    /// The PublicKey of the entity that generated the operation
    pub source: PublicKey,
    /// The context (policy) this operation depends on
    pub ctx: Identifier<A>,
    /// The signature of the crdt_top, required to apply the op
    pub signature: Option<Signature>,
}

/// CRDT Policy operation applicable to other Sequence replica.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrdtPolicyOperation<A, P> {
    /// Address of a Sequence object on the network.
    pub address: Address,
    /// The policy operation to apply.
    pub crdt_op: Op<(P, Option<Identifier<A>>), A>,
    /// The PublicKey of the entity that generated the operation
    pub source: PublicKey,
    /// The context (previous policy) this operation depends on
    pub ctx: Option<(Identifier<A>, Option<Identifier<A>>)>,
    /// The signature of the crdt_top, required to apply the op
    pub signature: Option<Signature>,
}

/// Sequence data type as a CRDT with Access Control
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SequenceCrdt<A: Ord, P> {
    /// Actor of this piece of data
    pub(crate) actor: A,
    /// Address on the network of this piece of data
    address: Address,
    /// CRDT to store the actual data, i.e. the items of the Sequence.
    /// We keep different Lists (diverted copies) for each Policy, which allows us to create
    /// branches of the Sequence when data ops that depend on old policies are applied.
    data: BTreeMap<Identifier<A>, List<Entry, A>>,
    /// History of the Policy matrix, each entry representing a version of the Policy matrix
    /// and the last item in the Sequence when this Policy was applied.
    policy: List<(P, Option<Identifier<A>>), A>,
}

impl<A, P> Display for SequenceCrdt<A, P>
where
    A: Ord + Clone + Display + Debug + Serialize,
    P: Perm + Hash + Clone + Serialize,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        if let Some(list) = self.current_list() {
            for (i, entry) in list.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "<{}>", String::from_utf8_lossy(&entry),)?;
            }
        }
        write!(f, "]")
    }
}

impl<A, P> SequenceCrdt<A, P>
where
    A: Ord + Clone + Debug + Serialize,
    P: Serialize,
{
    /// Constructs a new 'SequenceCrdt'.
    pub fn new(actor: A, address: Address) -> Self {
        Self {
            actor,
            address,
            data: BTreeMap::default(),
            policy: List::new(),
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the length of the sequence.
    pub fn len(&self) -> u64 {
        self.current_list().map(|l| l.len()).unwrap_or_default() as u64
    }

    /// Returns the index of last policy if there is at least a Policy.
    pub fn policy_index(&self) -> Option<u64> {
        if self.policy.is_empty() {
            None
        } else {
            Some((self.policy.len() - 1) as u64)
        }
    }

    /// Create crdt op to append a new item to the SequenceCrdt
    pub fn create_append_op(
        &self,
        entry: Entry,
        source: PublicKey,
    ) -> Result<CrdtDataOperation<A, Entry>> {
        // Retrieve the List corresponding to the current Policy,
        // or create and insert one if there is none.
        let address = *self.address();

        // Let's retrieve current Policy
        match self.policy.last_entry() {
            None => Err(Error::InvalidOperation),
            Some((cur_policy_id, _)) => match self.data.get(&cur_policy_id) {
                None => Err(Error::CrdtUnexpectedState),
                Some(list) => {
                    // Append the entry to the List corresponding to current Policy
                    let crdt_op = list.append(entry, self.actor.clone());

                    // We return the operation as it may need to be broadcasted to other replicas
                    Ok(CrdtDataOperation {
                        address,
                        crdt_op,
                        source,
                        ctx: cur_policy_id.clone(),
                        signature: None,
                    })
                }
            },
        }
    }

    /// Apply a remote data CRDT operation to this replica of the Sequence.
    pub fn apply_data_op(&mut self, op: CrdtDataOperation<A, Entry>) -> Result<()> {
        // First check op is validly signed.
        // Note: Perms for the op are checked at the upper Sequence layer.
        let sig = op.signature.ok_or(Error::CrdtMissingOpSignature)?;
        let bytes_to_verify = utils::serialise(&op.crdt_op).map_err(|err| {
            Error::Serialisation(format!(
                "Could not serialise CRDT data operation to verify signature: {}",
                err
            ))
        })?;
        op.source.verify(&sig, &bytes_to_verify)?;

        let policy_id = op.ctx.clone();
        if self.policy_by_id(&policy_id).is_some() {
            // We have to apply the op to all branches/copies of the Sequence as it may
            // be an old operation which appends an item to the master branch of items
            for (id, (_, item_id)) in self.policy.iter_entries() {
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
                    // Retrieve the List corresponding this Policy, creating if one doesn't exist
                    let list = self.data.entry(id.clone()).or_default();

                    // Apply the CRDT operation to the List data
                    list.apply(op.crdt_op.clone());
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

    /// Create a new crdt policy op
    pub fn create_policy_op(
        &self,
        policy: P,
        source: PublicKey,
    ) -> Result<CrdtPolicyOperation<A, P>> {
        let (new_list, prev_policy_id) = match self.policy.last_entry() {
            None => {
                // Create an empty List since there are no items yet for this Policy
                (List::new(), None)
            }
            Some((cur_policy_id, _)) => match self.data.get(&cur_policy_id) {
                Some(list) => (list.clone(), Some(cur_policy_id.clone())),
                None => {
                    // Create an empty List since there are no items yet for this Policy
                    (List::new(), Some(cur_policy_id.clone()))
                }
            },
        };

        // Last item in current Sequence to be used as causal info for new Policy
        let cur_last_item = new_list.last_entry().map(|(id, _)| id.clone());

        // Append the new Policy to the history
        let crdt_op = self
            .policy
            .append((policy, cur_last_item.clone()), self.actor.clone());

        // Causality info for this Policy op includes current Policy and item Identifiers
        let ctx = prev_policy_id.map(|policy_id| (policy_id, cur_last_item));

        // We return the operation as it may need to be broadcasted to other replicas
        Ok(CrdtPolicyOperation {
            address: *self.address(),
            crdt_op,
            source,
            ctx,
            signature: None,
        })
    }

    /// Apply a remote policy CRDT operation to this replica, keeping the current one in the history.
    pub fn apply_policy_op(&mut self, op: CrdtPolicyOperation<A, P>) -> Result<()> {
        // First check op is validly signed.
        // Note: Perms for the op are checked at the upper Sequence layer.
        let sig = op.signature.ok_or(Error::CrdtMissingOpSignature)?;
        let bytes_to_verify = utils::serialise(&op.crdt_op).map_err(|err| {
            Error::Serialisation(format!(
                "Could not serialise CRDT data operation to verify signature: {}",
                err
            ))
        })?;
        op.source.verify(&sig, &bytes_to_verify)?;

        let new_list = if let Some((policy_id, item_id)) = op.ctx {
            // policy op has a context/causality info,
            // let's check it's causally ready for applying
            if self.policy.get(&policy_id).is_none() {
                // The policy is not causally ready, return an error
                // so the sender can retry later and/or send the missing ops
                return Err(Error::OpNotCausallyReady);
            } else {
                // Retrieve the List corresponding to the Policy this op depends on,
                let list = self
                    .data
                    .get(&policy_id)
                    .ok_or(Error::CrdtUnexpectedState)?;

                // FIXME: Check that we actually have perms to be adding a new policy here, based on prev one...

                match item_id {
                    None => {
                        // The Policy doesn't depend on any item thus we copy the entire Sequence
                        list.clone()
                    }
                    Some(id) => {
                        // The Policy depends on specific item Id, create a copy with only
                        // items which Identifier is less than or equal to such Id.
                        // Note this logic is essentially copying the Sequence and undoing
                        // some Append ops which shall be filtered out based on their Id.
                        let mut new_list = List::new();
                        list.iter_entries().for_each(|(entry_id, val)| {
                            if entry_id <= &id {
                                let op = Op::Insert {
                                    id: entry_id.clone(),
                                    val: val.clone(),
                                };
                                new_list.apply(op);
                            }
                        });

                        new_list
                    }
                }
            }
        } else {
            // Create an empty List since there are no items yet for this Policy
            List::new()
        };

        let policy_id = op.crdt_op.id();
        if !self.data.contains_key(policy_id) {
            let _ = self.data.insert(policy_id.clone(), new_list);
        }

        // Apply the CRDT operation to the local replica of the policy
        self.policy.apply(op.crdt_op);

        Ok(())
    }

    /// Gets the entry at `index` if it exists.
    pub fn get(&self, index: Index) -> Option<&Entry> {
        let i = to_absolute_index(index, self.len() as usize)?;
        self.current_list().and_then(|list| list.position(i))
    }

    /// Gets the last entry.
    pub fn last_entry(&self) -> Option<&Entry> {
        self.current_list().and_then(|list| list.last())
    }

    /// Gets last policy from the history if there is at least one.
    pub fn policy(&self) -> Option<&P> {
        self.policy_at(Index::FromEnd(1))
    }

    /// Gets a policy from the history at `index` if it exists.
    pub fn policy_at(&self, index: impl Into<Index>) -> Option<&P> {
        let i = to_absolute_index(index.into(), self.policy.len())?;
        self.policy.position(i).map(|p| &p.0)
    }

    /// Gets a policy from the history looking it up by its Identfier.
    pub(crate) fn policy_by_id(&self, id: &Identifier<A>) -> Option<&P> {
        self.policy.get(id).map(|val| &val.0)
    }

    /// Gets a list of items which are within the given indices.
    /// Note the range of items is [start, end), i.e. the end index is not inclusive.
    pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
        let count = self.len() as usize;
        let start_index = to_absolute_index(start, count)?;
        if start_index >= count {
            return None;
        }
        let end_index = to_absolute_index(end, count)?;
        let items_to_take = end_index - start_index;

        self.current_list().map(|list| {
            list.iter()
                .skip(start_index)
                .take(items_to_take)
                .cloned()
                .collect::<Entries>()
        })
    }

    // Private helper to return the List correspondng to current/last Policy and Id
    fn current_list(&self) -> Option<&List<Entry, A>> {
        self.policy
            .last_entry()
            .and_then(|(id, _)| self.data.get(id))
    }
}

// Private helpers

fn to_absolute_index(index: Index, count: usize) -> Option<usize> {
    match index {
        Index::FromStart(index) if (index as usize) <= count => Some(index as usize),
        Index::FromStart(_) => None,
        Index::FromEnd(index) => count.checked_sub(index as usize),
    }
}
