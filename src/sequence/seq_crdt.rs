// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::metadata::{Address, Entries, Entry, Index, Owner, Perm};
use crate::{Error, PublicKey, Result};
use crdts::{lseq::LSeq, CmRDT, VClock};
pub use crdts::{lseq::Op, Actor};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display},
    hash::Hash,
};

/// Since in most of the cases it will be append operations, having a small
/// boundary will make the Identifiers' length to be shorter.
const LSEQ_BOUNDARY: u64 = 1;
/// Again, we are going to be dealing with append operations most of the time,
/// thus a large arity be benefitial to keep Identifiers' length short.
const LSEQ_TREE_BASE: u8 = 10; // arity of 1024 at root

/// Sequence data type as a CRDT with Access Control
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd)]
pub struct SequenceCrdt<A, P>
where
    A: Actor,
    P: Perm + Hash + Clone,
{
    /// Address on the network of this piece of data
    address: Address,
    /// CRDT to store the actual data, i.e. the items of the Sequence
    data: LSeq<Entry, A>,
    /// History of the Policy matrix, each entry representing a version of the Policy matrix.
    policy: LSeq<P, A>,
    /// Current version of the Policy, it should be greater or equal to all clocks in the Policy
    /// history. We use this to verify that operations are causally ready before applying them.
    policy_clock: VClock<A>,
    /// History of owners, each entry representing a version of the owner. An owner could
    /// represent an individual user, or a group of users, depending on the `PublicKey` type.
    owners: LSeq<Owner, A>,
    /// Overall version of the Sequence, it should be greater or equal to all clocks in
    /// the data, as well as policy and owners history. We use this to provide context
    /// information to remote replicas when applying the operations.
    clock: VClock<A>,
}

impl<A, P> Display for SequenceCrdt<A, P>
where
    A: Actor,
    P: Perm + Hash + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        for (i, entry) in self.data.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "<{}>", String::from_utf8_lossy(&entry),)?;
        }
        write!(f, "]")
    }
}

impl<A, P> SequenceCrdt<A, P>
where
    A: Actor,
    P: Perm + Hash + Clone,
{
    /// Constructs a new 'SequenceCrdt'.
    pub fn new(actor: A, address: Address) -> Self {
        Self {
            address,
            data: LSeq::new_with_args(actor.clone(), LSEQ_TREE_BASE, LSEQ_BOUNDARY),
            policy: LSeq::new_with_args(actor.clone(), LSEQ_TREE_BASE, LSEQ_BOUNDARY),
            policy_clock: VClock::default(),
            owners: LSeq::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY),
            clock: VClock::default(),
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the last entries index.
    pub fn entries_index(&self) -> u64 {
        self.data.len() as u64
    }

    /// Returns the last owners index.
    pub fn owners_index(&self) -> u64 {
        self.owners.len() as u64
    }

    /// Returns the last policy index.
    pub fn policy_index(&self) -> u64 {
        self.policy.len() as u64
    }

    /// Append a new item to the SequenceCrdt.
    pub fn append(&mut self, entry: Entry) -> Op<Entry, A> {
        // We return the operation as it may need to be broadcasted to other replicas
        let op = self.data.append(entry);
        // Let's update the global clock
        self.clock.apply(op.dot().clone());

        op
    }

    /// Apply a remote data CRDT operation to this replica of the Sequence.
    pub fn apply_crdt_op(&mut self, op: Op<Entry, A>) {
        let dot = op.dot();
        /*if self.clock.get(&dot.actor) >= dot.counter {
            // We ignore it since we've seen this op already
            println!("WE've seen this op: {:?}", dot.counter);
            return;
        }*/

        // Let's update the global clock
        self.clock.apply(dot.clone());
        // Finally, apply the CRDT operation to the data
        self.data.apply(op)
    }

    /// Gets the entry at `index` if it exists.
    pub fn get(&self, index: Index) -> Option<&Entry> {
        let i = to_absolute_index(index, self.entries_index() as usize)?;
        self.data.get(i)
    }

    /// Gets the last entry.
    pub fn last_entry(&self) -> Option<&Entry> {
        self.data.last()
    }

    /// Gets a policy from the history at `index` if it exists.
    pub fn policy(&self, index: impl Into<Index>) -> Option<&P> {
        let index = to_absolute_index(index.into(), self.policy.len())?;
        self.policy.get(index)
    }

    /// Gets an owner from the history at `index` if it exists.
    pub fn owner(&self, owners_index: impl Into<Index>) -> Option<&Owner> {
        let index = to_absolute_index(owners_index.into(), self.owners.len())?;
        self.owners.get(index)
    }

    /// Gets a list of items which are within the given indices.
    pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
        let start_index = to_absolute_index(start, self.entries_index() as usize)?;
        let end_index = to_absolute_index(end, self.entries_index() as usize)?;

        let range = self
            .data
            .iter()
            .take(end_index - 1)
            .enumerate()
            .filter_map(|(i, entry)| {
                if i >= start_index {
                    Some(entry.clone())
                } else {
                    None
                }
            })
            .collect::<Entries>();

        if range.is_empty() {
            None
        } else {
            Some(range)
        }
    }

    /// Sets a new Policy keeping the current one in the history.
    /// The Policy should contain valid indices.
    pub fn set_policy(&mut self, policy: P) -> Op<P, A> {
        let op = self.policy.append(policy);
        // Let's update the global clock
        self.clock.apply(op.dot().clone());
        // Let's update the policy global clock as well
        self.policy_clock.apply(op.dot().clone());

        op
    }

    /// Apply a remote policy CRDT operation to this replica.
    pub fn apply_crdt_policy_op(&mut self, op: Op<P, A>) {
        let dot = op.dot();
        // if local policy clock = clock in OP then go ahead
        /*if self.clock.get(&dot.actor) >= dot.counter {
            // We ignore it since we've seen this op already
            println!("WE've seen this perms op: {} > counter={:?}", self.clock.get(&dot.actor), dot.counter);
            return;
        }*/

        // Let's update the global clock
        self.clock.apply(dot.clone());
        // Let's update also the policy global clock
        self.policy_clock.apply(dot.clone());
        // Finally, apply the CRDT operation to the local replica of the policy
        self.policy.apply(op)
    }

    /// Sets a new Owner keeping the current one in the history.
    // TODO: make the owner to be part of the policy
    pub fn set_owner(&mut self, public_key: PublicKey) -> Op<Owner, A> {
        self.owners.append(Owner {
            entries_index: self.entries_index(),
            policy_index: self.policy_index(),
            public_key,
        })

        // TODO: update global clock
    }

    /// Apply a remote owner CRDT operation to this replica.
    // TODO: make the owner to be part of the policy
    pub fn apply_crdt_owner_op(&mut self, op: Op<Owner, A>) {
        let dot = op.dot();
        /*if self.clock.get(&dot.actor) >= dot.counter {
            // We ignore it since we've seen this op already
            return;
        }*/

        // Let's update the global clock
        self.clock.apply(dot.clone());
        // Finally, apply the CRDT operation to the owner
        self.owners.apply(op)
    }

    /// Checks if the requester is the last owner.
    ///
    /// Returns:
    /// `Ok(())` if the requester is the owner,
    /// `Err::InvalidOwners` if the last owner is invalid,
    /// `Err::AccessDenied` if the requester is not the owner.
    pub fn check_is_last_owner(&self, requester: PublicKey) -> Result<()> {
        if self
            .owner(Index::FromEnd(1))
            .ok_or_else(|| Error::InvalidOwners)?
            .public_key
            == requester
        {
            Ok(())
        } else {
            Err(Error::AccessDenied)
        }
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
