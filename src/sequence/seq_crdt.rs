// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::metadata::{Address, Entries, Entry, Index, Perm};
use crate::{Error, PublicKey, Result};
pub use crdts::{lseq::Op, Actor};
use crdts::{
    lseq::{ident::Identifier, LSeq},
    CmRDT, VClock,
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering::*,
    fmt::{self, Display},
    hash::Hash,
};

/// Since in most of the cases it will be append operations, having a small
/// boundary will make the Identifiers' length to be shorter.
const LSEQ_BOUNDARY: u64 = 1;
/// Again, we are going to be dealing with append operations most of the time,
/// thus a large arity be benefitial to keep Identifiers' length short.
const LSEQ_TREE_BASE: u8 = 10; // arity of 1024 at root

/// CRDT data operation applicable to other Sequence replica.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub struct CrdtDataOperation<A: Actor + Display + std::fmt::Debug, T> {
    /// Address of a Sequence object on the network.
    pub address: Address,
    /// The data operation to apply.
    pub crdt_op: Op<T, A>,
    /// The context (policy) this operation depends on
    pub ctx: VClock<A>,
}

/// CRDT policy operation applicable to other Sequence replica.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub struct CrdtPolicyOperation<A: Actor + Display + std::fmt::Debug, T> {
    /// Address of a Sequence object on the network.
    pub address: Address,
    /// The policy operation to apply.
    pub crdt_op: Op<T, A>,
    /// The context (data identifier) this operation depends on
    pub ctx: Option<Identifier<A>>,
}

/// Sequence data type as a CRDT with Access Control
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd)]
pub struct SequenceCrdt<A, P>
where
    A: Actor + Display + std::fmt::Debug,
    P: Perm + Hash + Clone,
{
    /// Address on the network of this piece of data
    address: Address,
    /// CRDT to store the actual data, i.e. the items of the Sequence
    data: LSeq<Entry, A>,
    /// History of the Policy matrix, each entry representing a version of the Policy matrix.
    policy: LSeq<P, A>,
    /// Current version of the Policy, it should be greater or equal to all clocks in the Policy
    /// history. We use this to provide context information to remote replicas when sending
    /// operations, and replicas can verify they are causally ready before applying them.
    policy_clock: VClock<A>,
}

impl<A, P> Display for SequenceCrdt<A, P>
where
    A: Actor + Display + std::fmt::Debug,
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
    A: Actor + Display + std::fmt::Debug,
    P: Perm + Hash + Clone,
{
    /// Constructs a new 'SequenceCrdt'.
    pub fn new(actor: A, address: Address) -> Self {
        Self {
            address,
            data: LSeq::new_with_args(actor.clone(), LSEQ_TREE_BASE, LSEQ_BOUNDARY),
            policy: LSeq::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY),
            policy_clock: VClock::default(),
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

    /// Returns the last policy index.
    pub fn policy_index(&self) -> u64 {
        self.policy.len() as u64
    }

    /// Append a new item to the SequenceCrdt.
    /// Returns the CRDT op and the context it depends on
    pub fn append(&mut self, entry: Entry) -> CrdtDataOperation<A, Entry> {
        let crdt_op = self.data.append(entry);

        // We return the operation as it may need to be broadcasted to other replicas
        CrdtDataOperation {
            address: *self.address(),
            crdt_op,
            ctx: self.policy_clock.clone(),
        }
    }

    /// Apply a remote data CRDT operation to this replica of the Sequence.
    pub fn apply_data_op(&mut self, op: CrdtDataOperation<A, Entry>) -> Result<()> {
        println!("APPLY D: REMOTE CONTEXT: {:?}", op.ctx);
        println!("APPLY D: POLICY CLOCK: {}", self.policy_clock);

        if let Some(Greater) = op.ctx.partial_cmp(&self.policy_clock) {
            // Operation is not causally ready as depends on a policy
            // version we aren't aware of yet.
            // Return error so sender can retry later and/or send the missing policy op
            Err(Error::OpNotCausallyReady)
        } else {
            // Finally, apply the CRDT operation to the data
            self.data.apply(op.crdt_op);
            Ok(())
        }
    }

    /// Sets a new Policy keeping the current one in the history.
    pub fn set_policy(&mut self, policy: P) -> CrdtPolicyOperation<A, P> {
        let crdt_op = self.policy.append(policy);

        // Let's update the policy global clock as well
        self.policy_clock.apply(crdt_op.dot().clone());

        println!("SET P: LOCAL POLICY CLOCK: {:?}", self.data.last_id());

        // We return the operation as it may need to be broadcasted to other replicas
        CrdtPolicyOperation {
            address: *self.address(),
            crdt_op,
            ctx: self.data.last_id().cloned(),
        }
    }

    /// Apply a remote policy CRDT operation to this replica.
    pub fn apply_policy_op(&mut self, op: CrdtPolicyOperation<A, P>) -> Result<()> {
        let dot = op.crdt_op.dot();

        println!("APPLY P: REMOTE CONTEXT: {}", op.ctx.is_some());
        if let (Some(id_in_ctx), Some(id)) = (op.ctx, self.data.last_id()) {
            // Let's check the new policy depends on an item we already have in the sequence
            if id_in_ctx > *id {
                // The policy is not causally ready, return an error
                // so the sender can retry later and/or send the missing ops
                return Err(Error::OpNotCausallyReady);
            }
        }

        // Let's update also the policy global clock
        self.policy_clock.apply(dot.clone());
        // Apply the CRDT operation to the local replica of the policy
        self.policy.apply(op.crdt_op);

        Ok(())
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

    /// Checks if the requester is the last owner.
    ///
    /// Returns:
    /// `Ok(())` if the requester is the owner,
    /// `Err::InvalidOwners` if the last owner is invalid,
    /// `Err::AccessDenied` if the requester is not the owner.
    pub fn check_is_last_owner(&self, requester: PublicKey) -> Result<()> {
        let owner = *self
            .policy(Index::FromEnd(1))
            .ok_or_else(|| Error::InvalidOwners)?
            .owner();

        if requester == owner {
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
