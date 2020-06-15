// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::metadata::{Address, Entries, Entry, Index, Indices, Owner, Perm};
use crate::{Error, PublicKey, Result};
use crdts::{lseq::LSeq, CmRDT};
pub use crdts::{lseq::Op, Actor};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display},
    hash::Hash,
};

/// Since in most of the cases it will be appends operations, having a small
/// boundary will make the Identifiers' length to be shorter.
const LSEQ_BOUNDARY: u64 = 1;
/// Again, we are going to be dealing with append operations most of the time,
/// thus a large arity be benefitial to keep Identifiers' length short.
const LSEQ_TREE_BASE: u8 = 10; // arity of 1024 at root

/// Sequence data type as a CRDT
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd)]
pub struct SequenceCrdt<A, P>
where
    A: Actor,
    P: Perm + Hash + Clone,
{
    /// Address on the network of this piece of data
    address: Address,
    /// CRDT to store the actual data
    data: LSeq<Entry, A>,
    /// This is the history of permissions matrix, with each entry representing a permissions matrix.
    permissions: LSeq<P, A>,
    /// This is the history of owners, with each entry representing an owner. Each single owner
    /// could represent an individual user, or a group of users, depending on the `PublicKey` type.
    owners: LSeq<Owner, A>,
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
            permissions: LSeq::new_with_args(actor.clone(), LSEQ_TREE_BASE, LSEQ_BOUNDARY),
            owners: LSeq::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY),
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

    /// Returns the last permissions index.
    pub fn permissions_index(&self) -> u64 {
        self.permissions.len() as u64
    }

    /// Append a new item to the SequenceCrdt.
    pub fn append(&mut self, entry: Entry) -> Op<Entry, A> {
        // We return the operation in case it needs to be broadcasted to other replicas
        self.data.append(entry)
    }

    /// Apply CRDT operation.
    pub fn apply_crdt_op(&mut self, op: Op<Entry, A>) {
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

    /// Gets a complete list of permissions.
    pub fn permissions(&self, index: impl Into<Index>) -> Option<&P> {
        let index = to_absolute_index(index.into(), self.permissions.len())?;
        self.permissions.get(index)
    }

    /// Returns the owner's public key and the indices at the time it was added.
    pub fn owner(&self, owners_index: impl Into<Index>) -> Option<&Owner> {
        let index = to_absolute_index(owners_index.into(), self.owners.len())?;
        self.owners.get(index)
    }

    /// Gets a list of keys and values with the given indices.
    pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
        let start_index = to_absolute_index(start, self.entries_index() as usize)?;
        let end_index = to_absolute_index(end, self.entries_index() as usize)?;

        let range = self
            .data
            .iter()
            .enumerate()
            .filter_map(|(i, entry)| {
                if i >= start_index && i < end_index {
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

    /// Returns a tuple containing the last entries index, last owners index, and last permissions
    /// indices.
    ///
    /// Always returns `Ok(Indices)`.
    pub fn indices(&self) -> Result<Indices> {
        Ok(Indices::new(
            self.entries_index(),
            self.owners_index(),
            self.permissions_index(),
        ))
    }

    /// Adds a new permissions entry.
    /// The `Perm` struct should contain valid indices.
    pub fn append_permissions(&mut self, permissions: P) -> Op<P, A> {
        self.permissions.append(permissions)
    }

    /// Apply Permissions CRDT operation.
    pub fn apply_crdt_perms_op(&mut self, op: Op<P, A>) {
        self.permissions.apply(op)
    }

    /// Adds a new owner entry.
    pub fn append_owner(&mut self, public_key: PublicKey) -> Op<Owner, A> {
        self.owners.append(Owner {
            entries_index: self.entries_index(),
            permissions_index: self.permissions_index(),
            public_key,
        })
    }

    /// Apply Owner CRDT operation.
    pub fn apply_crdt_owner_op(&mut self, op: Op<Owner, A>) {
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
