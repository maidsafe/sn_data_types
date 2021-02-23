// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::metadata::{Address, Entry, Index, Perm};
use crate::Signature;
use crate::{utils, Error, PublicKey, Result};
pub use crdts::glist::Marker;
use crdts::{
    glist::{GList, Op},
    CmRDT,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Debug, Display},
    hash::Hash,
};

/// CRDT Data operation applicable to other Sequence replica.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrdtOperation {
    /// Address of a Sequence object on the network.
    pub address: Address,
    /// The data operation to apply.
    pub crdt_op: Op<Entry>,
    /// The PublicKey of the entity that generated the operation
    pub source: PublicKey,
    /// The signature of source on the crdt_top, required to apply the op
    pub signature: Option<Signature>,
}

/// Sequence data type as a CRDT with Access Control
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SequenceCrdt<P> {
    /// Address on the network of this piece of data
    address: Address,
    /// CRDT to store the actual data, i.e. the items of the Sequence.
    data: GList<Entry>,
    /// The Policy matrix containing ownership and users permissions.
    policy: P,
}

impl<P> Display for SequenceCrdt<P>
where
    P: Perm + Hash + Clone + Serialize, // TODO: remove these bounds
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        for (i, (_marker, entry)) in self.data.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "<{}>", String::from_utf8_lossy(&entry))?;
        }
        write!(f, "]")
    }
}

impl<P: Serialize> SequenceCrdt<P> {
    /// Constructs a new 'SequenceCrdt'.
    pub fn new(address: Address, policy: P) -> Self {
        Self {
            address,
            data: GList::new(),
            policy,
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the length of the sequence.
    pub fn len(&self) -> u64 {
        self.data.len() as u64
    }

    /// Create crdt op to append a new item to the SequenceCrdt
    pub fn create_append_op(
        &self,
        last_seen_marker: Option<&Marker>,
        entry: Entry,
        source: PublicKey,
    ) -> Result<CrdtOperation> {
        let address = *self.address();

        // Append the entry to the List
        let crdt_op = self.data.insert_after(last_seen_marker, entry);

        // We return the operation as it may need to be broadcasted to other replicas
        Ok(CrdtOperation {
            address,
            crdt_op,
            source,
            signature: None,
        })
    }

    /// Apply a remote data CRDT operation to this replica of the Sequence.
    pub fn apply_op(&mut self, op: CrdtOperation) -> Result<()> {
        // Let's first check the op is validly signed.
        // Note: Perms for the op are checked at the upper Sequence layer.

        let sig = op.signature.ok_or(Error::CrdtMissingOpSignature)?;
        let bytes_to_verify = utils::serialise(&op.crdt_op).map_err(|err| {
            Error::Serialisation(format!(
                "Could not serialise CRDT operation to verify signature: {}",
                err
            ))
        })?;
        op.source.verify(&sig, &bytes_to_verify)?;

        // Apply the CRDT operation to the List data
        self.data.apply(op.crdt_op);

        Ok(())
    }

    /// Gets the entry at `index` if it exists.
    pub fn get(&self, index: Index) -> Option<&(Marker, Entry)> {
        let i = to_absolute_index(index, self.len() as usize)?;
        self.data.get(i)
    }

    /// Gets the last entry.
    pub fn last_entry(&self) -> Option<&(Marker, Entry)> {
        self.data.last()
    }

    /// Gets the Policy of the object.
    pub fn policy(&self) -> &P {
        &self.policy
    }

    /// Gets a list of items which are within the given indices.
    /// Note the range of items is [start, end), i.e. the end index is not inclusive.
    pub fn in_range(&self, start: Index, end: Index) -> Option<Vec<(Marker, Entry)>> {
        let count = self.len() as usize;
        let start_index = to_absolute_index(start, count)?;
        if start_index >= count {
            return None;
        }
        let end_index = to_absolute_index(end, count)?;
        let items_to_take = end_index - start_index;

        Some(
            self.data
                .iter()
                .skip(start_index)
                .take(items_to_take)
                .cloned()
                .collect(),
        )
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
