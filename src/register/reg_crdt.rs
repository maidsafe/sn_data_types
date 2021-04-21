// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::metadata::{Address, Entry};
use crate::{
    Signature, {utils, Error, PublicKey, Result},
};
pub use crdts::merkle_reg::Hash as EntryHash;
use crdts::{
    merkle_reg::{MerkleReg, Node},
    CmRDT,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Display},
    hash::Hash,
};

/// CRDT Data operation applicable to other Register replica.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrdtOperation<T> {
    /// Address of a Register object on the network.
    pub address: Address,
    /// The data operation to apply.
    pub crdt_op: Node<T>,
    /// The PublicKey of the entity that generated the operation
    pub source: PublicKey,
    /// The signature of source on the crdt_top, required to apply the op
    pub signature: Option<Signature>,
}

/// Register data type as a CRDT with Access Control
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd)]
pub struct RegisterCrdt {
    /// Address on the network of this piece of data
    address: Address,
    /// CRDT to store the actual data, i.e. the items of the Register.
    data: MerkleReg<Entry>,
}

impl Display for RegisterCrdt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(")?;
        for (i, entry) in self.data.read().values().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "<{}>", String::from_utf8_lossy(&entry),)?;
        }
        write!(f, ")")
    }
}

impl RegisterCrdt {
    /// Constructs a new 'RegisterCrdt'.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            data: MerkleReg::new(),
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns total number of items in the register.
    pub fn size(&self) -> u64 {
        (self.data.num_nodes() + self.data.num_orphans()) as u64
    }

    /// Write a new entry to the RegisterCrdt, returning the hash
    /// of the entry and the CRDT operation without a signature
    pub fn write(
        &mut self,
        entry: Entry,
        parents: BTreeSet<EntryHash>,
        source: PublicKey,
    ) -> Result<(EntryHash, CrdtOperation<Entry>)> {
        let address = *self.address();

        let crdt_op = self.data.write(entry, parents);
        self.data.apply(crdt_op.clone());
        let hash = crdt_op.hash();

        // We return the operation as it may need to be broadcasted to other replicas
        let op = CrdtOperation {
            address,
            crdt_op,
            source,
            signature: None,
        };

        Ok((hash, op))
    }

    /// Apply a remote data CRDT operation to this replica of the RegisterCrdt.
    pub fn apply_op(&mut self, op: CrdtOperation<Entry>) -> Result<()> {
        // Let's first check the op is validly signed.
        // Note: Perms for the op are checked at the upper Register layer.
        let sig = op.signature.ok_or(Error::CrdtMissingOpSignature)?;
        let bytes_to_verify = utils::serialise(&op.crdt_op).map_err(|err| {
            Error::Serialisation(format!(
                "Could not serialise CRDT operation to verify signature: {}",
                err
            ))
        })?;
        op.source.verify(&sig, &bytes_to_verify)?;

        // Check the targetting address is correct
        if self.address != op.address {
            return Err(Error::CrdtWrongAddress(op.address));
        }

        // Apply the CRDT operation to the Register
        self.data.apply(op.crdt_op);

        Ok(())
    }

    /// Get the entry corresponding to the provided `hash` if it exists.
    pub fn get(&self, hash: EntryHash) -> Option<&Entry> {
        self.data.node(hash).map(|node| &node.value)
    }

    /// Read the last entry, or entries if there are branches.
    pub fn read(&self) -> BTreeSet<(EntryHash, Entry)> {
        self.data
            .read()
            .hashes_and_nodes()
            .map(|(hash, node)| (hash, node.value.clone()))
            .collect()
    }
}
