// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

// TODO: Remove this once the false-positive has been fixed:
// https://github.com/rust-lang/rust-clippy/issues/4326.
#![allow(clippy::type_repetition_in_bounds)]

use super::append_only_data::{
    Action, Address, Entries, Entry, Index, Indices, Owner, PubPermissionSet, PubPermissions, User,
};
use crate::{Error, PublicKey, Result, XorName};
use crdts::{CmRDT, MVReg};
use serde::{Deserialize, Serialize};

// TODO: make this a parameter of the Sequence
type ActorType = XorName;

/// Sequence data type with a CRDT implementation
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sequence {
    address: Address,
    data: MVReg<Entry, ActorType>,
    permissions: Vec<PubPermissions>,
    /// This is the history of owners, with each entry representing an owner. Each single owner
    /// could represent an individual user, or a group of users, depending on the `PublicKey` type.
    owners: Vec<Owner>,
}

impl Sequence {
    /// Constructs a new 'Sequence'
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PubSeq { name, tag },
            data: MVReg::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
        }
    }

    /// Returns the shell of the data.
    pub fn shell(&self, entries_index: impl Into<Index>) -> Result<Self> {
        let entries_index = to_absolute_index(entries_index.into(), self.entries_index() as usize)
            .ok_or(Error::NoSuchEntry)? as u64;

        let permissions = self
            .permissions
            .iter()
            .filter(|perm| perm.entries_index <= entries_index)
            .cloned()
            .collect();

        let owners = self
            .owners
            .iter()
            .filter(|owner| owner.entries_index <= entries_index)
            .cloned()
            .collect();

        Ok(Self {
            address: self.address,
            data: MVReg::new(),
            permissions,
            owners,
        })
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Append a new item to the Sequence
    pub fn append(
        &mut self,
        entries: Entries,
        current_entries_index: Option<u64>,
        actor: ActorType,
    ) -> Result<()> {
        let read_ctx = self.data.read();
        let current_index = read_ctx.val.len() as u64;
        if let Some(index) = current_entries_index {
            if index != current_index {
                return Err(Error::InvalidSuccessor(current_index));
            }
        }

        let operation = self
            .data
            .write(entries[0].clone(), read_ctx.derive_add_ctx(actor));
        self.data.apply(operation);
        Ok(())
    }

    /// Returns the last entries index.
    pub fn entries_index(&self) -> u64 {
        let read_ctx = self.data.read();
        read_ctx.val.len() as u64
    }

    /// Returns the last owners index.
    pub fn owners_index(&self) -> u64 {
        self.owners.len() as u64
    }

    /// Returns the last permissions index.
    pub fn permissions_index(&self) -> u64 {
        self.permissions.len() as u64
    }

    /// Gets the entry at `key` if it exists.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let read_ctx = self.data.read();
        read_ctx.val.iter().find_map(|ref entry| {
            if entry.key.as_slice() == key {
                Some(entry.value.clone())
            } else {
                None
            }
        })
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

    /// Gets the last entry.
    pub fn last_entry(&self) -> Option<Entry> {
        let read_ctx = self.data.read();
        match read_ctx.val.last() {
            Some(entry) => Some((*entry).clone()),
            None => None,
        }
    }

    /// Checks permissions for given `action` for the provided user.
    ///
    /// Returns:
    /// `Ok(())` if the permissions are valid,
    /// `Err::InvalidOwners` if the last owner is invalid,
    /// `Err::AccessDenied` if the action is not allowed.
    pub fn check_permission(&self, _action: Action, _requester: PublicKey) -> Result<()> {
        Ok(())
    }

    /// Adds a new permissions entry.
    /// The `Perm` struct should contain valid indices.
    ///
    /// If the specified `permissions_index` does not match the last recorded permissions
    /// index + 1, an error will be returned.
    pub fn append_permissions(
        &mut self,
        permissions: PubPermissions,
        permissions_index: u64,
    ) -> Result<()> {
        if permissions.entries_index != self.entries_index() {
            return Err(Error::InvalidSuccessor(self.entries_index()));
        }
        if permissions.owners_index != self.owners_index() {
            return Err(Error::InvalidOwnersSuccessor(self.owners_index()));
        }
        if self.permissions_index() != permissions_index {
            return Err(Error::InvalidSuccessor(self.permissions_index()));
        }
        self.permissions.push(permissions);
        Ok(())
    }

    /// Adds a new owner entry.
    ///
    /// If the specified `owners_index` does not match the last recorded owners index + 1,
    /// an error will be returned.
    pub fn append_owner(&mut self, owner: Owner, owners_index: u64) -> Result<()> {
        if owner.entries_index != self.entries_index() {
            return Err(Error::InvalidSuccessor(self.entries_index()));
        }
        if owner.permissions_index != self.permissions_index() {
            return Err(Error::InvalidPermissionsSuccessor(self.permissions_index()));
        }
        if self.owners_index() != owners_index {
            return Err(Error::InvalidSuccessor(self.owners_index()));
        }
        self.owners.push(owner);
        Ok(())
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

    /// Gets a complete list of permissions.
    pub fn permissions(&self, index: impl Into<Index>) -> Result<&PubPermissions> {
        let index =
            to_absolute_index(index.into(), self.permissions.len()).ok_or(Error::NoSuchEntry)?;
        self.permissions.get(index).ok_or(Error::NoSuchEntry)
    }

    /// Returns user permissions, if applicable.
    pub fn user_permissions(
        &self,
        user: User,
        index: impl Into<Index>,
    ) -> Result<PubPermissionSet> {
        self.permissions(index)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    /// Returns the owner's public key and the indices at the time it was added.
    pub fn owner(&self, owners_index: impl Into<Index>) -> Option<&Owner> {
        let index = to_absolute_index(owners_index.into(), self.owners.len())?;
        self.owners.get(index)
    }

    /// Gets a list of keys and values with the given indices.
    pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
        let read_ctx = self.data.read();
        let start_index = to_absolute_index(start.into(), self.entries_index() as usize)?;
        let end_index = to_absolute_index(end.into(), self.entries_index() as usize)?;

        let range = read_ctx.val[start_index..end_index].to_vec();
        if range.is_empty() {
            None
        } else {
            Some(range)
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
