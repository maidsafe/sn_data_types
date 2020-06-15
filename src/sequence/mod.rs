// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod metadata;
mod seq_crdt;

use crate::{Error, PublicKey, Result, XorName};
pub use metadata::{
    Action, Address, Entries, Entry, Index, Indices, Kind, Owner, Perm, Permissions,
    PrivPermissions, PrivUserPermissions, PubPermissions, PubUserPermissions, User,
    UserPermissions,
};
use seq_crdt::{Op, SequenceCrdt};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
    hash::Hash,
};

// Type of data used for the 'Actor' in CRDT vector clocks
type ActorType = PublicKey;

/// Public Sequence.
pub type PubSeqData = SequenceCrdt<ActorType, PubPermissions>;
/// Private Sequence.
pub type PrivSeqData = SequenceCrdt<ActorType, PrivPermissions>;

impl Debug for PubSeqData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PubSequence {:?}", self.address().name())
    }
}

impl Debug for PrivSeqData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivSequence {:?}", self.address().name())
    }
}

/// Object storing a Sequence variant.
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    /// Public Sequence Data.
    Public(PubSeqData),
    /// Private Sequence Data.
    Private(PrivSeqData),
}

impl Data {
    /// Constructs a new Public Sequence Data.
    pub fn new_pub(actor: PublicKey, name: XorName, tag: u64) -> Self {
        Self::Public(PubSeqData::new(actor, name, tag))
    }

    /// Constructs a new Private Sequence Data.
    pub fn new_priv(actor: PublicKey, name: XorName, tag: u64) -> Self {
        Self::Private(PrivSeqData::new(actor, name, tag))
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
    pub fn is_priv(&self) -> bool {
        self.kind().is_priv()
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
                $data.check_is_last_owner($requester).or_else(|_| {
                    $data
                        .permissions(Index::FromEnd(1))
                        .ok_or(Error::AccessDenied)?
                        .is_action_allowed($requester, $action)
                })
            };
        }

        match self {
            Data::Public(data) => {
                if action == Action::Read {
                    return Ok(());
                }
                check_perm!(data, requester, action)
            }
            Data::Private(data) => check_perm!(data, requester, action),
        }
    }

    /// Returns the last entry index.
    pub fn entries_index(&self) -> u64 {
        match self {
            Data::Public(data) => data.entries_index(),
            Data::Private(data) => data.entries_index(),
        }
    }

    /// Returns the last permissions index.
    pub fn permissions_index(&self) -> u64 {
        match self {
            Data::Public(data) => data.permissions_index(),
            Data::Private(data) => data.permissions_index(),
        }
    }

    /// Returns the last owners index.
    pub fn owners_index(&self) -> u64 {
        match self {
            Data::Public(data) => data.owners_index(),
            Data::Private(data) => data.owners_index(),
        }
    }

    /// Gets a list of keys and values with the given indices.
    pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
        match self {
            Data::Public(data) => data.in_range(start, end),
            Data::Private(data) => data.in_range(start, end),
        }
    }

    /// Returns a value at 'index', if present.
    pub fn get(&self, index: Index) -> Option<&Vec<u8>> {
        match self {
            Data::Public(data) => data.get(index),
            Data::Private(data) => data.get(index),
        }
    }

    /// Returns the last entry, if present.
    pub fn last_entry(&self) -> Option<&Entry> {
        match self {
            Data::Public(data) => data.last_entry(),
            Data::Private(data) => data.last_entry(),
        }
    }

    /// Fetches owner at index.
    pub fn owner(&self, owners_index: impl Into<Index>) -> Option<&Owner> {
        match self {
            Data::Public(data) => data.owner(owners_index),
            Data::Private(data) => data.owner(owners_index),
        }
    }

    /// Appends new entry.
    pub fn append(&mut self, entry: Entry) -> MutationOperation<Entry> {
        let crdt_op = match self {
            Data::Public(data) => data.append(entry),
            Data::Private(data) => data.append(entry),
        };

        MutationOperation {
            address: *self.address(),
            crdt_op,
        }
    }

    /// Apply CRDT operation.
    pub fn apply_crdt_op(&mut self, op: Op<Entry, ActorType>) {
        match self {
            Data::Public(data) => data.apply_crdt_op(op),
            Data::Private(data) => data.apply_crdt_op(op),
        };
    }

    /// Adds a new permissions entry for Public Sequence.
    pub fn set_pub_permissions(
        &mut self,
        permissions: BTreeMap<User, PubUserPermissions>,
    ) -> Result<MutationOperation<PubPermissions>> {
        let address = *self.address();
        match self {
            Data::Public(data) => {
                let crdt_op = data.append_permissions(PubPermissions {
                    entries_index: data.entries_index(),
                    owners_index: data.owners_index(),
                    permissions,
                });
                Ok(MutationOperation { address, crdt_op })
            }
            Data::Private(_) => Err(Error::InvalidOperation),
        }
    }

    /// Adds a new permissions entry for Private Sequence.
    pub fn set_priv_permissions(
        &mut self,
        permissions: BTreeMap<PublicKey, PrivUserPermissions>,
    ) -> Result<MutationOperation<PrivPermissions>> {
        let address = *self.address();
        match self {
            Data::Private(data) => {
                let crdt_op = data.append_permissions(PrivPermissions {
                    entries_index: data.entries_index(),
                    owners_index: data.owners_index(),
                    permissions,
                });
                Ok(MutationOperation { address, crdt_op })
            }
            Data::Public(_) => Err(Error::InvalidOperation),
        }
    }

    /// Apply Public Permissions CRDT operation.
    pub fn apply_crdt_pub_perms_op(&mut self, op: Op<PubPermissions, ActorType>) -> Result<()> {
        match (self, &op) {
            (Data::Public(data), Op::Insert { .. }) => {
                data.apply_crdt_perms_op(op);
                Ok(())
            }
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Apply Private Permissions CRDT operation.
    pub fn apply_crdt_priv_perms_op(&mut self, op: Op<PrivPermissions, ActorType>) -> Result<()> {
        match self {
            Data::Private(data) => {
                data.apply_crdt_perms_op(op);
                Ok(())
            }
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Adds a new owner entry.
    pub fn set_owner(&mut self, owner: PublicKey) -> MutationOperation<Owner> {
        let address = *self.address();
        let crdt_op = match self {
            Data::Public(data) => data.append_owner(owner),
            Data::Private(data) => data.append_owner(owner),
        };

        MutationOperation { address, crdt_op }
    }

    /// Apply Owner CRDT operation.
    pub fn apply_crdt_owner_op(&mut self, op: Op<Owner, ActorType>) {
        match self {
            Data::Public(data) => data.apply_crdt_owner_op(op),
            Data::Private(data) => data.apply_crdt_owner_op(op),
        };
    }

    /// Checks if the requester is the last owner.
    ///
    /// Returns:
    /// `Ok(())` if the requester is the owner,
    /// `Err::InvalidOwners` if the last owner is invalid,
    /// `Err::AccessDenied` if the requester is not the owner.
    pub fn check_is_last_owner(&self, requester: PublicKey) -> Result<()> {
        match self {
            Data::Public(data) => data.check_is_last_owner(requester),
            Data::Private(data) => data.check_is_last_owner(requester),
        }
    }

    /// Returns user permissions, if applicable.
    pub fn user_permissions(&self, user: User, index: impl Into<Index>) -> Result<UserPermissions> {
        let user_perm = match self {
            Data::Public(data) => data
                .permissions(index)
                .ok_or(Error::NoSuchEntry)?
                .user_permissions(user)
                .ok_or(Error::NoSuchEntry)?,
            Data::Private(data) => data
                .permissions(index)
                .ok_or(Error::NoSuchEntry)?
                .user_permissions(user)
                .ok_or(Error::NoSuchEntry)?,
        };

        Ok(user_perm)
    }

    /// Returns public permissions, if applicable.
    pub fn pub_permissions(&self, index: impl Into<Index>) -> Result<&PubPermissions> {
        let perms = match self {
            Data::Public(data) => data.permissions(index),
            Data::Private(_) => return Err(Error::InvalidOperation),
        };
        perms.ok_or(Error::NoSuchEntry)
    }

    /// Returns private permissions, if applicable.
    pub fn priv_permissions(&self, index: impl Into<Index>) -> Result<&PrivPermissions> {
        let perms = match self {
            Data::Private(data) => data.permissions(index),
            Data::Public(_) => return Err(Error::InvalidOperation),
        };
        perms.ok_or(Error::NoSuchEntry)
    }
}

impl From<PubSeqData> for Data {
    fn from(data: PubSeqData) -> Self {
        Data::Public(data)
    }
}

impl From<PrivSeqData> for Data {
    fn from(data: PrivSeqData) -> Self {
        Data::Private(data)
    }
}

/// Mutation operation to apply to Sequence.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub struct MutationOperation<T> {
    /// Address of a Sequence object on the network.
    pub address: Address,
    /// The operation to apply.
    pub crdt_op: Op<T, ActorType>,
}
