// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! AppendOnlyData
//!
//! AppendOnlyData can be either published or unpublished and either sequenced or unsequenced.
//!
//! ## Published data
//!
//! Published data refers to the content that is published (made available) for everyone. For
//! example: websites, blogs, or research papers which anyone can fetch from the network and read
//! without requiring any permission. For such public content, it becomes important to retain a
//! history of changes. History is not be allowed to be tampered with and the published data remains
//! forever.
//!
//! The AppendOnly data type is pivotal for data perpetuity, because it ensures the published
//! versions are always available unlike the default behaviour of MutableData where the value can be
//! overwritten. This is central to prevent censorship of information.
//!
//! Data perpetuity is one of the fundamentals of the SAFE Network, which ensures the users of the
//! network shall be able to store published data in perpetuity.
//!
//! However, only the owners or permitted users shall be able to append the changes based on the
//! permission.
//!
//! ## Unpublished data
//!
//! Not all the data is desired to be made public. Personal data or organisations' data stored on
//! the network is not supposed to be accessed by everyone. Since the data is not published for
//! everyone, this is called unpublished data. Only the owner(s) shall be able to access and manage
//! the data based on the permission.
//!
//! The network should also be able to provide the flexibility for the users/developers to create
//! private data which can be versioned or mutable based on their needs.
//!
//! ### Private Data
//!
//! Users should be able to store private unpublished data on the network which is not accessible by
//! anyone else.
//!
//! ### Shared Data
//!
//! Users should be able to store unpublished data on the network and share it with a closed group.
//! The user should be able to give permissions like read, write, append based on the use case. For
//! example, a collaborative document which is meant to be worked on within a closed group.
//!
//! ## Sequenced and unsequenced data
//!
//! Similarly to MutableData, we further sub-divide AppendOnlyData into two distinct sub-categories,
//! sequenced and unsequenced. For sequenced AppendOnlyData the client must specify the next data
//! index while appending. For unsequenced AppendOnlyData the client does not have to pass the
//! index.

use crate::{utils, Error, PublicKey, Result, XorName};
use multibase::Decodable;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    hash::Hash,
    ops::Range,
};

/// Published sequenced AppendOnlyData.
pub type PubSeqAppendOnlyData = SeqAppendOnlyData<PubPermissions>;
/// Published unsequenced AppendOnlyData.
pub type PubUnseqAppendOnlyData = UnseqAppendOnlyData<PubPermissions>;
/// Unpublished sequenced AppendOnlyData.
pub type UnpubSeqAppendOnlyData = SeqAppendOnlyData<UnpubPermissions>;
/// Unpublished unsequenced AppendOnlyData.
pub type UnpubUnseqAppendOnlyData = UnseqAppendOnlyData<UnpubPermissions>;
/// List of entries.
pub type Entries = Vec<Entry>;

/// User that can access AppendOnlyData.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub enum User {
    /// Any user.
    Anyone,
    /// User identified by its public key.
    Key(PublicKey),
}

/// An action on AppendOnlyData.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Action {
    /// Read from the data.
    Read,
    /// Append to the data.
    Append,
    /// Manage permissions.
    ManagePermissions,
}

/// Index of some data.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Index {
    /// Absolute index.
    FromStart(u64),
    /// Relative index - start counting from the end.
    FromEnd(u64),
}

impl From<u64> for Index {
    fn from(index: u64) -> Self {
        Index::FromStart(index)
    }
}

/// Set of data, owners, permissions indices.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Indices {
    entries_index: u64,
    owners_index: u64,
    permissions_index: u64,
}

impl Indices {
    /// Constructs a new `Indices`.
    pub fn new(entries_index: u64, owners_index: u64, permissions_index: u64) -> Self {
        Indices {
            entries_index,
            owners_index,
            permissions_index,
        }
    }

    /// Returns the last entry index.
    pub fn entries_index(&self) -> u64 {
        self.entries_index
    }

    /// Returns the last owners index.
    pub fn owners_index(&self) -> u64 {
        self.owners_index
    }

    /// Returns the last permissions index.
    pub fn permissions_index(&self) -> u64 {
        self.permissions_index
    }
}

/// Set of unpublished permissions for a user.
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct UnpubPermissionSet {
    /// `true` if the user can read.
    read: bool,
    /// `true` if the user can append.
    append: bool,
    /// `true` if the user can manage permissions.
    manage_permissions: bool,
}

impl UnpubPermissionSet {
    /// Constructs a new unpublished permission set.
    pub fn new(read: bool, append: bool, manage_perms: bool) -> Self {
        UnpubPermissionSet {
            read,
            append,
            manage_permissions: manage_perms,
        }
    }

    /// Sets permissions.
    pub fn set_perms(&mut self, read: bool, append: bool, manage_perms: bool) {
        self.read = read;
        self.append = append;
        self.manage_permissions = manage_perms;
    }

    /// Returns `true` if `action` is allowed.
    pub fn is_allowed(self, action: Action) -> bool {
        match action {
            Action::Read => self.read,
            Action::Append => self.append,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

/// Set of published permissions for a user.
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PubPermissionSet {
    /// `Some(true)` if the user can append.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    append: Option<bool>,
    /// `Some(true)` if the user can manage permissions.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    manage_permissions: Option<bool>,
}

impl PubPermissionSet {
    /// Constructs a new published permission set.
    pub fn new(append: impl Into<Option<bool>>, manage_perms: impl Into<Option<bool>>) -> Self {
        PubPermissionSet {
            append: append.into(),
            manage_permissions: manage_perms.into(),
        }
    }

    /// Sets permissions.
    pub fn set_perms(
        &mut self,
        append: impl Into<Option<bool>>,
        manage_perms: impl Into<Option<bool>>,
    ) {
        self.append = append.into();
        self.manage_permissions = manage_perms.into();
    }

    /// Returns `Some(true)` if `action` is allowed and `Some(false)` if it's not permitted.
    /// `None` means that default permissions should be applied.
    pub fn is_allowed(self, action: Action) -> Option<bool> {
        match action {
            Action::Read => Some(true), // It's published data, so it's always allowed to read it.
            Action::Append => self.append,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

pub trait Perm {
    /// Returns true if `action` is allowed for the provided user.
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()>;
    /// Gets the last entry index.
    fn entries_index(&self) -> u64;
    /// Gets the last owner index.
    fn owners_index(&self) -> u64;
}

/// Unpublished permissions.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct UnpubPermissions {
    /// Map of users to their unpublished permission set.
    pub permissions: BTreeMap<PublicKey, UnpubPermissionSet>,
    /// The current index of the data when this permission change happened.
    pub entries_index: u64,
    /// The current index of the owners when this permission change happened.
    pub owners_index: u64,
}

impl UnpubPermissions {
    /// Gets the complete list of permissions.
    pub fn permissions(&self) -> &BTreeMap<PublicKey, UnpubPermissionSet> {
        &self.permissions
    }
}

impl Perm for UnpubPermissions {
    /// Returns `Ok(())` if `action` is allowed for the provided user and `Err(AccessDenied)` if
    /// this action is not permitted.
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()> {
        match self.permissions.get(&requester) {
            Some(perms) => {
                if perms.is_allowed(action) {
                    Ok(())
                } else {
                    Err(Error::AccessDenied)
                }
            }
            None => Err(Error::AccessDenied),
        }
    }

    /// Returns the last entry index.
    fn entries_index(&self) -> u64 {
        self.entries_index
    }

    /// Returns the last owners index.
    fn owners_index(&self) -> u64 {
        self.owners_index
    }
}

/// Published permissions.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PubPermissions {
    /// Map of users to their published permission set.
    pub permissions: BTreeMap<User, PubPermissionSet>,
    /// The current index of the data when this permission change happened.
    pub entries_index: u64,
    /// The current index of the owners when this permission change happened.
    pub owners_index: u64,
}

impl PubPermissions {
    /// Returns `Some(true)` if `action` is allowed for the provided user and `Some(false)` if it's
    /// not permitted. `None` means that default permissions should be applied.
    fn is_action_allowed_by_user(&self, user: &User, action: Action) -> Option<bool> {
        self.permissions
            .get(user)
            .and_then(|perms| perms.is_allowed(action))
    }

    /// Gets the complete list of permissions.
    pub fn permissions(&self) -> &BTreeMap<User, PubPermissionSet> {
        &self.permissions
    }
}

impl Perm for PubPermissions {
    /// Returns `Ok(())` if `action` is allowed for the provided user and `Err(AccessDenied)` if
    /// this action is not permitted.
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()> {
        match self
            .is_action_allowed_by_user(&User::Key(requester), action)
            .or_else(|| self.is_action_allowed_by_user(&User::Anyone, action))
        {
            Some(true) => Ok(()),
            Some(false) => Err(Error::AccessDenied),
            None => Err(Error::AccessDenied),
        }
    }

    /// Returns the last entry index.
    fn entries_index(&self) -> u64 {
        self.entries_index
    }

    /// Returns the last owners index.
    fn owners_index(&self) -> u64 {
        self.owners_index
    }
}

/// Wrapper type for permissions, which can be published or unpublished.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum Permissions {
    /// Published permissions.
    Pub(PubPermissions),
    /// Unpublished permissions.
    Unpub(UnpubPermissions),
}

impl From<UnpubPermissions> for Permissions {
    fn from(permissions: UnpubPermissions) -> Self {
        Permissions::Unpub(permissions)
    }
}

impl From<PubPermissions> for Permissions {
    fn from(permissions: PubPermissions) -> Self {
        Permissions::Pub(permissions)
    }
}

/// An owner could represent an individual user, or a group of users, depending on the `public_key`
/// type.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Owner {
    /// Public key.
    pub public_key: PublicKey,
    /// The current index of the data when this ownership change happened
    pub entries_index: u64,
    /// The current index of the permissions when this ownership change happened
    pub permissions_index: u64,
}

/// A key-value entry in AppendOnlyData.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default, Debug)]
pub struct Entry {
    /// Key.
    pub key: Vec<u8>,
    /// Contained data.
    pub value: Vec<u8>,
}

impl Entry {
    /// Constructs a new entry.
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Self {
        Self { key, value }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
struct AppendOnly<P: Perm> {
    address: Address,
    data: Entries,
    permissions: Vec<P>,
    /// This is the history of owners, with each entry representing an owner. Each single owner
    /// could represent an individual user, or a group of users, depending on the `PublicKey` type.
    owners: Vec<Owner>,
}

/// Common methods for all `AppendOnlyData` flavours.
pub trait AppendOnlyData<P> {
    /// Returns a value for the given key, if present.
    fn get(&self, key: &[u8]) -> Option<&Vec<u8>>;

    /// Returns the last entry, if present.
    fn last_entry(&self) -> Option<&Entry>;

    /// Gets a list of keys and values with the given indices.
    fn in_range(&self, start: Index, end: Index) -> Option<Entries>;

    /// Returns all entries.
    fn entries(&self) -> &Entries;

    /// Returns the address.
    fn address(&self) -> &Address;

    /// Returns the name.
    fn name(&self) -> &XorName;

    /// Returns the type tag.
    fn tag(&self) -> u64;

    /// Returns the last entry index.
    fn entries_index(&self) -> u64;

    /// Returns the last owners index.
    fn owners_index(&self) -> u64;

    /// Returns the last permissions index.
    fn permissions_index(&self) -> u64;

    /// Gets a complete list of permissions from the entry in the permissions list at the specified
    /// indices.
    fn permissions_range(&self, start: Index, end: Index) -> Option<&[P]>;

    /// Adds a new permissions entry.
    /// The `Perm` struct should contain valid indices.
    ///
    /// If the specified `permissions_index` does not match the last recorded permissions index + 1,
    /// an error will be returned.
    fn append_permissions(&mut self, permissions: P, permissions_index: u64) -> Result<()>;

    /// Fetches permissions at index.
    fn permissions(&self, perm_index: impl Into<Index>) -> Option<&P>;

    /// Fetches owner at index.
    fn owner(&self, owners_index: impl Into<Index>) -> Option<&Owner>;

    /// Fetches entry at index.
    fn entry(&self, entry_index: impl Into<Index>) -> Option<&Entry>;

    /// Gets a complete list of owners from the entry in the permissions list at the specified
    /// index.
    fn owners_range(&self, start: Index, end: Index) -> Option<&[Owner]>;

    /// Adds a new owner entry.
    ///
    /// If the specified `owners_index` does not match the last recorded owners index + 1, an error
    /// will be returned.
    fn append_owner(&mut self, owner: Owner, owners_index: u64) -> Result<()>;

    /// Checks if the requester is the last owner.
    ///
    /// Returns:
    /// `Ok(())` if the requester is the owner,
    /// `Err::InvalidOwners` if the last owner is invalid,
    /// `Err::AccessDenied` if the requester is not the owner.
    fn check_is_last_owner(&self, requester: PublicKey) -> Result<()>;
}

/// Common methods for published and unpublished unsequenced `AppendOnlyData`.
pub trait UnseqAppendOnly {
    /// Appends new entries.
    ///
    /// Returns an error if duplicate entries are present.
    fn append(&mut self, entries: Entries) -> Result<()>;
}

/// Common methods for published and unpublished sequenced `AppendOnlyData`.
pub trait SeqAppendOnly {
    /// Appends new entries.
    ///
    /// Returns an error if duplicate entries are present.
    /// If the specified `last_entries_index` does not match the last recorded entries index, an
    /// error will be returned.
    fn append(&mut self, entries: Entries, last_entries_index: u64) -> Result<()>;
}

macro_rules! impl_appendable_data {
    ($flavour:ident) => {
        #[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
        pub struct $flavour<P>
        where
            P: Perm + Hash + Clone,
        {
            inner: AppendOnly<P>,
        }

        impl<P> $flavour<P>
        where
            P: Perm + Hash + Clone,
        {
            /// Returns the shell of the data.
            pub fn shell(&self, entries_index: impl Into<Index>) -> Result<Self> {
                let entries_index =
                    to_absolute_index(entries_index.into(), self.entries_index() as usize)
                        .ok_or(Error::NoSuchEntry)? as u64;

                let permissions = self
                    .inner
                    .permissions
                    .iter()
                    .filter(|perm| perm.entries_index() <= entries_index)
                    .cloned()
                    .collect();

                let owners = self
                    .inner
                    .owners
                    .iter()
                    .filter(|owner| owner.entries_index <= entries_index)
                    .cloned()
                    .collect();

                Ok(Self {
                    inner: AppendOnly {
                        address: self.inner.address,
                        data: Vec::new(),
                        permissions,
                        owners,
                    },
                })
            }
        }

        impl<P> AppendOnlyData<P> for $flavour<P>
        where
            P: Perm + Hash + Clone,
        {
            /// Returns the address.
            fn address(&self) -> &Address {
                &self.inner.address
            }

            /// Returns the name.
            fn name(&self) -> &XorName {
                self.inner.address.name()
            }

            /// Returns the tag.
            fn tag(&self) -> u64 {
                self.inner.address.tag()
            }

            /// Returns the last entries index.
            fn entries_index(&self) -> u64 {
                self.inner.data.len() as u64
            }

            /// Returns the last owners index.
            fn owners_index(&self) -> u64 {
                self.inner.owners.len() as u64
            }

            /// Returns the last permissions index.
            fn permissions_index(&self) -> u64 {
                self.inner.permissions.len() as u64
            }

            /// Gets the entry at `key` if it exists.
            fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
                self.inner.data.iter().find_map(|entry| {
                    if entry.key.as_slice() == key {
                        Some(&entry.value)
                    } else {
                        None
                    }
                })
            }

            /// Gets the last entry.
            fn last_entry(&self) -> Option<&Entry> {
                self.inner.data.last()
            }

            /// Gets a complete list of permissions.
            fn permissions(&self, index: impl Into<Index>) -> Option<&P> {
                let index = to_absolute_index(index.into(), self.inner.permissions.len())?;
                self.inner.permissions.get(index)
            }

            /// Returns the owner's public key and the indices at the time it was added.
            fn owner(&self, owners_index: impl Into<Index>) -> Option<&Owner> {
                let index = to_absolute_index(owners_index.into(), self.inner.owners.len())?;
                self.inner.owners.get(index)
            }

            /// Returns the entry at the index.
            fn entry(&self, entry_index: impl Into<Index>) -> Option<&Entry> {
                let index = to_absolute_index(entry_index.into(), self.inner.data.len())?;
                self.inner.data.get(index)
            }

            fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
                let range = to_absolute_range(start, end, self.inner.data.len())?;
                Some(self.inner.data[range].to_vec())
            }

            /// Returns a complete list of entries.
            fn entries(&self) -> &Entries {
                &self.inner.data
            }

            fn permissions_range(&self, start: Index, end: Index) -> Option<&[P]> {
                let range = to_absolute_range(start, end, self.inner.permissions.len())?;
                Some(&self.inner.permissions[range])
            }

            fn owners_range(&self, start: Index, end: Index) -> Option<&[Owner]> {
                let range = to_absolute_range(start, end, self.inner.owners.len())?;
                Some(&self.inner.owners[range])
            }

            /// Adds a new permissions entry.
            /// The `Perm` struct should contain valid indices.
            ///
            /// If the specified `permissions_index` does not match the last recorded permissions
            /// index + 1, an error will be returned.
            fn append_permissions(&mut self, permissions: P, permissions_index: u64) -> Result<()> {
                if permissions.entries_index() != self.entries_index() {
                    return Err(Error::InvalidSuccessor(self.entries_index()));
                }
                if permissions.owners_index() != self.owners_index() {
                    return Err(Error::InvalidOwnersSuccessor(self.owners_index()));
                }
                if self.permissions_index() != permissions_index {
                    return Err(Error::InvalidSuccessor(self.permissions_index()));
                }
                self.inner.permissions.push(permissions);
                Ok(())
            }

            /// Adds a new owner entry.
            ///
            /// If the specified `owners_index` does not match the last recorded owners index + 1,
            /// an error will be returned.
            fn append_owner(&mut self, owner: Owner, owners_index: u64) -> Result<()> {
                if owner.entries_index != self.entries_index() {
                    return Err(Error::InvalidSuccessor(self.entries_index()));
                }
                if owner.permissions_index != self.permissions_index() {
                    return Err(Error::InvalidPermissionsSuccessor(self.permissions_index()));
                }
                if self.owners_index() != owners_index {
                    return Err(Error::InvalidSuccessor(self.owners_index()));
                }
                self.inner.owners.push(owner);
                Ok(())
            }

            /// Checks if the requester is the last owner.
            ///
            /// Returns:
            /// `Ok(())` if the requester is the owner,
            /// `Err::InvalidOwners` if the last owner is invalid,
            /// `Err::AccessDenied` if the requester is not the owner.
            fn check_is_last_owner(&self, requester: PublicKey) -> Result<()> {
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
    };
}

impl_appendable_data!(SeqAppendOnlyData);
impl_appendable_data!(UnseqAppendOnlyData);

impl SeqAppendOnlyData<PubPermissions> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            inner: AppendOnly {
                address: Address::PubSeq { name, tag },
                data: Vec::new(),
                permissions: Vec::new(),
                owners: Vec::new(),
            },
        }
    }
}

impl Debug for SeqAppendOnlyData<PubPermissions> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PubSeqAppendOnlyData {:?}", self.name())
    }
}

impl UnseqAppendOnlyData<PubPermissions> {
    /// Constructs a new published unsequenced AppendOnlyData.
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            inner: AppendOnly {
                address: Address::PubUnseq { name, tag },
                data: Vec::new(),
                permissions: Vec::new(),
                owners: Vec::new(),
            },
        }
    }
}

impl Debug for UnseqAppendOnlyData<PubPermissions> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PubUnseqAppendOnlyData {:?}", self.name())
    }
}

impl SeqAppendOnlyData<UnpubPermissions> {
    /// Constructs a new unpublished sequenced AppendOnlyData.
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            inner: AppendOnly {
                address: Address::UnpubSeq { name, tag },
                data: Vec::new(),
                permissions: Vec::new(),
                owners: Vec::new(),
            },
        }
    }
}

impl Debug for SeqAppendOnlyData<UnpubPermissions> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PubSeqAppendOnlyData {:?}", self.name())
    }
}

impl UnseqAppendOnlyData<UnpubPermissions> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            inner: AppendOnly {
                address: Address::UnpubUnseq { name, tag },
                data: Vec::new(),
                permissions: Vec::new(),
                owners: Vec::new(),
            },
        }
    }
}

impl Debug for UnseqAppendOnlyData<UnpubPermissions> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "UnpubUnseqAppendOnlyData {:?}", self.name())
    }
}

fn check_dup(data: &[Entry], entries: &mut Entries) -> Result<()> {
    let new: BTreeSet<&Vec<u8>> = entries.iter().map(|entry| &entry.key).collect();

    // If duplicate entries are present in the push.
    if new.len() < entries.len() {
        return Err(Error::DuplicateEntryKeys);
    }

    let existing: BTreeSet<&Vec<u8>> = data.iter().map(|entry| &entry.key).collect();
    if !existing.is_disjoint(&new) {
        let dup: Entries = entries
            .drain(..)
            .filter(|entry| existing.contains(&entry.key))
            .collect();
        return Err(Error::KeysExist(dup));
    }
    Ok(())
}

impl<P> SeqAppendOnly for SeqAppendOnlyData<P>
where
    P: Perm + Hash + Clone,
{
    fn append(&mut self, mut entries: Entries, last_entries_index: u64) -> Result<()> {
        check_dup(&self.inner.data, entries.as_mut())?;

        if last_entries_index != self.inner.data.len() as u64 {
            return Err(Error::InvalidSuccessor(self.inner.data.len() as u64));
        }

        self.inner.data.extend(entries);
        Ok(())
    }
}

impl<P> UnseqAppendOnly for UnseqAppendOnlyData<P>
where
    P: Perm + Hash + Clone,
{
    fn append(&mut self, mut entries: Entries) -> Result<()> {
        check_dup(&self.inner.data, entries.as_mut())?;

        self.inner.data.extend(entries);
        Ok(())
    }
}

macro_rules! check_perm {
    ($data: ident, $requester: ident, $action: ident) => {
        if $data
            .owner(Index::FromEnd(1))
            .ok_or(Error::InvalidOwners)?
            .public_key
            == $requester
        {
            Ok(())
        } else {
            $data
                .permissions(Index::FromEnd(1))
                .ok_or(Error::AccessDenied)?
                .is_action_allowed($requester, $action)
        }
    };
}

macro_rules! indices {
    ($data: ident) => {
        Ok(Indices::new(
            $data.entries_index(),
            $data.owners_index(),
            $data.permissions_index(),
        ))
    };
}

/// Kind of an AppendOnlyData.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    /// Published sequenced.
    PubSeq,
    /// Published unsequenced.
    PubUnseq,
    /// Unpublished sequenced.
    UnpubSeq,
    /// Unpublished unsequenced.
    UnpubUnseq,
}

impl Kind {
    /// Creates `Kind` from `published` and `sequenced` flags.
    pub fn from_flags(published: bool, sequenced: bool) -> Self {
        match (published, sequenced) {
            (true, true) => Kind::PubSeq,
            (true, false) => Kind::PubUnseq,
            (false, true) => Kind::UnpubSeq,
            (false, false) => Kind::UnpubUnseq,
        }
    }

    /// Returns true if published.
    pub fn is_pub(self) -> bool {
        self == Kind::PubSeq || self == Kind::PubUnseq
    }

    /// Returns true if unpublished.
    pub fn is_unpub(self) -> bool {
        !self.is_pub()
    }

    /// Returns true if sequenced.
    pub fn is_seq(self) -> bool {
        self == Kind::PubSeq || self == Kind::UnpubSeq
    }

    /// Returns true if unsequenced.
    pub fn is_unseq(self) -> bool {
        !self.is_seq()
    }
}

/// Address of an AppendOnlyData.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    /// Published sequenced namespace.
    PubSeq {
        /// Name.
        name: XorName,
        /// Tag.
        tag: u64,
    },
    /// Published unsequenced namespace.
    PubUnseq {
        /// Name.
        name: XorName,
        /// Tag.
        tag: u64,
    },
    /// Unpublished sequenced namespace.
    UnpubSeq {
        /// Name.
        name: XorName,
        /// Tag.
        tag: u64,
    },
    /// Unpublished unsequenced namespace.
    UnpubUnseq {
        /// Name.
        name: XorName,
        /// Tag.
        tag: u64,
    },
}

impl Address {
    /// Constructs a new `Address` given `kind`, `name`, and `tag`.
    pub fn from_kind(kind: Kind, name: XorName, tag: u64) -> Self {
        match kind {
            Kind::PubSeq => Address::PubSeq { name, tag },
            Kind::PubUnseq => Address::PubUnseq { name, tag },
            Kind::UnpubSeq => Address::UnpubSeq { name, tag },
            Kind::UnpubUnseq => Address::UnpubUnseq { name, tag },
        }
    }

    /// Returns the kind.
    pub fn kind(&self) -> Kind {
        match self {
            Address::PubSeq { .. } => Kind::PubSeq,
            Address::PubUnseq { .. } => Kind::PubUnseq,
            Address::UnpubSeq { .. } => Kind::UnpubSeq,
            Address::UnpubUnseq { .. } => Kind::UnpubUnseq,
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        match self {
            Address::PubSeq { ref name, .. }
            | Address::PubUnseq { ref name, .. }
            | Address::UnpubSeq { ref name, .. }
            | Address::UnpubUnseq { ref name, .. } => name,
        }
    }

    /// Returns the tag.
    pub fn tag(&self) -> u64 {
        match self {
            Address::PubSeq { tag, .. }
            | Address::PubUnseq { tag, .. }
            | Address::UnpubSeq { tag, .. }
            | Address::UnpubUnseq { tag, .. } => *tag,
        }
    }

    /// Returns true if published.
    pub fn is_pub(&self) -> bool {
        self.kind().is_pub()
    }

    /// Returns true if unpublished.
    pub fn is_unpub(&self) -> bool {
        self.kind().is_unpub()
    }

    /// Returns true if sequenced.
    pub fn is_seq(&self) -> bool {
        self.kind().is_seq()
    }

    /// Returns true if unsequenced.
    pub fn is_unseq(&self) -> bool {
        self.kind().is_unseq()
    }

    /// Returns the `Address` serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Creates from z-base-32 encoded string.
    pub fn decode_from_zbase32<I: Decodable>(encoded: I) -> Result<Self> {
        utils::decode(encoded)
    }
}

/// Object storing an AppendOnlyData variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    /// Published sequenced AppendOnlyData.
    PubSeq(PubSeqAppendOnlyData),
    /// Published unsequenced AppendOnlyData.
    PubUnseq(PubUnseqAppendOnlyData),
    /// Unpublished sequenced AppendOnlyData.
    UnpubSeq(UnpubSeqAppendOnlyData),
    /// Unpublished unsequenced AppendOnlyData.
    UnpubUnseq(UnpubUnseqAppendOnlyData),
}

impl Data {
    /// Returns the address.
    pub fn address(&self) -> &Address {
        match self {
            Data::PubSeq(data) => data.address(),
            Data::PubUnseq(data) => data.address(),
            Data::UnpubSeq(data) => data.address(),
            Data::UnpubUnseq(data) => data.address(),
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

    /// Returns `true` if published.
    pub fn is_pub(&self) -> bool {
        self.kind().is_pub()
    }

    /// Returns `true` if unpublished.
    pub fn is_unpub(&self) -> bool {
        self.kind().is_unpub()
    }

    /// Returns `true` if sequenced.
    pub fn is_seq(&self) -> bool {
        self.kind().is_seq()
    }

    /// Returns `true` if unsequenced.
    pub fn is_unseq(&self) -> bool {
        self.kind().is_unseq()
    }

    /// Checks permissions for given `action` for the provided user.
    ///
    /// Returns:
    /// `Ok(())` if the permissions are valid,
    /// `Err::InvalidOwners` if the last owner is invalid,
    /// `Err::AccessDenied` if the action is not allowed.
    pub fn check_permission(&self, action: Action, requester: PublicKey) -> Result<()> {
        match self {
            Data::PubSeq(data) => {
                if action == Action::Read {
                    return Ok(());
                }
                check_perm!(data, requester, action)
            }
            Data::PubUnseq(data) => {
                if action == Action::Read {
                    return Ok(());
                }
                check_perm!(data, requester, action)
            }
            Data::UnpubSeq(data) => check_perm!(data, requester, action),
            Data::UnpubUnseq(data) => check_perm!(data, requester, action),
        }
    }

    /// Returns the last entry index.
    pub fn entries_index(&self) -> u64 {
        match self {
            Data::PubSeq(data) => data.entries_index(),
            Data::PubUnseq(data) => data.entries_index(),
            Data::UnpubSeq(data) => data.entries_index(),
            Data::UnpubUnseq(data) => data.entries_index(),
        }
    }

    /// Returns the last permissions index.
    pub fn permissions_index(&self) -> u64 {
        match self {
            Data::PubSeq(data) => data.permissions_index(),
            Data::PubUnseq(data) => data.permissions_index(),
            Data::UnpubSeq(data) => data.permissions_index(),
            Data::UnpubUnseq(data) => data.permissions_index(),
        }
    }

    /// Returns the last owners index.
    pub fn owners_index(&self) -> u64 {
        match self {
            Data::PubSeq(data) => data.owners_index(),
            Data::PubUnseq(data) => data.owners_index(),
            Data::UnpubSeq(data) => data.owners_index(),
            Data::UnpubUnseq(data) => data.owners_index(),
        }
    }

    /// Fetches entry at index.
    pub fn entry(&self, entry_index: impl Into<Index>) -> Option<&Entry> {
        match self {
            Data::PubSeq(data) => data.entry(entry_index),
            Data::PubUnseq(data) => data.entry(entry_index),
            Data::UnpubSeq(data) => data.entry(entry_index),
            Data::UnpubUnseq(data) => data.entry(entry_index),
        }
    }

    /// Gets a list of keys and values with the given indices.
    pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
        match self {
            Data::PubSeq(data) => data.in_range(start, end),
            Data::PubUnseq(data) => data.in_range(start, end),
            Data::UnpubSeq(data) => data.in_range(start, end),
            Data::UnpubUnseq(data) => data.in_range(start, end),
        }
    }

    /// Returns a value for the given key, if present.
    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        match self {
            Data::PubSeq(data) => data.get(key),
            Data::PubUnseq(data) => data.get(key),
            Data::UnpubSeq(data) => data.get(key),
            Data::UnpubUnseq(data) => data.get(key),
        }
    }

    /// Returns a tuple containing the last entries index, last owners index, and last permissions
    /// indices.
    ///
    /// Always returns `Ok(Indices)`.
    pub fn indices(&self) -> Result<Indices> {
        match self {
            Data::PubSeq(data) => indices!(data),
            Data::PubUnseq(data) => indices!(data),
            Data::UnpubSeq(data) => indices!(data),
            Data::UnpubUnseq(data) => indices!(data),
        }
    }

    /// Returns the last entry, if present.
    pub fn last_entry(&self) -> Option<&Entry> {
        match self {
            Data::PubSeq(data) => data.last_entry(),
            Data::PubUnseq(data) => data.last_entry(),
            Data::UnpubSeq(data) => data.last_entry(),
            Data::UnpubUnseq(data) => data.last_entry(),
        }
    }

    /// Fetches owner at index.
    pub fn owner(&self, owners_index: impl Into<Index>) -> Option<&Owner> {
        match self {
            Data::PubSeq(data) => data.owner(owners_index),
            Data::PubUnseq(data) => data.owner(owners_index),
            Data::UnpubSeq(data) => data.owner(owners_index),
            Data::UnpubUnseq(data) => data.owner(owners_index),
        }
    }

    /// Gets a complete list of owners from the entry in the permissions list at the specified
    /// index.
    pub fn owners_range(&self, start: Index, end: Index) -> Option<&[Owner]> {
        match self {
            Data::PubSeq(data) => data.owners_range(start, end),
            Data::PubUnseq(data) => data.owners_range(start, end),
            Data::UnpubSeq(data) => data.owners_range(start, end),
            Data::UnpubUnseq(data) => data.owners_range(start, end),
        }
    }

    /// Appends new entries.
    ///
    /// Returns an error if duplicate entries are present or the data is not sequenced.
    pub fn append_seq(&mut self, entries: Entries, last_entries_index: u64) -> Result<()> {
        match self {
            Data::PubSeq(data) => data.append(entries, last_entries_index),
            Data::UnpubSeq(data) => data.append(entries, last_entries_index),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Appends new entries.
    ///
    /// Returns an error if duplicate entries are present or the data is not unsequenced.
    pub fn append_unseq(&mut self, entries: Entries) -> Result<()> {
        match self {
            Data::PubUnseq(data) => data.append(entries),
            Data::UnpubUnseq(data) => data.append(entries),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Adds a new published permissions entry for published data.
    /// The `Perm` struct should contain valid indices.
    ///
    /// If the specified `permissions_index` does not match the last recorded permissions index + 1
    /// or if this data is not published, an error will be returned.
    pub fn append_pub_permissions(
        &mut self,
        permissions: PubPermissions,
        permissions_index: u64,
    ) -> Result<()> {
        match self {
            Data::PubSeq(data) => data.append_permissions(permissions, permissions_index),
            Data::PubUnseq(data) => data.append_permissions(permissions, permissions_index),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Adds a new unpublished permissions entry for unpublished data.
    /// The `Perm` struct should contain valid indices.
    ///
    /// If the specified `permissions_index` does not match the last recorded permissions index + 1
    /// or if this data is not unpublished, an error will be returned.
    pub fn append_unpub_permissions(
        &mut self,
        permissions: UnpubPermissions,
        permissions_index: u64,
    ) -> Result<()> {
        match self {
            Data::UnpubSeq(data) => data.append_permissions(permissions, permissions_index),
            Data::UnpubUnseq(data) => data.append_permissions(permissions, permissions_index),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Adds a new owner entry.
    ///
    /// If the specified `owners_index` does not match the last recorded owners index + 1, an error
    /// will be returned.
    pub fn append_owner(&mut self, owner: Owner, owners_index: u64) -> Result<()> {
        match self {
            Data::PubSeq(data) => data.append_owner(owner, owners_index),
            Data::PubUnseq(data) => data.append_owner(owner, owners_index),
            Data::UnpubSeq(data) => data.append_owner(owner, owners_index),
            Data::UnpubUnseq(data) => data.append_owner(owner, owners_index),
        }
    }

    /// Checks if the requester is the last owner.
    ///
    /// Returns:
    /// `Ok(())` if the requester is the owner,
    /// `Err::InvalidOwners` if the last owner is invalid,
    /// `Err::AccessDenied` if the requester is not the owner.
    pub fn check_is_last_owner(&self, requester: PublicKey) -> Result<()> {
        match self {
            Data::PubSeq(data) => data.check_is_last_owner(requester),
            Data::PubUnseq(data) => data.check_is_last_owner(requester),
            Data::UnpubSeq(data) => data.check_is_last_owner(requester),
            Data::UnpubUnseq(data) => data.check_is_last_owner(requester),
        }
    }

    /// Returns published user permissions, if applicable.
    pub fn pub_user_permissions(
        &self,
        user: User,
        index: impl Into<Index>,
    ) -> Result<PubPermissionSet> {
        self.pub_permissions(index)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    /// Returns unpublished user permissions, if applicable.
    pub fn unpub_user_permissions(
        &self,
        user: PublicKey,
        index: impl Into<Index>,
    ) -> Result<UnpubPermissionSet> {
        self.unpub_permissions(index)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    /// Returns published permissions, if applicable.
    pub fn pub_permissions(&self, index: impl Into<Index>) -> Result<&PubPermissions> {
        let perms = match self {
            Data::PubSeq(data) => data.permissions(index),
            Data::PubUnseq(data) => data.permissions(index),
            _ => return Err(Error::NoSuchData),
        };
        perms.ok_or(Error::NoSuchEntry)
    }

    /// Returns unpublished permissions, if applicable.
    pub fn unpub_permissions(&self, index: impl Into<Index>) -> Result<&UnpubPermissions> {
        let perms = match self {
            Data::UnpubSeq(data) => data.permissions(index),
            Data::UnpubUnseq(data) => data.permissions(index),
            _ => return Err(Error::NoSuchData),
        };
        perms.ok_or(Error::NoSuchEntry)
    }

    /// Returns the shell of the data.
    pub fn shell(&self, index: impl Into<Index>) -> Result<Self> {
        match self {
            Data::PubSeq(adata) => adata.shell(index).map(Data::PubSeq),
            Data::PubUnseq(adata) => adata.shell(index).map(Data::PubUnseq),
            Data::UnpubSeq(adata) => adata.shell(index).map(Data::UnpubSeq),
            Data::UnpubUnseq(adata) => adata.shell(index).map(Data::UnpubUnseq),
        }
    }
}

impl From<PubSeqAppendOnlyData> for Data {
    fn from(data: PubSeqAppendOnlyData) -> Self {
        Data::PubSeq(data)
    }
}

impl From<PubUnseqAppendOnlyData> for Data {
    fn from(data: PubUnseqAppendOnlyData) -> Self {
        Data::PubUnseq(data)
    }
}

impl From<UnpubSeqAppendOnlyData> for Data {
    fn from(data: UnpubSeqAppendOnlyData) -> Self {
        Data::UnpubSeq(data)
    }
}

impl From<UnpubUnseqAppendOnlyData> for Data {
    fn from(data: UnpubUnseqAppendOnlyData) -> Self {
        Data::UnpubUnseq(data)
    }
}

/// Entries to append.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct AppendOperation {
    /// Address of an AppendOnlyData object on the network.
    pub address: Address,
    /// A list of entries to append.
    pub values: Entries,
}

fn to_absolute_index(index: Index, count: usize) -> Option<usize> {
    match index {
        Index::FromStart(index) if index as usize <= count => Some(index as usize),
        Index::FromStart(_) => None,
        Index::FromEnd(index) => count.checked_sub(index as usize),
    }
}

fn to_absolute_range(start: Index, end: Index, count: usize) -> Option<Range<usize>> {
    let start = to_absolute_index(start, count)?;
    let end = to_absolute_index(end, count)?;

    if start <= end {
        Some(start..end)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use threshold_crypto::SecretKey;
    use unwrap::{unwrap, unwrap_err};
    
    #[test]
    fn get_entry() {
        // pub, unseq
        let mut data = PubUnseqAppendOnlyData::new(rand::random(), 10);
        let entries = vec![
            Entry::new(b"key0".to_vec(), b"value0".to_vec()),
            Entry::new(b"key1".to_vec(), b"value1".to_vec()),
        ];
        unwrap!(data.append(entries));
        let data = Data::from(data);

        assert_eq!(
            data.entry(Index::FromStart(0)),
            Some(&Entry::new(b"key0".to_vec(), b"value0".to_vec()))
        );
        assert_eq!(
            data.entry(Index::FromStart(1)),
            Some(&Entry::new(b"key1".to_vec(), b"value1".to_vec()))
        );
        assert_eq!(data.entry(2), None);

        // pub, seq
        let mut data = PubSeqAppendOnlyData::new(rand::random(), 10);
        let entries = vec![
            Entry::new(b"key0".to_vec(), b"value0".to_vec()),
            Entry::new(b"key1".to_vec(), b"value1".to_vec()),
        ];
        unwrap!(data.append(entries, 0));
        let data = Data::from(data);

        assert_eq!(
            data.entry(Index::FromStart(0)),
            Some(&Entry::new(b"key0".to_vec(), b"value0".to_vec()))
        );
        assert_eq!(
            data.entry(Index::FromStart(1)),
            Some(&Entry::new(b"key1".to_vec(), b"value1".to_vec()))
        );
        assert_eq!(data.entry(2), None);

        // unpub, unseq
        let mut data = UnpubUnseqAppendOnlyData::new(rand::random(), 10);
        let entries = vec![
            Entry::new(b"key0".to_vec(), b"value0".to_vec()),
            Entry::new(b"key1".to_vec(), b"value1".to_vec()),
        ];
        unwrap!(data.append(entries));
        let data = Data::from(data);

        assert_eq!(
            data.entry(Index::FromStart(0)),
            Some(&Entry::new(b"key0".to_vec(), b"value0".to_vec()))
        );
        assert_eq!(
            data.entry(Index::FromStart(1)),
            Some(&Entry::new(b"key1".to_vec(), b"value1".to_vec()))
        );
        assert_eq!(data.entry(2), None);

        // unpub, seq
        let mut data = UnpubSeqAppendOnlyData::new(rand::random(), 10);
                let entries = vec![
            Entry::new(b"key0".to_vec(), b"value0".to_vec()),
            Entry::new(b"key1".to_vec(), b"value1".to_vec()),
        ];
        unwrap!(data.append(entries, 0));
        let data = Data::from(data);

        assert_eq!(
            data.entry(Index::FromStart(0)),
            Some(&Entry::new(b"key0".to_vec(), b"value0".to_vec()))
        );
        assert_eq!(
            data.entry(Index::FromStart(1)),
            Some(&Entry::new(b"key1".to_vec(), b"value1".to_vec()))
        );
        assert_eq!(data.entry(2), None);
    }

    #[test]
    fn append_permissions() {
        let mut data = SeqAppendOnlyData::<UnpubPermissions>::new(XorName([1; 32]), 10000);

        // Append the first permission set with correct indices - should pass.
        let res = data.append_permissions(
            UnpubPermissions {
                permissions: BTreeMap::new(),
                entries_index: 0,
                owners_index: 0,
            },
            0,
        );

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }

        // Verify that the permissions have been added.
        assert_eq!(
            unwrap!(data.permissions_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );

        // Append another permissions entry with incorrect indices - should fail.
        let res = data.append_permissions(
            UnpubPermissions {
                permissions: BTreeMap::new(),
                entries_index: 64,
                owners_index: 0,
            },
            1,
        );

        match res {
            Err(_) => (),
            Ok(()) => panic!("Unexpected Ok(()) result"),
        }

        // Verify that the number of permissions has not been changed.
        assert_eq!(
            unwrap!(data.permissions_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );
    }

    #[test]
    fn append_owners() {
        let owner_pk = gen_public_key();

        let mut data = SeqAppendOnlyData::<UnpubPermissions>::new(XorName([1; 32]), 10000);

        // Append the first owner with correct indices - should pass.
        let res = data.append_owner(
            Owner {
                public_key: owner_pk,
                entries_index: 0,
                permissions_index: 0,
            },
            0,
        );

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }

        // Verify that the owner has been added.
        assert_eq!(
            unwrap!(data.owners_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );

        // Append another owners entry with incorrect indices - should fail.
        let res = data.append_owner(
            Owner {
                public_key: owner_pk,
                entries_index: 64,
                permissions_index: 0,
            },
            1,
        );

        match res {
            Err(_) => (),
            Ok(()) => panic!("Unexpected Ok(()) result"),
        }

        // Verify that the number of owners has not been changed.
        assert_eq!(
            unwrap!(data.owners_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );
    }

    #[test]
    fn seq_append_entries() {
        let mut data = SeqAppendOnlyData::<PubPermissions>::new(XorName([1; 32]), 10000);
        unwrap!(data.append(vec![Entry::new(b"hello".to_vec(), b"world".to_vec())], 0));
    }

    #[test]
    fn assert_shell() {
        let owner_pk = gen_public_key();
        let owner_pk1 = gen_public_key();

        let mut data = SeqAppendOnlyData::<UnpubPermissions>::new(XorName([1; 32]), 10000);

        let _ = data.append_owner(
            Owner {
                public_key: owner_pk,
                entries_index: 0,
                permissions_index: 0,
            },
            0,
        );

        let _ = data.append_owner(
            Owner {
                public_key: owner_pk1,
                entries_index: 0,
                permissions_index: 0,
            },
            1,
        );

        assert_eq!(data.owners_index(), unwrap!(data.shell(0)).owners_index());
    }

    #[test]
    fn zbase32_encode_decode_adata_address() {
        let name = XorName(rand::random());
        let address = Address::UnpubSeq { name, tag: 15000 };
        let encoded = address.encode_to_zbase32();
        let decoded = unwrap!(self::Address::decode_from_zbase32(&encoded));
        assert_eq!(address, decoded);
    }

    #[test]
    fn append_unseq_data_test() {
        let mut data = UnpubUnseqAppendOnlyData::new(XorName(rand::random()), 10);

        // Assert that the entries are not appended because of duplicate keys.
        let entries = vec![
            Entry::new(b"KEY1".to_vec(), b"VALUE1".to_vec()),
            Entry::new(b"KEY2".to_vec(), b"VALUE2".to_vec()),
            Entry::new(b"KEY1".to_vec(), b"VALUE1".to_vec()),
        ];
        assert_eq!(Error::DuplicateEntryKeys, unwrap_err!(data.append(entries)));

        // Assert that the entries are appended because there are no duplicate keys.
        let entries1 = vec![
            Entry::new(b"KEY1".to_vec(), b"VALUE1".to_vec()),
            Entry::new(b"KEY2".to_vec(), b"VALUE2".to_vec()),
        ];

        unwrap!(data.append(entries1));

        // Assert that entries are not appended because they duplicate some keys appended previously.
        let entries2 = vec![Entry::new(b"KEY2".to_vec(), b"VALUE2".to_vec())];
        assert_eq!(
            Error::KeysExist(entries2.clone()),
            unwrap_err!(data.append(entries2))
        );

        // Assert that no duplicate keys are present and the append operation is successful.
        let entries3 = vec![Entry::new(b"KEY3".to_vec(), b"VALUE3".to_vec())];
        unwrap!(data.append(entries3));
    }

    #[test]
    fn append_seq_data_test() {
        let mut data = UnpubSeqAppendOnlyData::new(XorName(rand::random()), 10);

        // Assert that the entries are not appended because of duplicate keys.
        let entries = vec![
            Entry::new(b"KEY1".to_vec(), b"VALUE1".to_vec()),
            Entry::new(b"KEY2".to_vec(), b"VALUE2".to_vec()),
            Entry::new(b"KEY1".to_vec(), b"VALUE1".to_vec()),
        ];
        assert_eq!(
            Error::DuplicateEntryKeys,
            unwrap_err!(data.append(entries, 0))
        );

        // Assert that the entries are appended because there are no duplicate keys.
        let entries1 = vec![
            Entry::new(b"KEY1".to_vec(), b"VALUE1".to_vec()),
            Entry::new(b"KEY2".to_vec(), b"VALUE2".to_vec()),
        ];
        unwrap!(data.append(entries1, 0));

        // Assert that entries are not appended because they duplicate some keys appended previously.
        let entries2 = vec![Entry::new(b"KEY2".to_vec(), b"VALUE2".to_vec())];
        assert_eq!(
            Error::KeysExist(entries2.clone()),
            unwrap_err!(data.append(entries2, 2))
        );

        // Assert that no duplicate keys are present and the append operation is successful.
        let entries3 = vec![Entry::new(b"KEY3".to_vec(), b"VALUE3".to_vec())];
        unwrap!(data.append(entries3, 2));
    }

    #[test]
    fn in_range() {
        let mut data = PubSeqAppendOnlyData::new(rand::random(), 10);
        let entries = vec![
            Entry::new(b"key0".to_vec(), b"value0".to_vec()),
            Entry::new(b"key1".to_vec(), b"value1".to_vec()),
        ];
        unwrap!(data.append(entries, 0));

        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromStart(0)),
            Some(vec![])
        );
        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromStart(1)),
            Some(vec![Entry::new(b"key0".to_vec(), b"value0".to_vec())])
        );
        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromStart(2)),
            Some(vec![
                Entry::new(b"key0".to_vec(), b"value0".to_vec()),
                Entry::new(b"key1".to_vec(), b"value1".to_vec())
            ])
        );

        assert_eq!(
            data.in_range(Index::FromEnd(2), Index::FromEnd(1)),
            Some(vec![Entry::new(b"key0".to_vec(), b"value0".to_vec()),])
        );
        assert_eq!(
            data.in_range(Index::FromEnd(2), Index::FromEnd(0)),
            Some(vec![
                Entry::new(b"key0".to_vec(), b"value0".to_vec()),
                Entry::new(b"key1".to_vec(), b"value1".to_vec())
            ])
        );

        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromEnd(0)),
            Some(vec![
                Entry::new(b"key0".to_vec(), b"value0".to_vec()),
                Entry::new(b"key1".to_vec(), b"value1".to_vec())
            ])
        );

        // start > end
        assert_eq!(
            data.in_range(Index::FromStart(1), Index::FromStart(0)),
            None
        );
        assert_eq!(data.in_range(Index::FromEnd(1), Index::FromEnd(2)), None);

        // overflow
        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromStart(3)),
            None
        );
        assert_eq!(data.in_range(Index::FromEnd(3), Index::FromEnd(0)), None);
    }

    #[test]
    fn get_permissions() {
        let public_key = gen_public_key();
        let invalid_public_key = gen_public_key();

        let mut pub_perms = PubPermissions {
            permissions: BTreeMap::new(),
            entries_index: 0,
            owners_index: 0,
        };
        let _ = pub_perms
            .permissions
            .insert(User::Key(public_key), PubPermissionSet::new(false, false));

        let mut unpub_perms = UnpubPermissions {
            permissions: BTreeMap::new(),
            entries_index: 0,
            owners_index: 0,
        };
        let _ = unpub_perms
            .permissions
            .insert(public_key, UnpubPermissionSet::new(false, false, false));

        // pub, unseq
        let mut data = PubUnseqAppendOnlyData::new(rand::random(), 20);
        unwrap!(data.append_permissions(pub_perms.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.pub_permissions(0), Ok(&pub_perms));
        assert_eq!(data.unpub_permissions(0), Err(Error::NoSuchData));

        assert_eq!(
            data.pub_user_permissions(User::Key(public_key), 0),
            Ok(PubPermissionSet::new(false, false))
        );
        assert_eq!(
            data.unpub_user_permissions(public_key, 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.pub_user_permissions(User::Key(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // pub, seq
        let mut data = PubSeqAppendOnlyData::new(rand::random(), 20);
        unwrap!(data.append_permissions(pub_perms.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.pub_permissions(0), Ok(&pub_perms));
        assert_eq!(data.unpub_permissions(0), Err(Error::NoSuchData));

        assert_eq!(
            data.pub_user_permissions(User::Key(public_key), 0),
            Ok(PubPermissionSet::new(false, false))
        );
        assert_eq!(
            data.unpub_user_permissions(public_key, 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.pub_user_permissions(User::Key(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // unpub, unseq
        let mut data = UnpubUnseqAppendOnlyData::new(rand::random(), 20);
        unwrap!(data.append_permissions(unpub_perms.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.unpub_permissions(0), Ok(&unpub_perms));
        assert_eq!(data.pub_permissions(0), Err(Error::NoSuchData));

        assert_eq!(
            data.unpub_user_permissions(public_key, 0),
            Ok(UnpubPermissionSet::new(false, false, false))
        );
        assert_eq!(
            data.pub_user_permissions(User::Key(public_key), 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.unpub_user_permissions(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );

        // unpub, seq
        let mut data = UnpubSeqAppendOnlyData::new(rand::random(), 20);
        unwrap!(data.append_permissions(unpub_perms.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.unpub_permissions(0), Ok(&unpub_perms));
        assert_eq!(data.pub_permissions(0), Err(Error::NoSuchData));

        assert_eq!(
            data.unpub_user_permissions(public_key, 0),
            Ok(UnpubPermissionSet::new(false, false, false))
        );
        assert_eq!(
            data.pub_user_permissions(User::Key(public_key), 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.unpub_user_permissions(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );
    }

    fn gen_public_key() -> PublicKey {
        PublicKey::Bls(SecretKey::random().public_key())
    }

    #[test]
    fn check_pub_permission() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut inner = SeqAppendOnlyData::<PubPermissions>::new(XorName([1; 32]), 100);

        // no owner
        let data = Data::from(inner.clone());
        assert_eq!(
            data.check_permission(Action::Append, public_key_0),
            Err(Error::InvalidOwners)
        );
        // data is published - read always allowed
        assert_eq!(data.check_permission(Action::Read, public_key_0), Ok(()));

        // no permissions
        unwrap!(inner.append_owner(
            Owner {
                public_key: public_key_0,
                entries_index: 0,
                permissions_index: 0,
            },
            0,
        ));
        let data = Data::from(inner.clone());

        assert_eq!(data.check_permission(Action::Append, public_key_0), Ok(()));
        assert_eq!(
            data.check_permission(Action::Append, public_key_1),
            Err(Error::AccessDenied)
        );
        // data is published - read always allowed
        assert_eq!(data.check_permission(Action::Read, public_key_0), Ok(()));
        assert_eq!(data.check_permission(Action::Read, public_key_1), Ok(()));

        // with permissions
        let mut permissions = PubPermissions {
            permissions: BTreeMap::new(),
            entries_index: 0,
            owners_index: 1,
        };
        let _ = permissions
            .permissions
            .insert(User::Anyone, PubPermissionSet::new(true, false));
        let _ = permissions
            .permissions
            .insert(User::Key(public_key_1), PubPermissionSet::new(None, true));
        unwrap!(inner.append_permissions(permissions, 0));
        let data = Data::from(inner);

        // existing key fallback
        assert_eq!(data.check_permission(Action::Append, public_key_1), Ok(()));
        // existing key override
        assert_eq!(
            data.check_permission(Action::ManagePermissions, public_key_1),
            Ok(())
        );
        // non-existing keys are handled by `Anyone`
        assert_eq!(data.check_permission(Action::Append, public_key_2), Ok(()));
        assert_eq!(
            data.check_permission(Action::ManagePermissions, public_key_2),
            Err(Error::AccessDenied)
        );
        // data is published - read always allowed
        assert_eq!(data.check_permission(Action::Read, public_key_0), Ok(()));
        assert_eq!(data.check_permission(Action::Read, public_key_1), Ok(()));
        assert_eq!(data.check_permission(Action::Read, public_key_2), Ok(()));
    }

    #[test]
    fn check_unpub_permission() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut inner = SeqAppendOnlyData::<UnpubPermissions>::new(XorName([1; 32]), 100);

        // no owner
        let data = Data::from(inner.clone());
        assert_eq!(
            data.check_permission(Action::Read, public_key_0),
            Err(Error::InvalidOwners)
        );

        // no permissions
        unwrap!(inner.append_owner(
            Owner {
                public_key: public_key_0,
                entries_index: 0,
                permissions_index: 0,
            },
            0,
        ));
        let data = Data::from(inner.clone());

        assert_eq!(data.check_permission(Action::Read, public_key_0), Ok(()));
        assert_eq!(
            data.check_permission(Action::Read, public_key_1),
            Err(Error::AccessDenied)
        );

        // with permissions
        let mut permissions = UnpubPermissions {
            permissions: BTreeMap::new(),
            entries_index: 0,
            owners_index: 1,
        };
        let _ = permissions
            .permissions
            .insert(public_key_1, UnpubPermissionSet::new(true, true, false));
        unwrap!(inner.append_permissions(permissions, 0));
        let data = Data::from(inner);

        // existing key
        assert_eq!(data.check_permission(Action::Read, public_key_1), Ok(()));
        assert_eq!(data.check_permission(Action::Append, public_key_1), Ok(()));
        assert_eq!(
            data.check_permission(Action::ManagePermissions, public_key_1),
            Err(Error::AccessDenied)
        );

        // non-existing key
        assert_eq!(
            data.check_permission(Action::Read, public_key_2),
            Err(Error::AccessDenied)
        );
        assert_eq!(
            data.check_permission(Action::Append, public_key_2),
            Err(Error::AccessDenied)
        );
        assert_eq!(
            data.check_permission(Action::ManagePermissions, public_key_2),
            Err(Error::AccessDenied)
        );
    }
}
