// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{utils, Error, PublicKey, Result, XorName};
use multibase::Decodable;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    hash::Hash,
    ops::Range,
};

pub type PubSeqAppendOnlyData = SeqAppendOnlyData<PubPermissions>;
pub type PubUnseqAppendOnlyData = UnseqAppendOnlyData<PubPermissions>;
pub type UnpubSeqAppendOnlyData = SeqAppendOnlyData<UnpubPermissions>;
pub type UnpubUnseqAppendOnlyData = UnseqAppendOnlyData<UnpubPermissions>;
pub type Entries = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub enum User {
    Anyone,
    Key(PublicKey),
}

#[derive(Clone, Copy)]
pub enum Action {
    Read,
    Append,
    ManagePermissions,
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Index {
    FromStart(u64), // Absolute index
    FromEnd(u64),   // Relative index - start counting from the end
}

// Set of data, owners, permissions Indices.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Indices {
    data_index: u64,
    owners_index: u64,
    permissions_index: u64,
}

impl Indices {
    pub fn new(data_index: u64, owners_index: u64, permissions_index: u64) -> Self {
        Indices {
            data_index,
            owners_index,
            permissions_index,
        }
    }

    pub fn data_index(&self) -> u64 {
        self.data_index
    }

    pub fn owners_index(&self) -> u64 {
        self.owners_index
    }

    pub fn permissions_index(&self) -> u64 {
        self.permissions_index
    }
}

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct UnpubPermissionSet {
    read: bool,
    append: bool,
    manage_permissions: bool,
}

impl UnpubPermissionSet {
    pub fn new(read: bool, append: bool, manage_perms: bool) -> Self {
        UnpubPermissionSet {
            read,
            append,
            manage_permissions: manage_perms,
        }
    }

    pub fn set_perms(&mut self, read: bool, append: bool, manage_perms: bool) {
        self.read = read;
        self.append = append;
        self.manage_permissions = manage_perms;
    }

    pub fn is_allowed(self, action: Action) -> bool {
        match action {
            Action::Read => self.read,
            Action::Append => self.append,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PubPermissionSet {
    append: Option<bool>,
    manage_permissions: Option<bool>,
}

impl PubPermissionSet {
    pub fn new(append: impl Into<Option<bool>>, manage_perms: impl Into<Option<bool>>) -> Self {
        PubPermissionSet {
            append: append.into(),
            manage_permissions: manage_perms.into(),
        }
    }

    pub fn set_perms(
        &mut self,
        append: impl Into<Option<bool>>,
        manage_perms: impl Into<Option<bool>>,
    ) {
        self.append = append.into();
        self.manage_permissions = manage_perms.into();
    }

    pub fn is_allowed(self, action: Action) -> Option<bool> {
        match action {
            Action::Read => Some(true), // It's published data, so it's always allowed to read it.
            Action::Append => self.append,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

pub trait Permissions {
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()>;
    fn data_index(&self) -> u64;
    fn owner_entry_index(&self) -> u64;
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct UnpubPermissions {
    pub permissions: BTreeMap<PublicKey, UnpubPermissionSet>,
    /// The current index of the data when this permission change happened
    pub data_index: u64,
    /// The current index of the owners when this permission change happened
    pub owner_entry_index: u64,
}

impl UnpubPermissions {
    pub fn permissions(&self) -> BTreeMap<PublicKey, UnpubPermissionSet> {
        self.permissions.clone()
    }
}

impl Permissions for UnpubPermissions {
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()> {
        match self.permissions.get(&requester) {
            Some(perms) => {
                if perms.is_allowed(action) {
                    Ok(())
                } else {
                    Err(Error::AccessDenied)
                }
            }
            None => Err(Error::NoSuchEntry),
        }
    }

    fn data_index(&self) -> u64 {
        self.data_index
    }

    fn owner_entry_index(&self) -> u64 {
        self.owner_entry_index
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PubPermissions {
    pub permissions: BTreeMap<User, PubPermissionSet>,
    /// The current index of the data when this permission change happened
    pub data_index: u64,
    /// The current index of the owners when this permission change happened
    pub owner_entry_index: u64,
}

impl PubPermissions {
    fn check_anyone_permissions(&self, action: Action) -> bool {
        match self.permissions.get(&User::Anyone) {
            None => false,
            Some(perms) => perms.is_allowed(action).unwrap_or(false),
        }
    }

    pub fn permissions(&self) -> &BTreeMap<User, PubPermissionSet> {
        &self.permissions
    }
}

impl Permissions for PubPermissions {
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()> {
        match self.permissions.get(&User::Key(requester)) {
            Some(perms) => {
                if perms
                    .is_allowed(action)
                    .unwrap_or_else(|| self.check_anyone_permissions(action))
                {
                    Ok(())
                } else {
                    Err(Error::AccessDenied)
                }
            }
            None => Err(Error::NoSuchEntry),
        }
    }

    fn data_index(&self) -> u64 {
        self.data_index
    }

    fn owner_entry_index(&self) -> u64 {
        self.owner_entry_index
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Owner {
    pub public_key: PublicKey,
    /// The current index of the data when this ownership change happened
    pub data_index: u64,
    /// The current index of the permissions when this ownership change happened
    pub permissions_index: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
struct AppendOnly<P: Permissions> {
    address: Address,
    data: Entries,
    permissions: Vec<P>,
    // This is the history of owners, with each entry representing an owner.  Each single owner
    // could represent an individual user, or a group of users, depending on the `PublicKey` type.
    owners: Vec<Owner>,
}

/// Common methods for all `AppendOnlyData` flavours.
pub trait AppendOnlyData<P> {
    // /// Get a list of permissions for the provided user from the last entry in the permissions list.
    // fn user_permissions(&self, user: &User) -> Result<&PubPermissionSet>;

    /// Return a value for the given key (if it is present).
    fn get(&self, key: &[u8]) -> Option<&Vec<u8>>;

    /// Return the last entry in the Data (if it is present).
    fn last_entry(&self) -> Option<(Vec<u8>, Vec<u8>)>;

    /// Get a list of keys and values with the given indices.
    fn in_range(&self, start: Index, end: Index) -> Option<Entries>;

    /// Return all entries.
    fn entries(&self) -> &Entries;

    /// Return the address of this AppendOnlyData.
    fn address(&self) -> &Address;

    /// Return the name of this AppendOnlyData.
    fn name(&self) -> &XorName;

    /// Return the type tag of this AppendOnlyData.
    fn tag(&self) -> u64;

    /// Return the last entry index.
    fn entry_index(&self) -> u64;

    /// Return the last owners index.
    fn owners_index(&self) -> u64;

    /// Return the last permissions index.
    fn permissions_index(&self) -> u64;

    /// Get a complete list of permissions from the entry in the permissions list at the specified
    /// index.
    fn permissions_range(&self, start: Index, end: Index) -> Option<&[P]>;

    /// Add a new permissions entry.
    /// The `Permissions` struct should contain valid indices.
    fn append_permissions(&mut self, permissions: P, permissions_idx: u64) -> Result<()>;

    /// Fetch perms at index.
    fn fetch_permissions_at_index(&self, perm_index: u64) -> Option<&P>;

    /// Fetch owners at index.
    fn fetch_owner_at_index(&self, owners_index: u64) -> Option<&Owner>;

    /// Get a complete list of owners from the entry in the permissions list at the specified index.
    fn owners_range(&self, start: Index, end: Index) -> Option<&[Owner]>;

    /// Add a new owner entry.
    fn append_owner(&mut self, owner: Owner, owners_idx: u64) -> Result<()>;
}

/// Common methods for published and unpublished unsequenced `AppendOnlyData`.
pub trait UnseqAppendOnly {
    /// Append new entries.
    fn append(&mut self, entries: Entries) -> Result<()>;
}

/// Common methods for published and unpublished sequenced `AppendOnlyData`.
pub trait SeqAppendOnly {
    /// Append new entries.
    ///
    /// If the specified `last_entries_index` does not match the last recorded entries index, an
    /// error will be returned.
    fn append(&mut self, entries: Entries, last_entries_index: u64) -> Result<()>;
}

macro_rules! impl_appendable_data {
    ($flavour:ident) => {
        #[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
        pub struct $flavour<P>
        where
            P: Permissions + Hash + Clone,
        {
            inner: AppendOnly<P>,
        }

        impl<P> $flavour<P>
        where
            P: Permissions + Hash + Clone,
        {
            pub fn shell(&self, index: u64) -> Result<Self> {
                if index > self.entry_index() {
                    return Err(Error::NoSuchEntry);
                }

                let permissions = self
                    .inner
                    .permissions
                    .iter()
                    .filter(|perm| perm.data_index() <= index)
                    .cloned()
                    .collect();

                let owners = self
                    .inner
                    .owners
                    .iter()
                    .filter(|owner| owner.data_index <= index)
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
            P: Permissions + Hash + Clone,
        {
            fn address(&self) -> &Address {
                &self.inner.address
            }

            fn name(&self) -> &XorName {
                self.inner.address.name()
            }

            fn tag(&self) -> u64 {
                self.inner.address.tag()
            }

            fn entry_index(&self) -> u64 {
                self.inner.data.len() as u64
            }

            fn owners_index(&self) -> u64 {
                self.inner.owners.len() as u64
            }

            fn permissions_index(&self) -> u64 {
                self.inner.permissions.len() as u64
            }

            fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
                self.inner
                    .data
                    .iter()
                    .find_map(|(k, v)| if k.as_slice() == key { Some(v) } else { None })
            }

            fn last_entry(&self) -> Option<(Vec<u8>, Vec<u8>)> {
                match self.inner.data.last() {
                    Some(tup) => Some(tup.clone()),
                    None => None,
                }
            }

            fn fetch_permissions_at_index(&self, perm_index: u64) -> Option<&P> {
                self.inner.permissions.get(perm_index as usize)
            }

            fn fetch_owner_at_index(&self, owners_index: u64) -> Option<&Owner> {
                self.inner.owners.get(owners_index as usize)
            }

            fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
                let range = to_absolute_range(start, end, self.inner.data.len())?;
                Some(self.inner.data[range].to_vec())
            }

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

            fn append_permissions(&mut self, permissions: P, permissions_idx: u64) -> Result<()> {
                if permissions.data_index() != self.entry_index() {
                    return Err(Error::InvalidSuccessor(self.entry_index()));
                }
                if permissions.owner_entry_index() != self.owners_index() {
                    return Err(Error::InvalidOwnersSuccessor(self.owners_index()));
                }
                if self.permissions_index() != permissions_idx {
                    return Err(Error::InvalidSuccessor(self.permissions_index()));
                }
                self.inner.permissions.push(permissions);
                Ok(())
            }

            fn append_owner(&mut self, owner: Owner, owners_idx: u64) -> Result<()> {
                if owner.data_index != self.entry_index() {
                    return Err(Error::InvalidSuccessor(self.entry_index()));
                }
                if owner.permissions_index != self.permissions_index() {
                    return Err(Error::InvalidPermissionsSuccessor(self.permissions_index()));
                }
                if self.owners_index() != owners_idx {
                    return Err(Error::InvalidSuccessor(self.owners_index()));
                }
                self.inner.owners.push(owner);
                Ok(())
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

fn check_dup(data: &[(Vec<u8>, Vec<u8>)], entries: &mut Entries) -> Result<()> {
    let new: BTreeSet<&Vec<u8>> = entries.iter().map(|(key, _value)| key).collect();

    // If duplicate entries are present in the push.
    if new.len() < entries.len() {
        return Err(Error::DuplicateEntryKeys);
    }

    let existing: BTreeSet<&Vec<u8>> = data.iter().map(|(key, _value)| key).collect();
    if !existing.is_disjoint(&new) {
        let dup: Entries = entries
            .drain(..)
            .filter(|(key, _value)| existing.contains(&key))
            .collect();
        return Err(Error::KeysExist(dup));
    }
    Ok(())
}

impl<P> SeqAppendOnly for SeqAppendOnlyData<P>
where
    P: Permissions + Hash + Clone,
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
    P: Permissions + Hash + Clone,
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
            .fetch_owner_at_index($data.owners_index() - 1)
            .ok_or_else(|| Error::NoSuchData)?
            .public_key
            == $requester
        {
            Ok(())
        } else {
            $data
                .fetch_permissions_at_index($data.permissions_index() - 1)
                .ok_or_else(|| Error::NoSuchData)?
                .is_action_allowed($requester, $action)
        }
    };
}

macro_rules! indices {
    ($data: ident) => {
        Ok(Indices::new(
            $data.entry_index(),
            $data.owners_index(),
            $data.permissions_index(),
        ))
    };
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    PubSeq,
    PubUnseq,
    UnpubSeq,
    UnpubUnseq,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    PubSeq { name: XorName, tag: u64 },
    PubUnseq { name: XorName, tag: u64 },
    UnpubSeq { name: XorName, tag: u64 },
    UnpubUnseq { name: XorName, tag: u64 },
}

impl Address {
    pub fn from_kind(kind: Kind, name: XorName, tag: u64) -> Self {
        match kind {
            Kind::PubSeq => Address::PubSeq { name, tag },
            Kind::PubUnseq => Address::PubUnseq { name, tag },
            Kind::UnpubSeq => Address::UnpubSeq { name, tag },
            Kind::UnpubUnseq => Address::UnpubUnseq { name, tag },
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            Address::PubSeq { .. } => Kind::PubSeq,
            Address::PubUnseq { .. } => Kind::PubUnseq,
            Address::UnpubSeq { .. } => Kind::UnpubSeq,
            Address::UnpubUnseq { .. } => Kind::UnpubUnseq,
        }
    }

    pub fn name(&self) -> &XorName {
        match self {
            Address::PubSeq { ref name, .. }
            | Address::PubUnseq { ref name, .. }
            | Address::UnpubSeq { ref name, .. }
            | Address::UnpubUnseq { ref name, .. } => name,
        }
    }

    pub fn tag(&self) -> u64 {
        match self {
            Address::PubSeq { tag, .. }
            | Address::PubUnseq { tag, .. }
            | Address::UnpubSeq { tag, .. }
            | Address::UnpubUnseq { tag, .. } => *tag,
        }
    }

    /// Returns the Address serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Create from z-base-32 encoded string.
    pub fn decode_from_zbase32<I: Decodable>(encoded: I) -> Result<Self> {
        utils::decode(encoded)
    }
}

/// Object storing an appendonly data variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    PubSeq(PubSeqAppendOnlyData),
    PubUnseq(PubUnseqAppendOnlyData),
    UnpubSeq(UnpubSeqAppendOnlyData),
    UnpubUnseq(UnpubUnseqAppendOnlyData),
}

impl Data {
    pub fn check_permission(&self, action: Action, requester: PublicKey) -> Result<()> {
        match self {
            Data::PubSeq(data) => check_perm!(data, requester, action),
            Data::PubUnseq(data) => check_perm!(data, requester, action),
            Data::UnpubSeq(data) => check_perm!(data, requester, action),
            Data::UnpubUnseq(data) => check_perm!(data, requester, action),
        }
    }

    pub fn address(&self) -> &Address {
        match self {
            Data::PubSeq(data) => data.address(),
            Data::PubUnseq(data) => data.address(),
            Data::UnpubSeq(data) => data.address(),
            Data::UnpubUnseq(data) => data.address(),
        }
    }

    pub fn name(&self) -> &XorName {
        self.address().name()
    }

    pub fn tag(&self) -> u64 {
        self.address().tag()
    }

    pub fn kind(&self) -> Kind {
        self.address().kind()
    }

    pub fn data_index(&self) -> u64 {
        match self {
            Data::PubSeq(data) => data.entry_index(),
            Data::PubUnseq(data) => data.entry_index(),
            Data::UnpubSeq(data) => data.entry_index(),
            Data::UnpubUnseq(data) => data.entry_index(),
        }
    }

    pub fn permissions_index(&self) -> u64 {
        match self {
            Data::PubSeq(data) => data.permissions_index(),
            Data::PubUnseq(data) => data.permissions_index(),
            Data::UnpubSeq(data) => data.permissions_index(),
            Data::UnpubUnseq(data) => data.permissions_index(),
        }
    }

    pub fn owners_index(&self) -> u64 {
        match self {
            Data::PubSeq(data) => data.owners_index(),
            Data::PubUnseq(data) => data.owners_index(),
            Data::UnpubSeq(data) => data.owners_index(),
            Data::UnpubUnseq(data) => data.owners_index(),
        }
    }

    pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
        match self {
            Data::PubSeq(data) => data.in_range(start, end),
            Data::PubUnseq(data) => data.in_range(start, end),
            Data::UnpubSeq(data) => data.in_range(start, end),
            Data::UnpubUnseq(data) => data.in_range(start, end),
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        match self {
            Data::PubSeq(data) => data.get(key),
            Data::PubUnseq(data) => data.get(key),
            Data::UnpubSeq(data) => data.get(key),
            Data::UnpubUnseq(data) => data.get(key),
        }
    }

    pub fn indices(&self) -> Result<Indices> {
        match self {
            Data::PubSeq(data) => indices!(data),
            Data::PubUnseq(data) => indices!(data),
            Data::UnpubSeq(data) => indices!(data),
            Data::UnpubUnseq(data) => indices!(data),
        }
    }

    pub fn last_entry(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        match self {
            Data::PubSeq(data) => data.last_entry(),
            Data::PubUnseq(data) => data.last_entry(),
            Data::UnpubSeq(data) => data.last_entry(),
            Data::UnpubUnseq(data) => data.last_entry(),
        }
    }

    pub fn get_owners(&self, idx: u64) -> Option<&Owner> {
        match self {
            Data::PubSeq(data) => data.fetch_owner_at_index(idx),
            Data::PubUnseq(data) => data.fetch_owner_at_index(idx),
            Data::UnpubSeq(data) => data.fetch_owner_at_index(idx),
            Data::UnpubUnseq(data) => data.fetch_owner_at_index(idx),
        }
    }

    pub fn pub_user_permissions(&self, user: User, idx: u64) -> Result<PubPermissionSet> {
        self.pub_permissions(idx)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    pub fn unpub_user_permissions(&self, user: PublicKey, idx: u64) -> Result<UnpubPermissionSet> {
        self.unpub_permissions(idx)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    pub fn pub_permissions(&self, idx: u64) -> Result<&PubPermissions> {
        let perms = match self {
            Data::PubSeq(data) => data.fetch_permissions_at_index(idx),
            Data::PubUnseq(data) => data.fetch_permissions_at_index(idx),
            _ => return Err(Error::NoSuchData),
        };
        perms.ok_or(Error::NoSuchEntry)
    }

    pub fn unpub_permissions(&self, idx: u64) -> Result<&UnpubPermissions> {
        let perms = match self {
            Data::UnpubSeq(data) => data.fetch_permissions_at_index(idx),
            Data::UnpubUnseq(data) => data.fetch_permissions_at_index(idx),
            _ => return Err(Error::NoSuchData),
        };
        perms.ok_or(Error::NoSuchEntry)
    }

    pub fn shell(&self, idx: u64) -> Result<Self> {
        match self {
            Data::PubSeq(adata) => adata.shell(idx).map(Data::PubSeq),
            Data::PubUnseq(adata) => adata.shell(idx).map(Data::PubUnseq),
            Data::UnpubSeq(adata) => adata.shell(idx).map(Data::UnpubSeq),
            Data::UnpubUnseq(adata) => adata.shell(idx).map(Data::UnpubUnseq),
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

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct AppendOperation {
    // Address of an AppendOnlyData object on the network.
    pub address: Address,
    // A list of entries to append.
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
    fn append_permissions() {
        let mut data = SeqAppendOnlyData::<UnpubPermissions>::new(XorName([1; 32]), 10000);

        // Append the first permission set with correct indices - should pass.
        let res = data.append_permissions(
            UnpubPermissions {
                permissions: BTreeMap::new(),
                data_index: 0,
                owner_entry_index: 0,
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
                data_index: 64,
                owner_entry_index: 0,
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
        let owner_pk = PublicKey::Bls(SecretKey::random().public_key());

        let mut data = SeqAppendOnlyData::<UnpubPermissions>::new(XorName([1; 32]), 10000);

        // Append the first owner with correct indices - should pass.
        let res = data.append_owner(
            Owner {
                public_key: owner_pk,
                data_index: 0,
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
                data_index: 64,
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
        unwrap!(data.append(vec![(b"hello".to_vec(), b"world".to_vec())], 0));
    }

    #[test]
    fn assert_shell() {
        let owner_pk = PublicKey::Bls(SecretKey::random().public_key());
        let owner_pk1 = PublicKey::Bls(SecretKey::random().public_key());

        let mut data = SeqAppendOnlyData::<UnpubPermissions>::new(XorName([1; 32]), 10000);

        let _ = data.append_owner(
            Owner {
                public_key: owner_pk,
                data_index: 0,
                permissions_index: 0,
            },
            0,
        );

        let _ = data.append_owner(
            Owner {
                public_key: owner_pk1,
                data_index: 0,
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
            (b"KEY1".to_vec(), b"VALUE1".to_vec()),
            (b"KEY2".to_vec(), b"VALUE2".to_vec()),
            (b"KEY1".to_vec(), b"VALUE1".to_vec()),
        ];
        assert_eq!(Error::DuplicateEntryKeys, unwrap_err!(data.append(entries)));

        // Assert that the entries are appended because there are no duplicate keys.
        let entries1 = vec![
            (b"KEY1".to_vec(), b"VALUE1".to_vec()),
            (b"KEY2".to_vec(), b"VALUE2".to_vec()),
        ];

        unwrap!(data.append(entries1));

        // Assert that entries are not appended because they duplicate some keys appended previously.
        let entries2 = vec![(b"KEY2".to_vec(), b"VALUE2".to_vec())];
        assert_eq!(
            Error::KeysExist(entries2.clone()),
            unwrap_err!(data.append(entries2))
        );

        // Assert that no duplicate keys are present and the append operation is successful.
        let entries3 = vec![(b"KEY3".to_vec(), b"VALUE3".to_vec())];
        unwrap!(data.append(entries3));
    }

    #[test]
    fn append_seq_data_test() {
        let mut data = UnpubSeqAppendOnlyData::new(XorName(rand::random()), 10);

        // Assert that the entries are not appended because of duplicate keys.
        let entries = vec![
            (b"KEY1".to_vec(), b"VALUE1".to_vec()),
            (b"KEY2".to_vec(), b"VALUE2".to_vec()),
            (b"KEY1".to_vec(), b"VALUE1".to_vec()),
        ];
        assert_eq!(
            Error::DuplicateEntryKeys,
            unwrap_err!(data.append(entries, 0))
        );

        // Assert that the entries are appended because there are no duplicate keys.
        let entries1 = vec![
            (b"KEY1".to_vec(), b"VALUE1".to_vec()),
            (b"KEY2".to_vec(), b"VALUE2".to_vec()),
        ];
        unwrap!(data.append(entries1, 0));

        // Assert that entries are not appended because they duplicate some keys appended previously.
        let entries2 = vec![(b"KEY2".to_vec(), b"VALUE2".to_vec())];
        assert_eq!(
            Error::KeysExist(entries2.clone()),
            unwrap_err!(data.append(entries2, 2))
        );

        // Assert that no duplicate keys are present and the append operation is successful.
        let entries3 = vec![(b"KEY3".to_vec(), b"VALUE3".to_vec())];
        unwrap!(data.append(entries3, 2));
    }

    #[test]
    fn in_range() {
        let mut data = PubSeqAppendOnlyData::new(rand::random(), 10);
        let entries = vec![
            (b"key0".to_vec(), b"value0".to_vec()),
            (b"key1".to_vec(), b"value1".to_vec()),
        ];
        unwrap!(data.append(entries, 0));

        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromStart(0)),
            Some(vec![])
        );
        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromStart(1)),
            Some(vec![(b"key0".to_vec(), b"value0".to_vec())])
        );
        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromStart(2)),
            Some(vec![
                (b"key0".to_vec(), b"value0".to_vec()),
                (b"key1".to_vec(), b"value1".to_vec())
            ])
        );

        assert_eq!(
            data.in_range(Index::FromEnd(2), Index::FromEnd(1)),
            Some(vec![(b"key0".to_vec(), b"value0".to_vec()),])
        );
        assert_eq!(
            data.in_range(Index::FromEnd(2), Index::FromEnd(0)),
            Some(vec![
                (b"key0".to_vec(), b"value0".to_vec()),
                (b"key1".to_vec(), b"value1".to_vec())
            ])
        );

        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromEnd(0)),
            Some(vec![
                (b"key0".to_vec(), b"value0".to_vec()),
                (b"key1".to_vec(), b"value1".to_vec())
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
        let public_key = PublicKey::Bls(SecretKey::random().public_key());
        let invalid_public_key = PublicKey::Bls(SecretKey::random().public_key());

        let mut pub_perms = PubPermissions {
            permissions: BTreeMap::new(),
            data_index: 0,
            owner_entry_index: 0,
        };
        let _ = pub_perms
            .permissions
            .insert(User::Key(public_key), PubPermissionSet::new(false, false));

        let mut unpub_perms = UnpubPermissions {
            permissions: BTreeMap::new(),
            data_index: 0,
            owner_entry_index: 0,
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
}
