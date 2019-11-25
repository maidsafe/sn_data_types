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
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    hash::Hash,
    ops::Range,
};

pub type PublicSentriedSequence = Sequence<PublicPermissions, Sentried>;
pub type PublicSequence = Sequence<PublicPermissions, NonSentried>;
pub type PrivateSentriedSequence = Sequence<PrivatePermissions, Sentried>;
pub type PrivateSequence = Sequence<PrivatePermissions, NonSentried>;
pub type Entries = Vec<Entry>;

/// Marker for sentried data.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Sentried;

/// Marker for non-sentried data.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct NonSentried;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub enum User {
    Anyone,
    Key(PublicKey),
}

#[derive(Clone, Copy, Eq, PartialEq)]
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

impl From<u64> for Index {
    fn from(index: u64) -> Self {
        Index::FromStart(index)
    }
}

// Set of data, owners, permissions Indices.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExpectedIndices {
    expected_entries_index: u64,
    expected_owners_index: u64,
    expected_permissions_index: u64,
}

impl ExpectedIndices {
    pub fn new(
        expected_entries_index: u64,
        expected_owners_index: u64,
        expected_permissions_index: u64,
    ) -> Self {
        ExpectedIndices {
            expected_entries_index,
            expected_owners_index,
            expected_permissions_index,
        }
    }

    pub fn expected_entries_index(&self) -> u64 {
        self.expected_entries_index
    }

    pub fn expected_owners_index(&self) -> u64 {
        self.expected_owners_index
    }

    pub fn expected_permissions_index(&self) -> u64 {
        self.expected_permissions_index
    }
}

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivatePermissionSet {
    read: bool,
    append: bool,
    manage_permissions: bool,
}

impl PrivatePermissionSet {
    pub fn new(read: bool, append: bool, manage_permissions: bool) -> Self {
        PrivatePermissionSet {
            read,
            append,
            manage_permissions: manage_permissions,
        }
    }

    pub fn set_permissions(&mut self, read: bool, append: bool, manage_permissions: bool) {
        self.read = read;
        self.append = append;
        self.manage_permissions = manage_permissions;
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
pub struct PublicPermissionSet {
    append: Option<bool>,
    manage_permissions: Option<bool>,
}

impl PublicPermissionSet {
    pub fn new(
        append: impl Into<Option<bool>>,
        manage_permissions: impl Into<Option<bool>>,
    ) -> Self {
        PublicPermissionSet {
            append: append.into(),
            manage_permissions: manage_permissions.into(),
        }
    }

    pub fn set_permissions(
        &mut self,
        append: impl Into<Option<bool>>,
        manage_permissions: impl Into<Option<bool>>,
    ) {
        self.append = append.into();
        self.manage_permissions = manage_permissions.into();
    }

    pub fn is_allowed(self, action: Action) -> Option<bool> {
        match action {
            Action::Read => Some(true), // It's Public data, so it's always allowed to read it.
            Action::Append => self.append,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

pub trait Permissions: Clone + Eq + Ord + Hash + Serialize + DeserializeOwned {
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()>;
    fn expected_entries_index(&self) -> u64;
    fn expected_owners_index(&self) -> u64;
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivatePermissions {
    pub permissions: BTreeMap<PublicKey, PrivatePermissionSet>,
    /// The expected index of the data at the time this permission change is to become valid.
    pub expected_entries_index: u64,
    /// The expected index of the owners at the time this permission change is to become valid.
    pub expected_owners_index: u64,
}

impl PrivatePermissions {
    pub fn permissions(&self) -> &BTreeMap<PublicKey, PrivatePermissionSet> {
        &self.permissions
    }
}

impl Permissions for PrivatePermissions {
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()> {
        match self.permissions.get(&requester) {
            Some(permissions) => {
                if permissions.is_allowed(action) {
                    Ok(())
                } else {
                    Err(Error::AccessDenied)
                }
            }
            None => Err(Error::InvalidPermissions),
        }
    }

    fn expected_entries_index(&self) -> u64 {
        self.expected_entries_index
    }

    fn expected_owners_index(&self) -> u64 {
        self.expected_owners_index
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PublicPermissions {
    pub permissions: BTreeMap<User, PublicPermissionSet>,
    /// The expected index of the data at the time this permission change is to become valid.
    pub expected_entries_index: u64,
    /// The expected index of the owners at the time this permission change is to become valid.
    pub expected_owners_index: u64,
}

impl PublicPermissions {
    fn is_action_allowed_by_user(&self, user: &User, action: Action) -> Option<bool> {
        self.permissions
            .get(user)
            .and_then(|permissions| permissions.is_allowed(action))
    }

    pub fn permissions(&self) -> &BTreeMap<User, PublicPermissionSet> {
        &self.permissions
    }
}

impl Permissions for PublicPermissions {
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()> {
        match self
            .is_action_allowed_by_user(&User::Key(requester), action)
            .or_else(|| self.is_action_allowed_by_user(&User::Anyone, action))
        {
            Some(true) => Ok(()),
            Some(false) => Err(Error::AccessDenied),
            None => Err(Error::InvalidPermissions),
        }
    }

    fn expected_entries_index(&self) -> u64 {
        self.expected_entries_index
    }

    fn expected_owners_index(&self) -> u64 {
        self.expected_owners_index
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum SequencePermissions {
    Pub(PublicPermissions),
    Private(PrivatePermissions),
}

impl From<PrivatePermissions> for SequencePermissions {
    fn from(permissions: PrivatePermissions) -> Self {
        SequencePermissions::Private(permissions)
    }
}

impl From<PublicPermissions> for SequencePermissions {
    fn from(permissions: PublicPermissions) -> Self {
        SequencePermissions::Pub(permissions)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Owner {
    pub public_key: PublicKey,
    /// The expected index of the data at the time this ownership change is to become valid.
    pub expected_entries_index: u64,
    /// The expected index of the permissions at the time this ownership change is to become valid.
    pub expected_permissions_index: u64,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default, Debug)]
pub struct Entry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl Entry {
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Self {
        Self { key, value }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct Sequence<P, S> {
    address: Address,
    data: Entries,
    permissions: Vec<P>,
    // This is the history of owners, with each entry representing an owner.  Each single owner
    // could represent an individual user, or a group of users, depending on the `PublicKey` type.
    owners: Vec<Owner>,
    _flavour: S,
}

/// Common methods for all `Sequence` flavours.
impl<P, S> Sequence<P, S>
where
    P: Permissions,
    S: Copy,
{
    /// Returns the data shell - that is - everything except the entries themselves.
    pub fn shell(&self, expected_entries_index: impl Into<Index>) -> Result<Self> {
        let expected_entries_index = to_absolute_index(
            expected_entries_index.into(),
            self.expected_entries_index() as usize,
        )
        .ok_or(Error::NoSuchEntry)? as u64;

        let permissions = self
            .permissions
            .iter()
            .filter(|perm| perm.expected_entries_index() <= expected_entries_index)
            .cloned()
            .collect();

        let owners = self
            .owners
            .iter()
            .filter(|owner| owner.expected_entries_index <= expected_entries_index)
            .cloned()
            .collect();

        Ok(Self {
            address: self.address,
            data: Vec::new(),
            permissions,
            owners,
            _flavour: self._flavour,
        })
    }

    /// Return a value for the given key (if it is present).
    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.data.iter().find_map(|entry| {
            if entry.key.as_slice() == key {
                Some(&entry.value)
            } else {
                None
            }
        })
    }

    /// Return the current entry in the Data (if it is present).
    pub fn current_entry(&self) -> Option<&Entry> {
        self.data.last()
    }

    /// Get a list of keys and values with the given indices.
    pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
        let range = to_absolute_range(start, end, self.data.len())?;
        Some(self.data[range].to_vec())
    }

    /// Return all entries.
    pub fn entries(&self) -> &Entries {
        &self.data
    }

    /// Return the address of this Sequence.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Return the name of this Sequence.
    pub fn name(&self) -> &XorName {
        self.address.name()
    }

    /// Return the type tag of this Sequence.
    pub fn tag(&self) -> u64 {
        self.address.tag()
    }

    /// Return the expected entry index.
    pub fn expected_entries_index(&self) -> u64 {
        self.data.len() as u64
    }

    /// Return the expected owners index.
    pub fn expected_owners_index(&self) -> u64 {
        self.owners.len() as u64
    }

    /// Return the expected permissions index.
    pub fn expected_permissions_index(&self) -> u64 {
        self.permissions.len() as u64
    }

    /// Get a complete list of permissions from the entry in the permissions list at the specified
    /// index.
    pub fn permissions_range(&self, start: Index, end: Index) -> Option<&[P]> {
        let range = to_absolute_range(start, end, self.permissions.len())?;
        Some(&self.permissions[range])
    }

    /// Add a new permissions entry.
    /// The `Perm` struct should contain valid indices.
    pub fn append_permissions(&mut self, permissions: P, index: u64) -> Result<()> {
        if permissions.expected_entries_index() != self.expected_entries_index() {
            return Err(Error::InvalidSuccessor(self.expected_entries_index()));
        }
        if permissions.expected_owners_index() != self.expected_owners_index() {
            return Err(Error::InvalidOwnersSuccessor(self.expected_owners_index()));
        }
        if self.expected_permissions_index() != index {
            return Err(Error::InvalidSuccessor(self.expected_permissions_index()));
        }
        self.permissions.push(permissions);
        Ok(())
    }

    /// Fetch permissions at index.
    pub fn permissions(&self, index: impl Into<Index>) -> Option<&P> {
        let index = to_absolute_index(index.into(), self.permissions.len())?;
        self.permissions.get(index)
    }

    pub fn check_permission(&self, requester: PublicKey, action: Action) -> Result<()> {
        if self
            .owner(Index::FromEnd(1))
            .ok_or(Error::InvalidOwners)?
            .public_key
            == requester
        {
            Ok(())
        } else {
            self.permissions(Index::FromEnd(1))
                .ok_or(Error::InvalidPermissions)?
                .is_action_allowed(requester, action)
        }
    }

    /// Fetch owner at index.
    pub fn owner(&self, index: impl Into<Index>) -> Option<&Owner> {
        let index = to_absolute_index(index.into(), self.owners.len())?;
        self.owners.get(index)
    }

    /// Get a complete list of owners from the entry in the permissions list at the specified index.
    pub fn owners_range(&self, start: Index, end: Index) -> Option<&[Owner]> {
        let range = to_absolute_range(start, end, self.owners.len())?;
        Some(&self.owners[range])
    }
    /// Add a new owner entry.
    pub fn append_owner(&mut self, owner: Owner, index: u64) -> Result<()> {
        if owner.expected_entries_index != self.expected_entries_index() {
            return Err(Error::InvalidSuccessor(self.expected_entries_index()));
        }
        if owner.expected_permissions_index != self.expected_permissions_index() {
            return Err(Error::InvalidPermissionsSuccessor(
                self.expected_permissions_index(),
            ));
        }
        if self.expected_owners_index() != index {
            return Err(Error::InvalidSuccessor(self.expected_owners_index()));
        }
        self.owners.push(owner);
        Ok(())
    }

    /// Check if the requester is the last owner.
    pub fn check_is_current_owner(&self, requester: PublicKey) -> Result<()> {
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

    pub fn indices(&self) -> ExpectedIndices {
        ExpectedIndices::new(
            self.expected_entries_index(),
            self.expected_owners_index(),
            self.expected_permissions_index(),
        )
    }
}

/// Common methods for NonSentried flavours.
impl<P: Permissions> Sequence<P, NonSentried> {
    /// Append new entries.
    pub fn append(&mut self, mut entries: Entries) -> Result<()> {
        check_dup(&self.data, entries.as_mut())?;

        self.data.extend(entries);
        Ok(())
    }
}

/// Common methods for Sentried flavours.
impl<P: Permissions> Sequence<P, Sentried> {
    /// Append new entries.
    ///
    /// If the specified `expected_index` does not equal the entries count in data, an
    /// error will be returned.
    pub fn append(&mut self, mut entries: Entries, expected_index: u64) -> Result<()> {
        check_dup(&self.data, entries.as_mut())?;

        if expected_index != self.data.len() as u64 {
            return Err(Error::InvalidSuccessor(self.data.len() as u64));
        }

        self.data.extend(entries);
        Ok(())
    }
}

/// Public + Sentried
impl Sequence<PublicPermissions, Sentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PublicSentried { name, tag },
            data: Vec::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
            _flavour: Sentried,
        }
    }
}

impl Debug for Sequence<PublicPermissions, Sentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicSentriedSequence {:?}", self.name())
    }
}

/// Public + NonSentried
impl Sequence<PublicPermissions, NonSentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Public { name, tag },
            data: Vec::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
            _flavour: NonSentried,
        }
    }
}

impl Debug for Sequence<PublicPermissions, NonSentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicSequence {:?}", self.name())
    }
}

/// Private + Sentried
impl Sequence<PrivatePermissions, Sentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PrivateSentried { name, tag },
            data: Vec::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
            _flavour: Sentried,
        }
    }
}

impl Debug for Sequence<PrivatePermissions, Sentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateSentriedSequence {:?}", self.name())
    }
}

/// Private + NonSentried
impl Sequence<PrivatePermissions, NonSentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Private { name, tag },
            data: Vec::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
            _flavour: NonSentried,
        }
    }
}

impl Debug for Sequence<PrivatePermissions, NonSentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateSequence {:?}", self.name())
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

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    PublicSentried,
    Public,
    PrivateSentried,
    Private,
}

impl Kind {
    pub fn is_public(self) -> bool {
        self == Kind::PublicSentried || self == Kind::Public
    }

    pub fn is_private(self) -> bool {
        !self.is_public()
    }

    pub fn is_sentried(self) -> bool {
        self == Kind::PublicSentried || self == Kind::PrivateSentried
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    PublicSentried { name: XorName, tag: u64 },
    Public { name: XorName, tag: u64 },
    PrivateSentried { name: XorName, tag: u64 },
    Private { name: XorName, tag: u64 },
}

impl Address {
    pub fn from_kind(kind: Kind, name: XorName, tag: u64) -> Self {
        match kind {
            Kind::PublicSentried => Address::PublicSentried { name, tag },
            Kind::Public => Address::Public { name, tag },
            Kind::PrivateSentried => Address::PrivateSentried { name, tag },
            Kind::Private => Address::Private { name, tag },
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            Address::PublicSentried { .. } => Kind::PublicSentried,
            Address::Public { .. } => Kind::Public,
            Address::PrivateSentried { .. } => Kind::PrivateSentried,
            Address::Private { .. } => Kind::Private,
        }
    }

    pub fn name(&self) -> &XorName {
        match self {
            Address::PublicSentried { ref name, .. }
            | Address::Public { ref name, .. }
            | Address::PrivateSentried { ref name, .. }
            | Address::Private { ref name, .. } => name,
        }
    }

    pub fn tag(&self) -> u64 {
        match self {
            Address::PublicSentried { tag, .. }
            | Address::Public { tag, .. }
            | Address::PrivateSentried { tag, .. }
            | Address::Private { tag, .. } => *tag,
        }
    }

    pub fn is_public(&self) -> bool {
        self.kind().is_public()
    }

    pub fn is_private(&self) -> bool {
        self.kind().is_private()
    }

    pub fn is_sentried(&self) -> bool {
        self.kind().is_sentried()
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

/// Object storing a Sequence variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    PublicSentried(PublicSentriedSequence),
    Public(PublicSequence),
    PrivateSentried(PrivateSentriedSequence),
    Private(PrivateSequence),
}

impl Data {
    pub fn check_permission(&self, action: Action, requester: PublicKey) -> Result<()> {
        match (self, action) {
            (Data::PublicSentried(_), Action::Read) | (Data::Public(_), Action::Read) => {
                return Ok(())
            }
            _ => (),
        }

        match self {
            Data::PublicSentried(data) => data.check_permission(requester, action),
            Data::Public(data) => data.check_permission(requester, action),
            Data::PrivateSentried(data) => data.check_permission(requester, action),
            Data::Private(data) => data.check_permission(requester, action),
        }
    }

    pub fn address(&self) -> &Address {
        match self {
            Data::PublicSentried(data) => data.address(),
            Data::Public(data) => data.address(),
            Data::PrivateSentried(data) => data.address(),
            Data::Private(data) => data.address(),
        }
    }

    pub fn kind(&self) -> Kind {
        self.address().kind()
    }

    pub fn name(&self) -> &XorName {
        self.address().name()
    }

    pub fn tag(&self) -> u64 {
        self.address().tag()
    }

    pub fn is_public(&self) -> bool {
        self.kind().is_public()
    }

    pub fn is_private(&self) -> bool {
        self.kind().is_private()
    }

    pub fn is_sentried(&self) -> bool {
        self.kind().is_sentried()
    }

    pub fn expected_entries_index(&self) -> u64 {
        match self {
            Data::PublicSentried(data) => data.expected_entries_index(),
            Data::Public(data) => data.expected_entries_index(),
            Data::PrivateSentried(data) => data.expected_entries_index(),
            Data::Private(data) => data.expected_entries_index(),
        }
    }

    pub fn expected_permissions_index(&self) -> u64 {
        match self {
            Data::PublicSentried(data) => data.expected_permissions_index(),
            Data::Public(data) => data.expected_permissions_index(),
            Data::PrivateSentried(data) => data.expected_permissions_index(),
            Data::Private(data) => data.expected_permissions_index(),
        }
    }

    pub fn expected_owners_index(&self) -> u64 {
        match self {
            Data::PublicSentried(data) => data.expected_owners_index(),
            Data::Public(data) => data.expected_owners_index(),
            Data::PrivateSentried(data) => data.expected_owners_index(),
            Data::Private(data) => data.expected_owners_index(),
        }
    }

    pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
        match self {
            Data::PublicSentried(data) => data.in_range(start, end),
            Data::Public(data) => data.in_range(start, end),
            Data::PrivateSentried(data) => data.in_range(start, end),
            Data::Private(data) => data.in_range(start, end),
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        match self {
            Data::PublicSentried(data) => data.get(key),
            Data::Public(data) => data.get(key),
            Data::PrivateSentried(data) => data.get(key),
            Data::Private(data) => data.get(key),
        }
    }

    pub fn indices(&self) -> ExpectedIndices {
        match self {
            Data::PublicSentried(data) => data.indices(),
            Data::Public(data) => data.indices(),
            Data::PrivateSentried(data) => data.indices(),
            Data::Private(data) => data.indices(),
        }
    }

    pub fn current_entry(&self) -> Option<&Entry> {
        match self {
            Data::PublicSentried(data) => data.current_entry(),
            Data::Public(data) => data.current_entry(),
            Data::PrivateSentried(data) => data.current_entry(),
            Data::Private(data) => data.current_entry(),
        }
    }

    pub fn owner(&self, index: impl Into<Index>) -> Option<&Owner> {
        match self {
            Data::PublicSentried(data) => data.owner(index),
            Data::Public(data) => data.owner(index),
            Data::PrivateSentried(data) => data.owner(index),
            Data::Private(data) => data.owner(index),
        }
    }

    pub fn check_is_current_owner(&self, requester: PublicKey) -> Result<()> {
        match self {
            Data::PublicSentried(data) => data.check_is_current_owner(requester),
            Data::Public(data) => data.check_is_current_owner(requester),
            Data::PrivateSentried(data) => data.check_is_current_owner(requester),
            Data::Private(data) => data.check_is_current_owner(requester),
        }
    }

    pub fn public_user_permissions(
        &self,
        user: User,
        index: impl Into<Index>,
    ) -> Result<PublicPermissionSet> {
        self.public_permissions(index)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    pub fn private_user_permissions(
        &self,
        user: PublicKey,
        index: impl Into<Index>,
    ) -> Result<PrivatePermissionSet> {
        self.private_permissions(index)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    pub fn public_permissions(&self, index: impl Into<Index>) -> Result<&PublicPermissions> {
        let permissions = match self {
            Data::PublicSentried(data) => data.permissions(index),
            Data::Public(data) => data.permissions(index),
            _ => return Err(Error::NoSuchData),
        };
        permissions.ok_or(Error::NoSuchEntry)
    }

    pub fn private_permissions(&self, index: impl Into<Index>) -> Result<&PrivatePermissions> {
        let permissions = match self {
            Data::PrivateSentried(data) => data.permissions(index),
            Data::Private(data) => data.permissions(index),
            _ => return Err(Error::NoSuchData),
        };
        permissions.ok_or(Error::NoSuchEntry)
    }

    pub fn shell(&self, index: impl Into<Index>) -> Result<Self> {
        match self {
            Data::PublicSentried(adata) => adata.shell(index).map(Data::PublicSentried),
            Data::Public(adata) => adata.shell(index).map(Data::Public),
            Data::PrivateSentried(adata) => adata.shell(index).map(Data::PrivateSentried),
            Data::Private(adata) => adata.shell(index).map(Data::Private),
        }
    }
}

impl From<PublicSentriedSequence> for Data {
    fn from(data: PublicSentriedSequence) -> Self {
        Data::PublicSentried(data)
    }
}

impl From<PublicSequence> for Data {
    fn from(data: PublicSequence) -> Self {
        Data::Public(data)
    }
}

impl From<PrivateSentriedSequence> for Data {
    fn from(data: PrivateSentriedSequence) -> Self {
        Data::PrivateSentried(data)
    }
}

impl From<PrivateSequence> for Data {
    fn from(data: PrivateSequence) -> Self {
        Data::Private(data)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct AppendOperation {
    // Address of an Sequence object on the network.
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
        let mut data = PrivateSentriedSequence::new(XorName([1; 32]), 10000);

        // Append the first permission set with correct ExpectedIndices - should pass.
        let res = data.append_permissions(
            PrivatePermissions {
                permissions: BTreeMap::new(),
                expected_entries_index: 0,
                expected_owners_index: 0,
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

        // Append another permissions entry with incorrect ExpectedIndices - should fail.
        let res = data.append_permissions(
            PrivatePermissions {
                permissions: BTreeMap::new(),
                expected_entries_index: 64,
                expected_owners_index: 0,
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

        let mut data = PrivateSentriedSequence::new(XorName([1; 32]), 10000);

        // Append the first owner with correct ExpectedIndices - should pass.
        let res = data.append_owner(
            Owner {
                public_key: owner_pk,
                expected_entries_index: 0,
                expected_permissions_index: 0,
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

        // Append another owners entry with incorrect ExpectedIndices - should fail.
        let res = data.append_owner(
            Owner {
                public_key: owner_pk,
                expected_entries_index: 64,
                expected_permissions_index: 0,
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
        let mut data = PublicSentriedSequence::new(XorName([1; 32]), 10000);
        unwrap!(data.append(vec![Entry::new(b"hello".to_vec(), b"world".to_vec())], 0));
    }

    #[test]
    fn assert_shell() {
        let owner_pk = gen_public_key();
        let owner_pk1 = gen_public_key();

        let mut data = PrivateSentriedSequence::new(XorName([1; 32]), 10000);

        let _ = data.append_owner(
            Owner {
                public_key: owner_pk,
                expected_entries_index: 0,
                expected_permissions_index: 0,
            },
            0,
        );

        let _ = data.append_owner(
            Owner {
                public_key: owner_pk1,
                expected_entries_index: 0,
                expected_permissions_index: 0,
            },
            1,
        );

        assert_eq!(
            data.expected_owners_index(),
            unwrap!(data.shell(0)).expected_owners_index()
        );
    }

    #[test]
    fn zbase32_encode_decode_adata_address() {
        let name = XorName(rand::random());
        let address = Address::PrivateSentried { name, tag: 15000 };
        let encoded = address.encode_to_zbase32();
        let decoded = unwrap!(self::Address::decode_from_zbase32(&encoded));
        assert_eq!(address, decoded);
    }

    #[test]
    fn append_unseq_data_test() {
        let mut data = PrivateSequence::new(XorName(rand::random()), 10);

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
        let mut data = PrivateSentriedSequence::new(XorName(rand::random()), 10);

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
        let mut data = PublicSentriedSequence::new(rand::random(), 10);
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

        let mut pub_permissions = PublicPermissions {
            permissions: BTreeMap::new(),
            expected_entries_index: 0,
            expected_owners_index: 0,
        };
        let _ = pub_permissions.permissions.insert(
            User::Key(public_key),
            PublicPermissionSet::new(false, false),
        );

        let mut private_permissions = PrivatePermissions {
            permissions: BTreeMap::new(),
            expected_entries_index: 0,
            expected_owners_index: 0,
        };
        let _ = private_permissions
            .permissions
            .insert(public_key, PrivatePermissionSet::new(false, false, false));

        // pub, unseq
        let mut data = PublicSequence::new(rand::random(), 20);
        unwrap!(data.append_permissions(pub_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.public_permissions(0), Ok(&pub_permissions));
        assert_eq!(data.private_permissions(0), Err(Error::NoSuchData));

        assert_eq!(
            data.public_user_permissions(User::Key(public_key), 0),
            Ok(PublicPermissionSet::new(false, false))
        );
        assert_eq!(
            data.private_user_permissions(public_key, 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.public_user_permissions(User::Key(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // pub, seq
        let mut data = PublicSentriedSequence::new(rand::random(), 20);
        unwrap!(data.append_permissions(pub_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.public_permissions(0), Ok(&pub_permissions));
        assert_eq!(data.private_permissions(0), Err(Error::NoSuchData));

        assert_eq!(
            data.public_user_permissions(User::Key(public_key), 0),
            Ok(PublicPermissionSet::new(false, false))
        );
        assert_eq!(
            data.private_user_permissions(public_key, 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.public_user_permissions(User::Key(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // Private, unseq
        let mut data = PrivateSequence::new(rand::random(), 20);
        unwrap!(data.append_permissions(private_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.private_permissions(0), Ok(&private_permissions));
        assert_eq!(data.public_permissions(0), Err(Error::NoSuchData));

        assert_eq!(
            data.private_user_permissions(public_key, 0),
            Ok(PrivatePermissionSet::new(false, false, false))
        );
        assert_eq!(
            data.public_user_permissions(User::Key(public_key), 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.private_user_permissions(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );

        // Private, seq
        let mut data = PrivateSentriedSequence::new(rand::random(), 20);
        unwrap!(data.append_permissions(private_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.private_permissions(0), Ok(&private_permissions));
        assert_eq!(data.public_permissions(0), Err(Error::NoSuchData));

        assert_eq!(
            data.private_user_permissions(public_key, 0),
            Ok(PrivatePermissionSet::new(false, false, false))
        );
        assert_eq!(
            data.public_user_permissions(User::Key(public_key), 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.private_user_permissions(invalid_public_key, 0),
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
        let mut inner = PublicSentriedSequence::new(XorName([1; 32]), 100);

        // no owner
        let data = Data::from(inner.clone());
        assert_eq!(
            data.check_permission(Action::Append, public_key_0),
            Err(Error::InvalidOwners)
        );
        // data is Public - read always allowed
        assert_eq!(data.check_permission(Action::Read, public_key_0), Ok(()));

        // no permissions
        unwrap!(inner.append_owner(
            Owner {
                public_key: public_key_0,
                expected_entries_index: 0,
                expected_permissions_index: 0,
            },
            0,
        ));
        let data = Data::from(inner.clone());

        assert_eq!(data.check_permission(Action::Append, public_key_0), Ok(()));
        assert_eq!(
            data.check_permission(Action::Append, public_key_1),
            Err(Error::InvalidPermissions)
        );
        // data is Public - read always allowed
        assert_eq!(data.check_permission(Action::Read, public_key_0), Ok(()));
        assert_eq!(data.check_permission(Action::Read, public_key_1), Ok(()));

        // with permissions
        let mut permissions = PublicPermissions {
            permissions: BTreeMap::new(),
            expected_entries_index: 0,
            expected_owners_index: 1,
        };
        let _ = permissions
            .permissions
            .insert(User::Anyone, PublicPermissionSet::new(true, false));
        let _ = permissions.permissions.insert(
            User::Key(public_key_1),
            PublicPermissionSet::new(None, true),
        );
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
        // data is Public - read always allowed
        assert_eq!(data.check_permission(Action::Read, public_key_0), Ok(()));
        assert_eq!(data.check_permission(Action::Read, public_key_1), Ok(()));
        assert_eq!(data.check_permission(Action::Read, public_key_2), Ok(()));
    }

    #[test]
    fn check_private_permission() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut inner = PrivateSentriedSequence::new(XorName([1; 32]), 100);

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
                expected_entries_index: 0,
                expected_permissions_index: 0,
            },
            0,
        ));
        let data = Data::from(inner.clone());

        assert_eq!(data.check_permission(Action::Read, public_key_0), Ok(()));
        assert_eq!(
            data.check_permission(Action::Read, public_key_1),
            Err(Error::InvalidPermissions)
        );

        // with permissions
        let mut permissions = PrivatePermissions {
            permissions: BTreeMap::new(),
            expected_entries_index: 0,
            expected_owners_index: 1,
        };
        let _ = permissions
            .permissions
            .insert(public_key_1, PrivatePermissionSet::new(true, true, false));
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
            Err(Error::InvalidPermissions)
        );
        assert_eq!(
            data.check_permission(Action::Append, public_key_2),
            Err(Error::InvalidPermissions)
        );
        assert_eq!(
            data.check_permission(Action::ManagePermissions, public_key_2),
            Err(Error::InvalidPermissions)
        );
    }
}
