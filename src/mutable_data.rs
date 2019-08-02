// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{utils, EntryError, Error, PublicKey, Result, XorName};
use hex_fmt::HexFmt;
use multibase::Decodable;
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    mem,
};

/// Mutable data that is unpublished on the network. This data can only be fetched by the owner or
/// those in the permissions fields with `Permission::Read` access.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct SeqMutableData {
    /// Network address.
    address: Address,
    /// Key-Value semantics.
    data: SeqEntries,
    /// Maps an application key to a list of allowed or forbidden actions.
    permissions: BTreeMap<PublicKey, PermissionSet>,
    /// Version should be increased for any changes to MutableData fields except for data.
    version: u64,
    /// Contains the public key of an owner or owners of this data.
    ///
    /// Data Handlers in vaults enforce that a mutation request has a valid signature of the owner.
    owner: PublicKey,
}

impl Debug for SeqMutableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "SeqMutableData {:?}", self.name())
    }
}

/// Mutable data that is unpublished on the network. This data can only be fetched by the owner or
/// those in the permissions fields with `Permission::Read` access.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct UnseqMutableData {
    /// Network address.
    address: Address,
    /// Key-Value semantics.
    data: UnseqEntries,
    /// Maps an application key to a list of allowed or forbidden actions.
    permissions: BTreeMap<PublicKey, PermissionSet>,
    /// Version should be increased for any changes to MutableData fields except for data.
    version: u64,
    /// Contains the public key of an owner or owners of this data.
    ///
    /// Data Handlers in vaults enforce that a mutation request has a valid signature of the owner.
    owner: PublicKey,
}

impl Debug for UnseqMutableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "UnseqMutableData {:?}", self.name())
    }
}

/// A value in `Sequenced MutableData`.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct SeqValue {
    /// Actual data.
    pub data: Vec<u8>,
    /// SHALL be incremented sequentially for any change to `data`.
    pub version: u64,
}

impl Debug for SeqValue {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:<8} :: {}", HexFmt(&self.data), self.version)
    }
}

#[derive(Debug, Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Value {
    Seq(SeqValue),
    Unseq(Vec<u8>),
}

impl From<SeqValue> for Value {
    fn from(value: SeqValue) -> Self {
        Value::Seq(value)
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Value::Unseq(value)
    }
}

#[derive(Debug, Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Values {
    Seq(Vec<SeqValue>),
    Unseq(Vec<Vec<u8>>),
}

impl From<Vec<SeqValue>> for Values {
    fn from(values: Vec<SeqValue>) -> Self {
        Values::Seq(values)
    }
}

impl From<Vec<Vec<u8>>> for Values {
    fn from(values: Vec<Vec<u8>>) -> Self {
        Values::Unseq(values)
    }
}

/// Set of user permissions.
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct PermissionSet {
    permissions: BTreeSet<Action>,
}

impl PermissionSet {
    /// Construct new permission set.
    pub fn new() -> PermissionSet {
        PermissionSet {
            permissions: Default::default(),
        }
    }

    /// Allow the given action.
    pub fn allow(mut self, action: Action) -> Self {
        let _ = self.permissions.insert(action);
        self
    }

    /// Deny the given action.
    pub fn deny(mut self, action: Action) -> Self {
        let _ = self.permissions.remove(&action);
        self
    }

    /// Is the given action allowed according to this permission set?
    pub fn is_allowed(&self, action: Action) -> bool {
        self.permissions.contains(&action)
    }
}

/// Set of Actions that can be performed on the Data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Action {
    /// Permission to read entries.
    Read,
    /// Permission to insert new entries.
    Insert,
    /// Permission to update existing entries.
    Update,
    /// Permission to delete existing entries.
    Delete,
    /// Permission to modify permissions for other users.
    ManagePermissions,
}

macro_rules! impl_mutable_data {
    ($flavour:ident) => {
        impl $flavour {
            /// Returns the Shell of the data
            pub fn shell(&self) -> Self {
                Self {
                    address: self.address.clone(),
                    data: BTreeMap::new(),
                    permissions: self.permissions.clone(),
                    version: self.version,
                    owner: self.owner,
                }
            }

            /// Returns the address of the Mutable data
            pub fn address(&self) -> &Address {
                &self.address
            }

            /// Returns the name of the Mutable data
            pub fn name(&self) -> &XorName {
                self.address.name()
            }

            /// Returns the tag type of the Mutable data
            pub fn tag(&self) -> u64 {
                self.address.tag()
            }

            /// Returns the kind of the Mutable data.
            pub fn kind(&self) -> Kind {
                self.address.kind()
            }

            /// Returns the version of the Mutable data
            pub fn version(&self) -> u64 {
                self.version
            }

            /// Returns the owner key
            pub fn owner(&self) -> &PublicKey {
                &self.owner
            }

            /// Returns all the keys in the data
            pub fn keys(&self) -> BTreeSet<Vec<u8>> {
                self.data.keys().cloned().collect()
            }

            /// Gets a complete list of permissions
            pub fn permissions(&self) -> BTreeMap<PublicKey, PermissionSet> {
                self.permissions.clone()
            }

            pub fn user_permissions(&self, user: PublicKey) -> Result<&PermissionSet> {
                self.permissions.get(&user).ok_or(Error::NoSuchKey)
            }

            pub fn check_is_owner(&self, requester: PublicKey) -> Result<()> {
                if self.owner == requester {
                    Ok(())
                } else {
                    Err(Error::AccessDenied)
                }
            }

            pub fn check_permissions(&self, action: Action, requester: PublicKey) -> Result<()> {
                if self.owner == requester {
                    Ok(())
                } else {
                    let permissions = self
                        .user_permissions(requester)
                        .map_err(|_| Error::AccessDenied)?;
                    if permissions.is_allowed(action) {
                        Ok(())
                    } else {
                        Err(Error::AccessDenied)
                    }
                }
            }

            /// Insert or update permissions for the provided user.
            pub fn set_user_permissions(
                &mut self,
                user: PublicKey,
                permissions: PermissionSet,
                version: u64,
            ) -> Result<()> {
                if version != self.version + 1 {
                    return Err(Error::InvalidSuccessor(self.version));
                }
                let _prev = self.permissions.insert(user, permissions);
                self.version = version;
                Ok(())
            }

            /// Delete permissions for the provided user.
            pub fn del_user_permissions(&mut self, user: PublicKey, version: u64) -> Result<()> {
                if version != self.version + 1 {
                    return Err(Error::InvalidSuccessor(self.version));
                }
                if !self.permissions.contains_key(&user) {
                    return Err(Error::NoSuchKey);
                }
                let _ = self.permissions.remove(&user);
                self.version = version;
                Ok(())
            }

            /// Delete user permissions without performing any validation.
            pub fn del_user_permissions_without_validation(
                &mut self,
                user: PublicKey,
                version: u64,
            ) -> bool {
                if version <= self.version {
                    return false;
                }
                let _ = self.permissions.remove(&user);
                self.version = version;
                true
            }

            /// Change owner of the mutable data.
            pub fn change_owner(&mut self, new_owner: PublicKey, version: u64) -> Result<()> {
                if version != self.version + 1 {
                    return Err(Error::InvalidSuccessor(self.version));
                }
                self.owner = new_owner;
                self.version = version;
                Ok(())
            }

            /// Change the owner without performing any validation.
            pub fn change_owner_without_validation(
                &mut self,
                new_owner: PublicKey,
                version: u64,
            ) -> bool {
                if version <= self.version {
                    return false;
                }

                self.owner = new_owner;
                self.version = version;
                true
            }

            pub fn is_action_allowed(&self, requester: &PublicKey, action: Action) -> bool {
                match self.permissions.get(requester) {
                    Some(perms) => perms.is_allowed(action),
                    None => false,
                }
            }
        }
    };
}

impl_mutable_data!(SeqMutableData);
impl_mutable_data!(UnseqMutableData);

/// Implements functions which are COMMON for both the mutable data
impl UnseqMutableData {
    /// Create a new Unsequenced Mutable Data
    pub fn new(name: XorName, tag: u64, owner: PublicKey) -> Self {
        Self {
            address: Address::Unseq { name, tag },
            data: Default::default(),
            permissions: Default::default(),
            version: 0,
            owner,
        }
    }

    /// Create a new Unsequenced Mutable Data with entries and permissions
    pub fn new_with_data(
        name: XorName,
        tag: u64,
        data: UnseqEntries,
        permissions: BTreeMap<PublicKey, PermissionSet>,
        owner: PublicKey,
    ) -> Self {
        Self {
            address: Address::Unseq { name, tag },
            data,
            permissions,
            version: 0,
            owner,
        }
    }

    /// Returns a value for the given key
    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.data.get(key)
    }

    /// Returns values of all entries
    pub fn values(&self) -> Vec<Vec<u8>> {
        self.data.values().cloned().collect()
    }

    /// Returns all entries
    pub fn entries(&self) -> &UnseqEntries {
        &self.data
    }

    /// Removes and returns all entries
    pub fn take_entries(&mut self) -> UnseqEntries {
        mem::replace(&mut self.data, BTreeMap::new())
    }

    pub fn mutate_entries(
        &mut self,
        actions: UnseqEntryActions,
        requester: PublicKey,
    ) -> Result<()> {
        let (insert, update, delete) = actions.actions.into_iter().fold(
            (
                BTreeMap::<Vec<u8>, Vec<u8>>::new(),
                BTreeMap::<Vec<u8>, Vec<u8>>::new(),
                BTreeSet::<Vec<u8>>::new(),
            ),
            |(mut insert, mut update, mut delete), (key, item)| {
                match item {
                    UnseqEntryAction::Ins(value) => {
                        let _ = insert.insert(key, value);
                    }
                    UnseqEntryAction::Update(value) => {
                        let _ = update.insert(key, value);
                    }
                    UnseqEntryAction::Del => {
                        let _ = delete.insert(key);
                    }
                };
                (insert, update, delete)
            },
        );

        if *self.owner() != requester
            && ((!insert.is_empty() && !self.is_action_allowed(&requester, Action::Insert))
                || (!update.is_empty() && !self.is_action_allowed(&requester, Action::Update))
                || (!delete.is_empty() && !self.is_action_allowed(&requester, Action::Delete)))
        {
            return Err(Error::AccessDenied);
        }

        let mut new_data = self.data.clone();
        let mut errors = BTreeMap::new();

        for (key, val) in insert {
            match new_data.entry(key) {
                Entry::Occupied(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::EntryExists(0));
                }
                Entry::Vacant(entry) => {
                    let _ = entry.insert(val);
                }
            }
        }

        for (key, val) in update {
            match new_data.entry(key) {
                Entry::Occupied(mut entry) => {
                    let _ = entry.insert(val);
                }
                Entry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        for key in delete {
            match new_data.entry(key.clone()) {
                Entry::Occupied(_) => {
                    let _ = new_data.remove(&key);
                }
                Entry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        if !errors.is_empty() {
            return Err(Error::InvalidEntryActions(errors));
        }

        let _old_data = mem::replace(&mut self.data, new_data);

        Ok(())
    }
}

/// Implements functions for sequenced Mutable Data.
impl SeqMutableData {
    /// Create a new Sequenced Mutable Data
    pub fn new(name: XorName, tag: u64, owner: PublicKey) -> Self {
        Self {
            address: Address::Seq { name, tag },
            data: Default::default(),
            permissions: Default::default(),
            version: 0,
            owner,
        }
    }

    /// Create a new Sequenced Mutable Data with entries and permissions
    pub fn new_with_data(
        name: XorName,
        tag: u64,
        data: SeqEntries,
        permissions: BTreeMap<PublicKey, PermissionSet>,
        owner: PublicKey,
    ) -> Self {
        Self {
            address: Address::Seq { name, tag },
            data,
            permissions,
            version: 0,
            owner,
        }
    }

    /// Returns a value by the given key
    pub fn get(&self, key: &[u8]) -> Option<&SeqValue> {
        self.data.get(key)
    }

    /// Returns values of all entries
    pub fn values(&self) -> Vec<SeqValue> {
        self.data.values().cloned().collect()
    }

    /// Returns all entries
    pub fn entries(&self) -> &SeqEntries {
        &self.data
    }

    /// Removes and returns all entries
    pub fn take_entries(&mut self) -> SeqEntries {
        mem::replace(&mut self.data, BTreeMap::new())
    }

    /// Mutates entries (key + value pairs) in bulk
    pub fn mutate_entries(&mut self, actions: SeqEntryActions, requester: PublicKey) -> Result<()> {
        // Deconstruct actions into inserts, updates, and deletes
        let (insert, update, delete) = actions.actions.into_iter().fold(
            (BTreeMap::new(), BTreeMap::new(), BTreeMap::new()),
            |(mut insert, mut update, mut delete), (key, item)| {
                match item {
                    SeqEntryAction::Ins(value) => {
                        let _ = insert.insert(key, value);
                    }
                    SeqEntryAction::Update(value) => {
                        let _ = update.insert(key, value);
                    }
                    SeqEntryAction::Del(version) => {
                        let _ = delete.insert(key, version);
                    }
                };
                (insert, update, delete)
            },
        );

        if *self.owner() != requester
            && ((!insert.is_empty() && !self.is_action_allowed(&requester, Action::Insert))
                || (!update.is_empty() && !self.is_action_allowed(&requester, Action::Update))
                || (!delete.is_empty() && !self.is_action_allowed(&requester, Action::Delete)))
        {
            return Err(Error::AccessDenied);
        }

        let mut new_data = self.data.clone();
        let mut errors = BTreeMap::new();

        for (key, val) in insert {
            match new_data.entry(key) {
                Entry::Occupied(entry) => {
                    let _ = errors.insert(
                        entry.key().clone(),
                        EntryError::EntryExists(entry.get().version as u8),
                    );
                }
                Entry::Vacant(entry) => {
                    let _ = entry.insert(val);
                }
            }
        }

        for (key, val) in update {
            match new_data.entry(key) {
                Entry::Occupied(mut entry) => {
                    let current_version = entry.get().version;
                    if val.version == current_version + 1 {
                        let _ = entry.insert(val);
                    } else {
                        let _ = errors.insert(
                            entry.key().clone(),
                            EntryError::InvalidSuccessor(current_version as u8),
                        );
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        for (key, version) in delete {
            match new_data.entry(key.clone()) {
                Entry::Occupied(entry) => {
                    let current_version = entry.get().version;
                    if version == current_version + 1 {
                        let _ = new_data.remove(&key);
                    } else {
                        let _ = errors.insert(
                            entry.key().clone(),
                            EntryError::InvalidSuccessor(current_version as u8),
                        );
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        if !errors.is_empty() {
            return Err(Error::InvalidEntryActions(errors));
        }

        let _old_data = mem::replace(&mut self.data, new_data);

        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    Unseq,
    Seq,
}

impl Kind {
    pub fn is_seq(self) -> bool {
        self == Kind::Seq
    }

    pub fn is_unseq(self) -> bool {
        !self.is_seq()
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    Unseq { name: XorName, tag: u64 },
    Seq { name: XorName, tag: u64 },
}

impl Address {
    pub fn from_kind(kind: Kind, name: XorName, tag: u64) -> Self {
        match kind {
            Kind::Seq => Address::Seq { name, tag },
            Kind::Unseq => Address::Unseq { name, tag },
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            Address::Seq { .. } => Kind::Seq,
            Address::Unseq { .. } => Kind::Unseq,
        }
    }

    pub fn name(&self) -> &XorName {
        match self {
            Address::Unseq { ref name, .. } | Address::Seq { ref name, .. } => name,
        }
    }

    pub fn tag(&self) -> u64 {
        match self {
            Address::Unseq { tag, .. } | Address::Seq { tag, .. } => *tag,
        }
    }

    pub fn is_seq(&self) -> bool {
        self.kind().is_seq()
    }

    pub fn is_unseq(&self) -> bool {
        self.kind().is_unseq()
    }

    /// Returns the Address serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Create from z-base-32 encoded string.
    pub fn decode_from_zbase32<T: Decodable>(encoded: T) -> Result<Self> {
        utils::decode(encoded)
    }
}

/// Object storing a mutable data variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    Seq(SeqMutableData),
    Unseq(UnseqMutableData),
}

impl Data {
    pub fn address(&self) -> &Address {
        match self {
            Data::Seq(data) => data.address(),
            Data::Unseq(data) => data.address(),
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

    pub fn is_seq(&self) -> bool {
        self.kind().is_seq()
    }

    pub fn is_unseq(&self) -> bool {
        self.kind().is_unseq()
    }

    pub fn version(&self) -> u64 {
        match self {
            Data::Seq(data) => data.version(),
            Data::Unseq(data) => data.version(),
        }
    }

    pub fn keys(&self) -> BTreeSet<Vec<u8>> {
        match self {
            Data::Seq(data) => data.keys(),
            Data::Unseq(data) => data.keys(),
        }
    }

    pub fn shell(&self) -> Self {
        match self {
            Data::Seq(data) => Data::Seq(data.shell()),
            Data::Unseq(data) => Data::Unseq(data.shell()),
        }
    }

    pub fn permissions(&self) -> BTreeMap<PublicKey, PermissionSet> {
        match self {
            Data::Seq(data) => data.permissions(),
            Data::Unseq(data) => data.permissions(),
        }
    }

    pub fn user_permissions(&self, user: PublicKey) -> Result<&PermissionSet> {
        match self {
            Data::Seq(data) => data.user_permissions(user),
            Data::Unseq(data) => data.user_permissions(user),
        }
    }

    pub fn set_user_permissions(
        &mut self,
        user: PublicKey,
        permissions: PermissionSet,
        version: u64,
    ) -> Result<()> {
        match self {
            Data::Seq(data) => data.set_user_permissions(user, permissions, version),
            Data::Unseq(data) => data.set_user_permissions(user, permissions, version),
        }
    }

    pub fn del_user_permissions(&mut self, user: PublicKey, version: u64) -> Result<()> {
        match self {
            Data::Seq(data) => data.del_user_permissions(user, version),
            Data::Unseq(data) => data.del_user_permissions(user, version),
        }
    }

    pub fn check_permissions(&self, action: Action, requester: PublicKey) -> Result<()> {
        match self {
            Data::Seq(data) => data.check_permissions(action, requester),
            Data::Unseq(data) => data.check_permissions(action, requester),
        }
    }

    pub fn check_is_owner(&self, requester: PublicKey) -> Result<()> {
        match self {
            Data::Seq(data) => data.check_is_owner(requester),
            Data::Unseq(data) => data.check_is_owner(requester),
        }
    }

    pub fn owner(&self) -> PublicKey {
        match self {
            Data::Seq(data) => data.owner,
            Data::Unseq(data) => data.owner,
        }
    }

    pub fn mutate_entries(&mut self, actions: EntryActions, requester: PublicKey) -> Result<()> {
        match self {
            Data::Seq(data) => {
                if let EntryActions::Seq(actions) = actions {
                    return data.mutate_entries(actions, requester);
                }
            }
            Data::Unseq(data) => {
                if let EntryActions::Unseq(actions) = actions {
                    return data.mutate_entries(actions, requester);
                }
            }
        }

        Err(Error::InvalidOperation)
    }
}

impl From<SeqMutableData> for Data {
    fn from(data: SeqMutableData) -> Self {
        Data::Seq(data)
    }
}

impl From<UnseqMutableData> for Data {
    fn from(data: UnseqMutableData) -> Self {
        Data::Unseq(data)
    }
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub enum SeqEntryAction {
    /// Inserts a new Sequenced entry
    Ins(SeqValue),
    /// Updates an entry with a new value and version
    Update(SeqValue),
    /// Deletes an entry
    Del(u64),
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub enum UnseqEntryAction {
    /// Inserts a new Unsequenced entry
    Ins(Vec<u8>),
    /// Updates an entry with a new value
    Update(Vec<u8>),
    /// Deletes an entry
    Del,
}

/// Helper struct to build entry actions on `MutableData`
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug, Default)]
pub struct SeqEntryActions {
    actions: BTreeMap<Vec<u8>, SeqEntryAction>,
}

impl SeqEntryActions {
    /// Create a new Sequenced Entry Actions list
    pub fn new() -> Self {
        Default::default()
    }

    /// Insert a new key-value pair
    pub fn ins(mut self, key: Vec<u8>, content: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(
            key,
            SeqEntryAction::Ins(SeqValue {
                data: content,
                version,
            }),
        );
        self
    }

    /// Update an existing key-value pair
    pub fn update(mut self, key: Vec<u8>, content: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(
            key,
            SeqEntryAction::Update(SeqValue {
                data: content,
                version,
            }),
        );
        self
    }

    /// Delete an entry
    pub fn del(mut self, key: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(key, SeqEntryAction::Del(version));
        self
    }
}

impl From<SeqEntryActions> for BTreeMap<Vec<u8>, SeqEntryAction> {
    fn from(actions: SeqEntryActions) -> Self {
        actions.actions
    }
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug, Default)]
pub struct UnseqEntryActions {
    actions: BTreeMap<Vec<u8>, UnseqEntryAction>,
}

impl UnseqEntryActions {
    /// Create a new Unsequenced Entry Actions list
    pub fn new() -> Self {
        Default::default()
    }

    /// Insert a new key-value pair
    pub fn ins(mut self, key: Vec<u8>, content: Vec<u8>) -> Self {
        let _ = self.actions.insert(key, UnseqEntryAction::Ins(content));
        self
    }

    /// Update existing key-value pair
    pub fn update(mut self, key: Vec<u8>, content: Vec<u8>) -> Self {
        let _ = self.actions.insert(key, UnseqEntryAction::Update(content));
        self
    }

    /// Delete existing key
    pub fn del(mut self, key: Vec<u8>) -> Self {
        let _ = self.actions.insert(key, UnseqEntryAction::Del);
        self
    }
}

impl From<UnseqEntryActions> for BTreeMap<Vec<u8>, UnseqEntryAction> {
    fn from(actions: UnseqEntryActions) -> Self {
        actions.actions
    }
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub enum EntryActions {
    Seq(SeqEntryActions),
    Unseq(UnseqEntryActions),
}

impl EntryActions {
    pub fn kind(&self) -> Kind {
        match self {
            EntryActions::Seq(_) => Kind::Seq,
            EntryActions::Unseq(_) => Kind::Unseq,
        }
    }
}

impl From<SeqEntryActions> for EntryActions {
    fn from(entry_actions: SeqEntryActions) -> Self {
        EntryActions::Seq(entry_actions)
    }
}

impl From<UnseqEntryActions> for EntryActions {
    fn from(entry_actions: UnseqEntryActions) -> Self {
        EntryActions::Unseq(entry_actions)
    }
}

pub type SeqEntries = BTreeMap<Vec<u8>, SeqValue>;
pub type UnseqEntries = BTreeMap<Vec<u8>, Vec<u8>>;

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub enum Entries {
    Seq(SeqEntries),
    Unseq(UnseqEntries),
}

impl From<SeqEntries> for Entries {
    fn from(entries: SeqEntries) -> Self {
        Entries::Seq(entries)
    }
}

impl From<UnseqEntries> for Entries {
    fn from(entries: UnseqEntries) -> Self {
        Entries::Unseq(entries)
    }
}

#[cfg(test)]
mod test {
    use super::{Address, XorName};
    use unwrap::unwrap;

    #[test]
    fn zbase32_encode_decode_mdata_address() {
        let name = XorName(rand::random());
        let address = Address::Seq { name, tag: 15000 };
        let encoded = address.encode_to_zbase32();
        let decoded = unwrap!(self::Address::decode_from_zbase32(&encoded));
        assert_eq!(address, decoded);
    }
}
