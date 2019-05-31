// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

use crate::errors::{DataError, EntryError};
use crate::XorName;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::mem;
use std::vec::Vec;
use threshold_crypto::*;

/// Mutable data that is unpublished on the network. This data can only be fetch be the owners / those in the permissions fields with `Permission::Read` access.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct SequencedMutableData {
    /// Network address.
    name: XorName,
    /// Type tag.
    tag: u64,
    /// Key-Value semantics.
    data: BTreeMap<Vec<u8>, Value>,
    /// Maps an application key to a list of allowed or forbidden actions.
    permissions: BTreeMap<PublicKey, PermissionSet>,
    /// Version should be increased for any changes to MutableData fields except for data.
    version: u64,
    /// Contains a set of owners of this data. DataManagers enforce that a mutation request is
    /// coming from the MaidManager Authority of the Owner.
    owners: PublicKey,
}

/// A value in `Sequenced MutableData`
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct Value {
    /// Actual data.
    data: Vec<u8>,
    /// SHALL be incremented sequentially for any change to `data`.
    version: u64,
}

/// Mutable data that is unpublished on the network. This data can only be fetch be the owners / those in the permissions fields with `Permission::Read` access.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct UnsequencedMutableData {
    /// Network address.
    name: XorName,
    /// Type tag.
    tag: u64,
    /// Key-Value semantics.
    data: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Maps an application key to a list of allowed or forbidden actions.
    permissions: BTreeMap<PublicKey, PermissionSet>,
    /// Version should be increased for any changes to MutableData fields except for data.
    version: u64,
    /// Contains a set of owners of this data. DataManagers enforce that a mutation request is
    /// coming from the MaidManager Authority of the Owner.
    owners: PublicKey,
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
        self.permissions.insert(action);
        self
    }

    /// Deny the given action.
    pub fn deny(mut self, action: Action) -> Self {
        self.permissions.remove(&action);
        self
    }

    /// Is the given action allowed according to this permission set?
    pub fn is_allowed(&self, action: Action) -> bool {
        self.permissions.contains(&action)
    }
}

/// Set of Actions that can be performed on the Data
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Action {
    /// Permission to read entries
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

/// Implements functions which are COMMON for both the mutable data
impl UnsequencedMutableData {
    pub fn new(
        name: XorName,
        tag: u64,
        permissions: BTreeMap<PublicKey, PermissionSet>,
        data: BTreeMap<Vec<u8>, Vec<u8>>,
        owners: PublicKey,
    ) -> UnsequencedMutableData {
        UnsequencedMutableData {
            name,
            tag,
            data,
            permissions,
            version: 0,
            owners,
        }
    }

    /// Returns a value for the given key
    pub fn get(&self, requester: PublicKey, key: &[u8]) -> Result<Option<&Vec<u8>>, DataError> {
        if self.is_action_allowed(requester, Action::Read) {
            Ok(self.data.get(key))
        } else {
            Err(DataError::AccessDenied)
        }
    }

    /// Returns values of all entries
    pub fn values(&self, requester: PublicKey) -> Result<Vec<&Vec<u8>>, DataError> {
        if self.is_action_allowed(requester, Action::Read) {
            Ok(self.data.values().collect())
        } else {
            Err(DataError::AccessDenied)
        }
    }

    /// Returns all entries
    pub fn entries(&self, requester: PublicKey) -> Result<&BTreeMap<Vec<u8>, Vec<u8>>, DataError> {
        if self.is_action_allowed(requester, Action::Read) {
            Ok(&self.data)
        } else {
            Err(DataError::AccessDenied)
        }
    }

    /// Removes and returns all entries
    pub fn take_entries(
        &mut self,
        requester: PublicKey,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, DataError> {
        if self.is_action_allowed(requester, Action::Read)
            && self.is_action_allowed(requester, Action::Delete)
        {
            Ok(mem::replace(&mut self.data, BTreeMap::new()))
        } else {
            Err(DataError::AccessDenied)
        }
    }

    pub fn mutate_entries(
        &mut self,
        actions: BTreeMap<Vec<u8>, EntryAction>,
        requester: PublicKey,
    ) -> Result<(), DataError> {
        let (insert, update, delete) = actions.into_iter().fold(
            (
                BTreeMap::<Vec<u8>, Vec<u8>>::new(),
                BTreeMap::<Vec<u8>, Vec<u8>>::new(),
                BTreeMap::<Vec<u8>, u64>::new(),
            ),
            |(mut insert, mut update, mut delete), (key, item)| {
                match item {
                    EntryAction::InsUnseq(value) => {
                        let _ = insert.insert(key, value);
                    }
                    EntryAction::UpdateUnseq(value) => {
                        let _ = update.insert(key, value);
                    }
                    EntryAction::DelUnseq => {
                        delete.insert(key, 0 as u64);
                    }
                    _ => {}
                };
                (insert, update, delete)
            },
        );

        if (!insert.is_empty() && !self.is_action_allowed(requester, Action::Insert))
            || (!update.is_empty() && !self.is_action_allowed(requester, Action::Update))
            || (!delete.is_empty() && !self.is_action_allowed(requester, Action::Delete))
        {
            return Err(DataError::AccessDenied);
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

        for (key, _version) in delete {
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
            return Err(DataError::InvalidEntryActions(errors));
        }

        let _old_data = mem::replace(&mut self.data, new_data);

        Ok(())
    }

    /// Returns the name of the Mutable data
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Returns the tag type of the Mutable data
    pub fn tag(&self) -> u64 {
        self.tag
    }

    /// Returns the Shell of the data
    pub fn shell(&self) -> Self {
        UnsequencedMutableData {
            name: self.name,
            tag: self.tag,
            data: BTreeMap::new(),
            permissions: self.permissions.clone(),
            version: self.version,
            owners: self.owners,
        }
    }

    /// Returns the version of the Mutable data
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Returns the owner key
    pub fn owners(&self) -> &PublicKey {
        &self.owners
    }

    /// Returns all the keys in the data
    pub fn keys(&self) -> BTreeSet<&Vec<u8>> {
        self.data.keys().collect()
    }

    /// Gets a complete list of permissions
    pub fn permissions(&self) -> BTreeMap<PublicKey, PermissionSet> {
        self.permissions.clone()
    }

    pub fn user_permissions(&self, user: &PublicKey) -> Result<&PermissionSet, DataError> {
        self.permissions.get(user).ok_or(DataError::NoSuchKey)
    }

    /// Insert or update permissions for the provided user.
    pub fn set_user_permissions(
        &mut self,
        user: PublicKey,
        permissions: PermissionSet,
        version: u64,
        requester: PublicKey,
    ) -> Result<(), DataError> {
        if !self.is_action_allowed(requester, Action::ManagePermissions) {
            return Err(DataError::AccessDenied);
        }
        if version != self.version + 1 {
            return Err(DataError::InvalidSuccessor(self.version));
        }
        let _prev = self.permissions.insert(user, permissions);
        self.version = version;
        Ok(())
    }

    /// Delete permissions for the provided user.
    pub fn del_user_permissions(
        &mut self,
        user: &PublicKey,
        version: u64,
        requester: PublicKey,
    ) -> Result<(), DataError> {
        if !self.is_action_allowed(requester, Action::ManagePermissions) {
            return Err(DataError::AccessDenied);
        }
        if version != self.version + 1 {
            return Err(DataError::InvalidSuccessor(self.version));
        }
        if !self.permissions.contains_key(user) {
            return Err(DataError::NoSuchKey);
        }
        let _ = self.permissions.remove(user);
        self.version = version;
        Ok(())
    }

    /// Delete user permissions without performing any validation.
    pub fn del_user_permissions_without_validation(
        &mut self,
        user: &PublicKey,
        version: u64,
    ) -> bool {
        if version <= self.version {
            return false;
        }
        let _ = self.permissions.remove(user);
        self.version = version;
        true
    }

    /// Change owner of the mutable data.
    pub fn change_owner(&mut self, new_owner: PublicKey, version: u64) -> Result<(), DataError> {
        if version != self.version + 1 {
            return Err(DataError::InvalidSuccessor(self.version));
        }
        self.owners = new_owner;
        self.version = version;
        Ok(())
    }

    /// Change the owner without performing any validation.
    pub fn change_owner_without_validation(&mut self, new_owner: PublicKey, version: u64) -> bool {
        if version <= self.version {
            return false;
        }

        self.owners = new_owner;
        self.version = version;
        true
    }

    pub fn is_action_allowed(&self, requester: PublicKey, action: Action) -> bool {
        if self.owners == requester {
            return true;
        }
        match self.permissions.get(&requester) {
            Some(perms) => perms.clone().is_allowed(action),
            None => false,
        }
    }
}

/// Implements functions which are COMMON for both the mutable data
impl SequencedMutableData {
    pub fn new(
        name: XorName,
        tag: u64,
        permissions: BTreeMap<PublicKey, PermissionSet>,
        data: BTreeMap<Vec<u8>, Value>,
        owners: PublicKey,
    ) -> Self {
        SequencedMutableData {
            name,
            tag,
            data,
            permissions,
            version: 0,
            owners,
        }
    }

    /// Returns a value by the given key
    pub fn get(&self, requester: PublicKey, key: &[u8]) -> Result<Option<&Value>, DataError> {
        if self.owners == requester {
            Ok(self.data.get(key))
        } else {
            Err(DataError::AccessDenied)
        }
    }

    /// Returns values of all entries
    pub fn values(&self, requester: PublicKey) -> Result<Vec<&Value>, DataError> {
        if self.owners == requester {
            Ok(self.data.values().collect())
        } else {
            Err(DataError::AccessDenied)
        }
    }

    /// Returns all entries
    pub fn entries(&self, requester: PublicKey) -> Result<&BTreeMap<Vec<u8>, Value>, DataError> {
        if self.owners == requester {
            Ok(&self.data)
        } else {
            Err(DataError::AccessDenied)
        }
    }

    /// Removes and returns all entries
    pub fn take_entries(
        &mut self,
        requester: PublicKey,
    ) -> Result<BTreeMap<Vec<u8>, Value>, DataError> {
        if self.owners == requester {
            Ok(mem::replace(&mut self.data, BTreeMap::new()))
        } else {
            Err(DataError::AccessDenied)
        }
    }

    /// Mutates entries (key + value pairs) in bulk
    pub fn mutate_entries(
        &mut self,
        actions: BTreeMap<Vec<u8>, EntryAction>,
        requester: PublicKey,
    ) -> Result<(), DataError> {
        // Deconstruct actions into inserts, updates, and deletes
        let (insert, update, delete) = actions.into_iter().fold(
            (BTreeMap::new(), BTreeMap::new(), BTreeMap::new()),
            |(mut insert, mut update, mut delete), (key, item)| {
                match item {
                    EntryAction::InsSeq(value) => {
                        let _ = insert.insert(key, value);
                    }
                    EntryAction::UpdateSeq(value) => {
                        let _ = update.insert(key, value);
                    }
                    EntryAction::DelSeq(version) => {
                        let _ = delete.insert(key, version);
                    }
                    _ => {}
                };
                (insert, update, delete)
            },
        );

        if (!insert.is_empty() && !self.is_action_allowed(requester, Action::Insert))
            || (!update.is_empty() && !self.is_action_allowed(requester, Action::Update))
            || (!delete.is_empty() && !self.is_action_allowed(requester, Action::Delete))
        {
            return Err(DataError::AccessDenied);
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
            return Err(DataError::InvalidEntryActions(errors));
        }

        let _old_data = mem::replace(&mut self.data, new_data);

        Ok(())
    }

    /// Returns the name of the Mutable data
    pub fn name(&self) -> &XorName {
        &self.name
    }
    /// Returns the tag type of the Mutable data
    pub fn tag(&self) -> u64 {
        self.tag
    }
    /// Returns the Shell of the data
    pub fn shell(&self) -> Self {
        SequencedMutableData {
            name: self.name,
            tag: self.tag,
            data: BTreeMap::new(),
            permissions: self.permissions.clone(),
            version: self.version,
            owners: self.owners,
        }
    }
    /// Returns the version of the Mutable data
    pub fn version(&self) -> u64 {
        self.version
    }
    /// Returns the owner key
    pub fn owners(&self) -> &PublicKey {
        &self.owners
    }
    /// Returns all the keys in the data
    pub fn keys(&self) -> BTreeSet<&Vec<u8>> {
        self.data.keys().collect()
    }

    /// Gets a complete list of permissions
    pub fn permissions(&self) -> BTreeMap<PublicKey, PermissionSet> {
        self.permissions.clone()
    }

    pub fn user_permissions(&self, user: &PublicKey) -> Result<&PermissionSet, DataError> {
        self.permissions.get(user).ok_or(DataError::NoSuchKey)
    }

    /// Insert or update permissions for the provided user.
    pub fn set_user_permissions(
        &mut self,
        user: PublicKey,
        permissions: PermissionSet,
        version: u64,
        requester: PublicKey,
    ) -> Result<(), DataError> {
        if !self.is_action_allowed(requester, Action::ManagePermissions) {
            return Err(DataError::AccessDenied);
        }
        if version != self.version + 1 {
            return Err(DataError::InvalidSuccessor(self.version));
        }
        let _prev = self.permissions.insert(user, permissions);
        self.version = version;
        Ok(())
    }

    /// Delete permissions for the provided user.
    pub fn del_user_permissions(
        &mut self,
        user: &PublicKey,
        version: u64,
        requester: PublicKey,
    ) -> Result<(), DataError> {
        if !self.is_action_allowed(requester, Action::ManagePermissions) {
            return Err(DataError::AccessDenied);
        }
        if version != self.version + 1 {
            return Err(DataError::InvalidSuccessor(self.version));
        }
        if !self.permissions.contains_key(user) {
            return Err(DataError::NoSuchKey);
        }
        let _ = self.permissions.remove(user);
        self.version = version;
        Ok(())
    }

    /// Delete user permissions without performing any validation.
    pub fn del_user_permissions_without_validation(
        &mut self,
        user: &PublicKey,
        version: u64,
    ) -> bool {
        if version <= self.version {
            return false;
        }
        let _ = self.permissions.remove(user);
        self.version = version;
        true
    }

    /// Change owner of the mutable data.
    pub fn change_owner(&mut self, new_owner: PublicKey, version: u64) -> Result<(), DataError> {
        if version != self.version + 1 {
            return Err(DataError::InvalidSuccessor(self.version));
        }
        self.owners = new_owner;
        self.version = version;
        Ok(())
    }

    /// Change the owner without performing any validation.
    pub fn change_owner_without_validation(&mut self, new_owner: PublicKey, version: u64) -> bool {
        if version <= self.version {
            return false;
        }

        self.owners = new_owner;
        self.version = version;
        true
    }

    pub fn is_action_allowed(&self, requester: PublicKey, action: Action) -> bool {
        if self.owners == requester {
            return true;
        }
        match self.permissions.get(&requester) {
            Some(perms) => perms.clone().is_allowed(action),
            None => false,
        }
    }
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct MutableDataRef {
    // Address of a MutableData object on the network.
    name: XorName,
    // Type tag.
    tag: u64,
}

impl MutableDataRef {
    pub fn new(name: XorName, tag: u64) -> Self {
        MutableDataRef { name, tag }
    }

    pub fn name(&self) -> XorName {
        self.name
    }

    pub fn tag(&self) -> u64 {
        self.tag
    }
}

#[derive(Debug, Clone)]
pub enum EntryAction {
    /// Inserts a new Sequenced entry
    InsSeq(Value),
    /// Inserts a new Unsequenced entry
    InsUnseq(Vec<u8>),
    /// Updates an entry with a new value and version
    UpdateSeq(Value),
    /// Updates an entry with a new value
    UpdateUnseq(Vec<u8>),
    /// Deletes an entry by emptying its contents. Contains the version number
    DelSeq(u64),
    /// Deletes an entry by emptying its value
    DelUnseq,
}

/// Helper struct to build entry actions on `MutableData`
#[derive(Debug, Default, Clone)]
pub struct EntryActions {
    actions: BTreeMap<Vec<u8>, EntryAction>,
}

impl EntryActions {
    /// Create a helper to simplify construction of `MutableData` actions
    pub fn new() -> Self {
        Default::default()
    }

    /// Insert a new key-value pair
    pub fn ins_seq(mut self, key: Vec<u8>, content: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(
            key,
            EntryAction::InsSeq(Value {
                data: content,
                version,
            }),
        );
        self
    }

    /// Insert a new key-value pair
    pub fn ins_unseq(mut self, key: Vec<u8>, content: Vec<u8>) -> Self {
        let _ = self.actions.insert(key, EntryAction::InsUnseq(content));
        self
    }

    /// Update existing key-value pair
    pub fn update_seq(mut self, key: Vec<u8>, content: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(
            key,
            EntryAction::UpdateSeq(Value {
                data: content,
                version,
            }),
        );
        self
    }

    /// Update existing key-value pair
    pub fn update_unseq(mut self, key: Vec<u8>, content: Vec<u8>) -> Self {
        let _ = self.actions.insert(key, EntryAction::UpdateUnseq(content));
        self
    }

    /// Delete existing key
    pub fn del_seq(mut self, key: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(key, EntryAction::DelSeq(version));
        self
    }

    /// Delete existing key
    pub fn del_unseq(mut self, key: Vec<u8>) -> Self {
        let _ = self.actions.insert(key, EntryAction::DelUnseq);
        self
    }
}

impl Into<BTreeMap<Vec<u8>, EntryAction>> for EntryActions {
    fn into(self) -> BTreeMap<Vec<u8>, EntryAction> {
        self.actions
    }
}
