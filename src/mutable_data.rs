// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::errors::{EntryError, Error};
use crate::request::{Request, Requester};
use crate::PublicKey;
use crate::XorName;
use bincode::serialize;
use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::mem;
use threshold_crypto::PublicKey as BlsPublicKey;

/// Mutable data that is unpublished on the network. This data can only be fetched by the owners or
/// those in the permissions fields with `Permission::Read` access.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct SeqMutableData {
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
    owners: BlsPublicKey,
}

/// A value in `Sequenced MutableData`
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct Value {
    /// Actual data.
    data: Vec<u8>,
    /// SHALL be incremented sequentially for any change to `data`.
    version: u64,
}

impl Value {
    pub fn new(data: Vec<u8>, version: u64) -> Self {
        Value { data, version }
    }
}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} :: {}",
            std::str::from_utf8(&self.data).unwrap(),
            self.version
        )
    }
}

/// Mutable data that is unpublished on the network. This data can only be fetch by the owners or
/// those in the permissions fields with `Permission::Read` access.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct UnseqMutableData {
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
    owners: BlsPublicKey,
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

/// Defines common functions in both sequenced and unsequenced types
pub trait MutableData {
    fn name(&self) -> &XorName;

    fn tag(&self) -> u64;

    fn version(&self) -> u64;

    fn owners(&self) -> &BlsPublicKey;

    fn keys(&self) -> BTreeSet<Vec<u8>>;

    fn permissions(&self) -> BTreeMap<PublicKey, PermissionSet>;

    fn user_permissions(&self, user: PublicKey) -> Result<&PermissionSet, Error>;

    fn check_permissions(&self, rpc: Request, requester: Requester) -> Result<(), Error>;

    fn set_user_permissions(
        &mut self,
        user: PublicKey,
        permissions: PermissionSet,
        version: u64,
    ) -> Result<(), Error>;

    fn del_user_permissions(&mut self, user: PublicKey, version: u64) -> Result<(), Error>;

    fn del_user_permissions_without_validation(&mut self, user: PublicKey, version: u64) -> bool;

    fn change_owner(&mut self, new_owner: BlsPublicKey, version: u64) -> Result<(), Error>;

    fn change_owner_without_validation(&mut self, new_owner: BlsPublicKey, version: u64) -> bool;

    fn is_action_allowed(&self, requester: &PublicKey, action: Action) -> bool;
}

macro_rules! impl_mutable_data {
    ($flavour:ident) => {
        impl $flavour {
            pub fn new(name: XorName, tag: u64, owners: BlsPublicKey) -> Self {
                Self {
                    name,
                    tag,
                    data: Default::default(),
                    permissions: Default::default(),
                    version: 0,
                    owners,
                }
            }

            /// Returns the Shell of the data
            pub fn shell(&self) -> Self {
                Self {
                    name: self.name,
                    tag: self.tag,
                    data: BTreeMap::new(),
                    permissions: self.permissions.clone(),
                    version: self.version,
                    owners: self.owners,
                }
            }
        }

        impl MutableData for $flavour {
            /// Returns the name of the Mutable data
            fn name(&self) -> &XorName {
                &self.name
            }

            /// Returns the tag type of the Mutable data
            fn tag(&self) -> u64 {
                self.tag
            }

            /// Returns the version of the Mutable data
            fn version(&self) -> u64 {
                self.version
            }

            /// Returns the owner key
            fn owners(&self) -> &BlsPublicKey {
                &self.owners
            }

            /// Returns all the keys in the data
            fn keys(&self) -> BTreeSet<Vec<u8>> {
                self.data.keys().cloned().collect()
            }

            /// Gets a complete list of permissions
            fn permissions(&self) -> BTreeMap<PublicKey, PermissionSet> {
                self.permissions.clone()
            }

            fn user_permissions(&self, user: PublicKey) -> Result<&PermissionSet, Error> {
                self.permissions.get(&user).ok_or(Error::NoSuchKey)
            }

            fn check_permissions(
                &self,
                request: Request,
                requester: Requester,
            ) -> Result<(), Error> {
                match requester {
                    Requester::Key(key) => {
                        check_permissions_for_key(self.user_permissions(key)?, request)
                    }
                    Requester::Owner(signature) => {
                        verify_ownership(signature, *self.owners(), request)
                    }
                }
            }

            /// Insert or update permissions for the provided user.
            fn set_user_permissions(
                &mut self,
                user: PublicKey,
                permissions: PermissionSet,
                version: u64,
            ) -> Result<(), Error> {
                if version != self.version + 1 {
                    return Err(Error::InvalidSuccessor(self.version));
                }
                let _prev = self.permissions.insert(user, permissions);
                self.version = version;
                Ok(())
            }

            /// Delete permissions for the provided user.
            fn del_user_permissions(&mut self, user: PublicKey, version: u64) -> Result<(), Error> {
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
            fn del_user_permissions_without_validation(
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
            fn change_owner(&mut self, new_owner: BlsPublicKey, version: u64) -> Result<(), Error> {
                if version != self.version + 1 {
                    return Err(Error::InvalidSuccessor(self.version));
                }
                self.owners = new_owner;
                self.version = version;
                Ok(())
            }

            /// Change the owner without performing any validation.
            fn change_owner_without_validation(
                &mut self,
                new_owner: BlsPublicKey,
                version: u64,
            ) -> bool {
                if version <= self.version {
                    return false;
                }

                self.owners = new_owner;
                self.version = version;
                true
            }

            fn is_action_allowed(&self, requester: &PublicKey, action: Action) -> bool {
                match self.permissions.get(requester) {
                    Some(perms) => perms.is_allowed(action),
                    None => false,
                }
            }
        }
    };
}
fn check_permissions_for_key(permissions: &PermissionSet, request: Request) -> Result<(), Error> {
    match request {
        Request::GetUnseqMData { .. }
        | Request::GetSeqMData { .. }
        | Request::GetUnseqMDataShell { .. }
        | Request::GetSeqMDataShell { .. }
        | Request::GetMDataVersion { .. }
        | Request::ListMDataKeys { .. }
        | Request::ListSeqMDataEntries { .. }
        | Request::ListSeqMDataValues { .. }
        | Request::GetSeqMDataValue { .. }
        | Request::ListUnseqMDataEntries { .. }
        | Request::GetUnseqMDataValue { .. }
        | Request::ListUnseqMDataValues { .. }
        | Request::ListMDataPermissions { .. }
        | Request::ListMDataUserPermissions { .. } => {
            if permissions.is_allowed(Action::Read) {
                Ok(())
            } else {
                Err(Error::AccessDenied)
            }
        }

        Request::SetMDataUserPermissions { .. } | Request::DelMDataUserPermissions { .. } => {
            if permissions.is_allowed(Action::ManagePermissions) {
                Ok(())
            } else {
                Err(Error::AccessDenied)
            }
        }

        // Mutation permissions are checked later
        Request::MutateSeqMDataEntries { .. } | Request::MutateUnseqMDataEntries { .. } => Ok(()),

        Request::DeleteMData { .. } => Err(Error::AccessDenied),

        _ => Err(Error::InvalidOperation),
    }
}

fn verify_ownership(
    signature: threshold_crypto::Signature,
    bls_key: BlsPublicKey,
    request: Request,
) -> Result<(), Error> {
    let message = serialize(&request).unwrap_or_default();
    if bls_key.verify(&signature, message) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

impl_mutable_data!(SeqMutableData);
impl_mutable_data!(UnseqMutableData);

/// Implements functions which are COMMON for both the mutable data
impl UnseqMutableData {
    /// Create a new Unsequenced Mutable Data with entries and permissions
    pub fn new_with_data(
        name: XorName,
        tag: u64,
        data: BTreeMap<Vec<u8>, Vec<u8>>,
        permissions: BTreeMap<PublicKey, PermissionSet>,
        owners: BlsPublicKey,
    ) -> Self {
        Self {
            name,
            tag,
            data,
            permissions,
            version: 0,
            owners,
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
    pub fn entries(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.data
    }

    /// Removes and returns all entries
    pub fn take_entries(&mut self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        mem::replace(&mut self.data, BTreeMap::new())
    }

    pub fn mutate_entries(
        &mut self,
        actions: BTreeMap<Vec<u8>, UnseqEntryAction>,
        request: Request,
        requester: Requester,
    ) -> Result<(), Error> {
        let (insert, update, delete) = actions.into_iter().fold(
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

        match requester {
            Requester::Key(key) => {
                if (!insert.is_empty() && !self.is_action_allowed(&key, Action::Insert))
                    || (!update.is_empty() && !self.is_action_allowed(&key, Action::Update))
                    || (!delete.is_empty() && !self.is_action_allowed(&key, Action::Delete))
                {
                    return Err(Error::AccessDenied);
                }
            }
            Requester::Owner(signature) => {
                if verify_ownership(signature, *self.owners(), request).is_err() {
                    return Err(Error::AccessDenied);
                }
            }
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
    /// Create a new Sequenced Mutable Data with entries and permissions
    pub fn new_with_data(
        name: XorName,
        tag: u64,
        data: BTreeMap<Vec<u8>, Value>,
        permissions: BTreeMap<PublicKey, PermissionSet>,
        owners: BlsPublicKey,
    ) -> Self {
        Self {
            name,
            tag,
            data,
            permissions,
            version: 0,
            owners,
        }
    }

    /// Returns a value by the given key
    pub fn get(&self, key: &[u8]) -> Option<&Value> {
        self.data.get(key)
    }

    /// Returns values of all entries
    pub fn values(&self) -> Vec<Value> {
        self.data.values().cloned().collect()
    }

    /// Returns all entries
    pub fn entries(&self) -> &BTreeMap<Vec<u8>, Value> {
        &self.data
    }

    /// Removes and returns all entries
    pub fn take_entries(&mut self) -> BTreeMap<Vec<u8>, Value> {
        mem::replace(&mut self.data, BTreeMap::new())
    }

    /// Mutates entries (key + value pairs) in bulk
    pub fn mutate_entries(
        &mut self,
        actions: BTreeMap<Vec<u8>, SeqEntryAction>,
        request: Request,
        requester: Requester,
    ) -> Result<(), Error> {
        // Deconstruct actions into inserts, updates, and deletes
        let (insert, update, delete) = actions.into_iter().fold(
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

        match requester {
            Requester::Key(key) => {
                if (!insert.is_empty() && !self.is_action_allowed(&key, Action::Insert))
                    || (!update.is_empty() && !self.is_action_allowed(&key, Action::Update))
                    || (!delete.is_empty() && !self.is_action_allowed(&key, Action::Delete))
                {
                    return Err(Error::AccessDenied);
                }
            }
            Requester::Owner(signature) => {
                if verify_ownership(signature, *self.owners(), request).is_err() {
                    return Err(Error::AccessDenied);
                }
            }
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

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub enum SeqEntryAction {
    /// Inserts a new Sequenced entry
    Ins(Value),
    /// Updates an entry with a new value and version
    Update(Value),
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
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct SeqEntryActions {
    actions: BTreeMap<Vec<u8>, SeqEntryAction>,
}

impl SeqEntryActions {
    /// Insert a new key-value pair
    pub fn ins(mut self, key: Vec<u8>, content: Vec<u8>, version: u64) -> Self {
        let _ = self.actions.insert(
            key,
            SeqEntryAction::Ins(Value {
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
            SeqEntryAction::Update(Value {
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

impl Into<BTreeMap<Vec<u8>, SeqEntryAction>> for SeqEntryActions {
    fn into(self) -> BTreeMap<Vec<u8>, SeqEntryAction> {
        self.actions
    }
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct UnseqEntryActions {
    actions: BTreeMap<Vec<u8>, UnseqEntryAction>,
}

impl UnseqEntryActions {
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

impl Into<BTreeMap<Vec<u8>, UnseqEntryAction>> for UnseqEntryActions {
    fn into(self) -> BTreeMap<Vec<u8>, UnseqEntryAction> {
        self.actions
    }
}
