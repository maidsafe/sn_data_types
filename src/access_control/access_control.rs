// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#![allow(dead_code)]

use crate::shared_data::User;
use crate::PublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash};

/// The type of access to the native data structures.
//#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum AccessType {
    /// Writing to data structures.
    Write(DataStructWriteAccess),
    /// Reading from data structures.
    Read(DataStructReadAccess),
}

/// The various write operations that can be performed on a data struct.
//#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DataStructWriteAccess {
    /// Map write access.
    Map(MapWriteAccess),
    /// Sequence write access.
    Sequence(SequenceWriteAccess),
}

/// Reading of data structures.
//#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DataStructReadAccess {
    /// Map read access types.
    Map(ReadAccess),
    /// Sequence read access types.
    Sequence(ReadAccess),
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ReadAccess {
    /// Read from the data.
    Data,
    /// Read from owners.
    Owners,
    /// Read from permissions.
    Permissions,
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum HardErasureAccess {
    /// Hard-update existing values.
    HardUpdate,
    /// Hard-delete existing values.
    HardDelete,
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SequenceWriteAccess {
    /// Append new values.
    Append,
    /// Hard-delete and hard-update existing values.
    HardErasure(HardErasureAccess),
    /// Modify permissions for other users.
    ModifyPermissions(SequencePermissionModificationAccess),
}

/// The various write operations that can be performed on a Map.
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum MapWriteAccess {
    /// Insert new values.
    Insert,
    /// Soft-update existing values.
    Update,
    /// Soft-delete existing values.
    Delete,
    /// Hard-delete and hard-update existing values.
    HardErasure(HardErasureAccess),
    /// Modify permissions for other users.
    ModifyPermissions(MapPermissionModificationAccess),
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum MapPermissionModificationAccess {
    /// Modify permission to read from a Map.
    Read(ReadAccess),
    /// Modify permission to write to a Map.
    Write(MapWriteAccessModification),
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum MapWriteAccessModification {
    /// Modify permission to insert new values.
    Insert,
    /// Modify permission to soft-update existing values.
    Update,
    /// Modify permission to soft-delete existing values.
    Delete,
    /// Modify permission to hard-delete and hard-update existing values.
    HardErasure(HardErasureAccess),
    /// Modify permission to modify permissions for other users (yep, inception..).
    ModifyPermissions,
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SequencePermissionModificationAccess {
    /// Read from a Sequence.
    Read(ReadAccess),
    /// Write to a Sequence.
    Write(SequenceWriteAccessModification),
}

#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SequenceWriteAccessModification {
    /// Append new values.
    Append,
    /// Hard-delete and hard-update existing values.
    HardErasure(HardErasureAccess),
    /// Modify permissions for other users (yep, inception..).
    ModifyPermissions,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivatePermissions {
    state: BTreeMap<AccessType, bool>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PublicPermissions {
    state: BTreeMap<AccessType, bool>,
}

impl PrivatePermissions {
    pub fn new(state: BTreeMap<AccessType, bool>) -> Self {
        PrivatePermissions { state }
    }

    pub fn set(&mut self, state: BTreeMap<AccessType, bool>) {
        self.state = state;
    }

    pub fn is_allowed(self, access: &AccessType) -> bool {
        match self.state.get(access) {
            Some(true) => true,
            _ => false,
        }
    }
}

impl PublicPermissions {
    pub fn new(state: BTreeMap<AccessType, bool>) -> Self {
        PublicPermissions { state }
    }

    pub fn set(&mut self, state: BTreeMap<AccessType, bool>) {
        self.state = state; // todo: filter out Queries
    }

    /// Returns `Some(true)` if `access` is allowed and `Some(false)` if it's not.
    /// `None` means that `User::Anyone` permissions apply.
    pub fn is_allowed(self, access: &AccessType) -> Option<bool> {
        match access {
            AccessType::Read(_) => Some(true), // It's Public data, so it's always allowed to read it.
            _ => match self.state.get(access) {
                Some(true) => Some(true),
                Some(false) => Some(false),
                None => None,
            },
        }
    }
}

pub trait DataAccessControl: Clone + Eq + Ord + Hash + Serialize + DeserializeOwned {
    fn is_allowed(&self, user: &PublicKey, access: &AccessType) -> bool;
    fn expected_data_index(&self) -> u64;
    fn expected_owners_index(&self) -> u64;
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivateAccessControl {
    pub permissions: BTreeMap<PublicKey, PrivatePermissions>,
    /// The expected index of the data at the time this grant state change is to become valid.
    pub expected_data_index: u64,
    /// The expected index of the owners at the time this grant state is to become valid.
    pub expected_owners_index: u64,
}

impl PrivateAccessControl {
    pub fn permissions(&self) -> &BTreeMap<PublicKey, PrivatePermissions> {
        &self.permissions
    }
}

impl DataAccessControl for PrivateAccessControl {
    fn is_allowed(&self, user: &PublicKey, access: &AccessType) -> bool {
        match self.permissions.get(user) {
            Some(access_state) => access_state.clone().is_allowed(access),
            None => false,
        }
    }

    fn expected_data_index(&self) -> u64 {
        self.expected_data_index
    }

    fn expected_owners_index(&self) -> u64 {
        self.expected_owners_index
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PublicAccessControl {
    pub permissions: BTreeMap<User, PublicPermissions>,
    /// The expected index of the data at the time this grant state change is to become valid.
    pub expected_data_index: u64,
    /// The expected index of the owners at the time this grant state change is to become valid.
    pub expected_owners_index: u64,
}

impl PublicAccessControl {
    fn is_allowed_(&self, user: &User, access: &AccessType) -> Option<bool> {
        match self.permissions.get(user) {
            Some(state) => match state.clone().is_allowed(access) {
                Some(true) => Some(true),
                Some(false) => Some(false),
                None => None,
            },
            _ => None,
        }
    }

    pub fn permissions(&self) -> &BTreeMap<User, PublicPermissions> {
        &self.permissions
    }
}

impl DataAccessControl for PublicAccessControl {
    fn is_allowed(&self, user: &PublicKey, access: &AccessType) -> bool {
        match self.is_allowed_(&User::Specific(*user), access) {
            Some(true) => true,
            Some(false) => false,
            None => match self.is_allowed_(&User::Anyone, access) {
                Some(true) => true,
                _ => false,
            },
        }
    }

    fn expected_data_index(&self) -> u64 {
        self.expected_data_index
    }

    fn expected_owners_index(&self) -> u64 {
        self.expected_owners_index
    }
}
