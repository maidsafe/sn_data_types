// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::shared_types::User;
use crate::PublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash};

/// ===========================================================
///  Access control of data type instances and their content.
/// ===========================================================

/// The type of access to the native data structures.
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum AccessType {
    /// Read data, owners and permissions.
    Read,
    /// Append new values.
    Append,
    /// Insert new values.
    Insert,
    /// Soft-update existing values.
    Update,
    /// Soft-delete existing values.
    Delete,
    /// Hard-update existing values.
    HardUpdate,
    /// Hard-delete existing values.
    HardDelete,
    /// Modify permissions for other users.
    ModifyPermissions,
}

/// An AccessList consists of a list of users and their
/// corresponding access configuration, as of a specific
/// version of the data and the owners.
/// The two flavours of data types have different
/// variants of AccessList.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum AccessList {
    /// Denotes the public variant of an AccessList.
    Public(PublicAccessList),
    /// Denotes the private variant of an AccessList.
    Private(PrivateAccessList),
}

impl From<PrivateAccessList> for AccessList {
    fn from(list: PrivateAccessList) -> Self {
        AccessList::Private(list)
    }
}

impl From<PublicAccessList> for AccessList {
    fn from(list: PublicAccessList) -> Self {
        AccessList::Public(list)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum UserAccess {
    Public(PublicUserAccess),
    Private(PrivateUserAccess),
}

impl From<PrivateUserAccess> for UserAccess {
    fn from(access: PrivateUserAccess) -> Self {
        UserAccess::Private(access)
    }
}

impl From<PublicUserAccess> for UserAccess {
    fn from(access: PublicUserAccess) -> Self {
        UserAccess::Public(access)
    }
}

/// The access configuration to Private data, for a User.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivateUserAccess {
    status: BTreeMap<AccessType, bool>,
}

/// The access configuration to Public data, for a User.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PublicUserAccess {
    status: BTreeMap<AccessType, bool>,
}

impl PrivateUserAccess {
    /// The ctor can be instantiated with
    /// an access configuration.
    pub fn new(status: BTreeMap<AccessType, bool>) -> Self {
        PrivateUserAccess { status }
    }

    /// Determines if a specific access is
    /// allowed according to this user access
    /// configuration.
    pub fn is_allowed(&self, access: AccessType) -> bool {
        match self.status.get(&access) {
            Some(true) => true,
            _ => false,
        }
    }
}

impl PublicUserAccess {
    /// The ctor can be instantiated with
    /// an access configuration.
    pub fn new(status: BTreeMap<AccessType, bool>) -> Self {
        // todo: filter out Queries
        PublicUserAccess { status }
    }

    /// Returns `Some(true)` if `access` is allowed and `Some(false)` if it's not.
    /// `None` means that `User::Anyone` permissions apply.
    pub fn is_allowed(&self, access: AccessType) -> Option<bool> {
        match access {
            AccessType::Read => Some(true), // It's Public data, so it's always allowed to read it.
            _ => self.status.get(&access).copied(),
        }
    }
}

pub trait AccessListTrait: Clone + Eq + Ord + Hash + Serialize + DeserializeOwned {
    fn is_allowed(&self, user: &PublicKey, access: AccessType) -> bool;
    fn expected_data_version(&self) -> u64;
    fn expected_owners_version(&self) -> u64;
}

/// AccessList for Private data.
/// An AccessList consists of a list of users and their
/// corresponding access configuration, as of a specific
/// version of the data and the owners.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivateAccessList {
    /// The list of users and their access configuration.
    pub access_list: BTreeMap<PublicKey, PrivateUserAccess>,
    /// The expected index of the data at the time this grant status change is to become valid.
    pub expected_data_version: u64,
    /// The expected index of the owners at the time this grant status is to become valid.
    pub expected_owners_version: u64,
}

impl PrivateAccessList {
    /// Returns the list of users and their access configuration.
    pub fn access_list(&self) -> &BTreeMap<PublicKey, PrivateUserAccess> {
        &self.access_list
    }
}

impl AccessListTrait for PrivateAccessList {
    fn is_allowed(&self, user: &PublicKey, access: AccessType) -> bool {
        self.access_list
            .get(user)
            .map(|access_status| access_status.is_allowed(access))
            .unwrap_or(false)
    }

    fn expected_data_version(&self) -> u64 {
        self.expected_data_version
    }

    fn expected_owners_version(&self) -> u64 {
        self.expected_owners_version
    }
}

/// AccessList for Public data.
/// An AccessList consists of a list of users and their
/// corresponding access configuration, as of a specific
/// version of the data and the owners.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PublicAccessList {
    /// The list of users and their access configuration.
    pub access_list: BTreeMap<User, PublicUserAccess>,
    /// The expected index of the data at the time this grant status change is to become valid.
    pub expected_data_version: u64,
    /// The expected index of the owners at the time this grant status change is to become valid.
    pub expected_owners_version: u64,
}

impl PublicAccessList {
    fn is_allowed_(&self, user: &User, access: AccessType) -> Option<bool> {
        self.access_list
            .get(user)
            .map(|access_status| access_status.is_allowed(access))
            .unwrap_or(None)
    }

    /// Returns the list of users and their access configuration.
    pub fn access_list(&self) -> &BTreeMap<User, PublicUserAccess> {
        &self.access_list
    }
}

impl AccessListTrait for PublicAccessList {
    fn is_allowed(&self, user: &PublicKey, access: AccessType) -> bool {
        self.is_allowed_(&User::Specific(*user), access)
            .or_else(|| self.is_allowed_(&User::Anyone, access))
            .unwrap_or(false)
    }

    fn expected_data_version(&self) -> u64 {
        self.expected_data_version
    }

    fn expected_owners_version(&self) -> u64 {
        self.expected_owners_version
    }
}
