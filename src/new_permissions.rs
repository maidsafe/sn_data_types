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
use std::{
    collections::{BTreeMap, BTreeSet},
    hash::Hash,
};

/// A query or cmd on Map.
//#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Request {
    /// A cmd on a data type.
    Cmd(Cmd),
    /// A query a data type.
    Query(Query),
}

/// Set of Cmds that can be performed on a Map. Unless rejected, always mutates state.
//#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Cmd {
    /// Map permissions.
    Map(MapCmd),
    /// Sequence permissions.
    Sequence(SequenceCmd),
}

#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SequenceCmd {
    /// Permission to append new values.
    Append,
    /// Permission to hard-delete and hard-update existing values.
    HardErasure(HardErasureCmd),
    /// Permission to modify permissions for other users.
    ModifyPermissions(ModifyableSequencePermissions),
}

/// Set of Cmds that can be performed on a Map. Unless rejected, always mutates state.
#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum MapCmd {
    /// Permission to insert new values.
    Insert,
    /// Permission to soft-update existing values.
    Update,
    /// Permission to soft-delete existing values.
    Delete,
    /// Permission to hard-delete and hard-update existing values.
    HardErasure(HardErasureCmd),
    /// Permission to modify permissions for other users.
    ModifyPermissions(ModifyableMapPermissions),
}

#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ModifyableMapPermissions {
    /// Read from the Map data.
    ReadData,
    /// Read from Map owners.
    ReadOwners,
    /// Read from Map permissions.
    ReadPermissions,
    /// Permission to write to Map.
    Write(MapWrite),
}

#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum MapWrite {
    /// Permission to insert new values.
    Insert,
    /// Permission to soft-update existing values.
    Update,
    /// Permission to soft-delete existing values.
    Delete,
    /// Permission to hard-delete and hard-update existing values.
    HardErasure(HardErasureCmd),
    /// Permission to modify permissions for other users.
    ModifyPermissions, // hmm.. inception...
}

#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ModifyableSequencePermissions {
    /// Read from the data.
    ReadData,
    /// Read from owners.
    ReadOwners,
    /// Read from permissions.
    ReadPermissions,
    /// Permission to write to Map.
    Write(SequenceWrite),
}

#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SequenceWrite {
    /// Permission to append new values.
    Append,
    /// Permission to hard-delete and hard-update existing values.
    HardErasure(HardErasureCmd),
    /// Permission to modify permissions for other users.
    ModifyPermissions, // hmm.. inception...
}

#[derive(Clone, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum HardErasureCmd {
    /// Permission to hard-update existing values.
    HardUpdate,
    /// Permission to hard-delete existing values.
    HardDelete,
}

/// A query on Map, can never mutate state.
//#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Query {
    /// Query for Map types.
    Map(MapQuery),
    /// Query for Sequence types.
    Sequence(SequenceQuery),
}

/// A query on Map, can never mutate state.
//#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum MapQuery {
    /// Read from the data.
    ReadData,
    /// Read from owners.
    ReadOwners,
    /// Read from permissions.
    ReadPermissions,
}

/// A query on Map, can never mutate state.
//#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SequenceQuery {
    /// Read from the data.
    ReadData,
    /// Read from owners.
    ReadOwners,
    /// Read from permissions.
    ReadPermissions,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivatePermissionSet {
    permitted_requests: BTreeSet<Request>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PublicPermissionSet {
    permitted_requests: BTreeSet<Request>,
}

impl PrivatePermissionSet {
    pub fn new(permitted_requests: BTreeSet<Request>) -> Self {
        PrivatePermissionSet { permitted_requests }
    }

    pub fn set_permissions(&mut self, permitted_requests: BTreeSet<Request>) {
        self.permitted_requests = permitted_requests;
    }

    pub fn is_permitted(self, request: &Request) -> bool {
        self.permitted_requests.contains(request)
    }
}

impl PublicPermissionSet {
    pub fn new(permitted_requests: BTreeSet<Request>) -> Self {
        PublicPermissionSet { permitted_requests }
    }

    pub fn set_permissions(&mut self, permitted_requests: BTreeSet<Request>) {
        self.permitted_requests = permitted_requests; // todo: filter out Queries
    }

    pub fn is_permitted(self, request: &Request) -> bool {
        match request {
            Request::Query(_) => true, // It's Public data, so it's always allowed to read it.
            _ => self.permitted_requests.contains(request),
        }
    }
}

pub trait Permissions: Clone + Eq + Ord + Hash + Serialize + DeserializeOwned {
    fn is_permitted(&self, user: &PublicKey, request: &Request) -> bool;
    fn expected_data_index(&self) -> u64;
    fn expected_owners_index(&self) -> u64;
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivatePermissions {
    pub permissions: BTreeMap<PublicKey, PrivatePermissionSet>,
    /// The expected index of the data at the time this permission change is to become valid.
    pub expected_data_index: u64,
    /// The expected index of the owners at the time this permission change is to become valid.
    pub expected_owners_index: u64,
}

impl PrivatePermissions {
    pub fn permissions(&self) -> &BTreeMap<PublicKey, PrivatePermissionSet> {
        &self.permissions
    }
}

impl Permissions for PrivatePermissions {
    fn is_permitted(&self, user: &PublicKey, request: &Request) -> bool {
        match self.permissions.get(user) {
            Some(permissions) => permissions.clone().is_permitted(request),
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
pub struct PublicPermissions {
    pub permissions: BTreeMap<User, PublicPermissionSet>,
    /// The expected index of the data at the time this permission change is to become valid.
    pub expected_data_index: u64,
    /// The expected index of the owners at the time this permission change is to become valid.
    pub expected_owners_index: u64,
}

impl PublicPermissions {
    fn is_permitted_(&self, user: &User, request: &Request) -> bool {
        match self.permissions.get(user) {
            Some(permissions) => permissions.clone().is_permitted(request),
            _ => false,
        }
    }

    pub fn permissions(&self) -> &BTreeMap<User, PublicPermissionSet> {
        &self.permissions
    }
}

impl Permissions for PublicPermissions {
    fn is_permitted(&self, user: &PublicKey, request: &Request) -> bool {
        match self.is_permitted_(&User::Specific(*user), request) {
            true => true,
            false => self.is_permitted_(&User::Anyone, request),
        }
    }

    fn expected_data_index(&self) -> u64 {
        self.expected_data_index
    }

    fn expected_owners_index(&self) -> u64 {
        self.expected_owners_index
    }
}
