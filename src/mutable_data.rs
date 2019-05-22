// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use routing::XorName;
// use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::vec::Vec;
// use threshold_crypto::PublicKey;
use rust_sodium::crypto::sign::PublicKey;


#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum MutableDataKind {
    // Unsequenced, unpublished Mutable Data
    Unsequenced { data: BTreeMap<Vec<u8>, Value> },
    // Sequenced, unpublished Mutable Data
    Sequenced { data: BTreeMap<Vec<u8>, Vec<u8>> },
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Permission {
    Read,
    Insert,
    Update,
    Delete,
    ManagePermissions,
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct UnpublishedMutableData {
    /// Network address
    name: XorName,
    /// Type tag
    tag: u64,
    /// Key-Value semantics
    data: MutableDataKind,
    /// Maps an application key to a list of allowed or forbidden actions
    permissions: BTreeMap<User, BTreeSet<Permission>>,
    /// Version should be increased for any changes to MutableData fields except for data
    version: u64,
    /// Contains a set of owners of this data. DataManagers enforce that a mutation request is
    /// coming from the MaidManager Authority of the Owner.
    /// Currently limited to one owner to disallow multisig
    owners: PublicKey,
}

impl UnpublishedMutableData {
    pub fn new(
    name: XorName,
    tag: u64,
    data: MutableDataKind,
    permissions: BTreeMap<User, BTreeSet<Permission>>,
    version: u64,
    owners: PublicKey,
    ) -> Self {
        UnpublishedMutableData {
            name,
            tag,
            data,
            permissions,
            version,
            owners
        }
    }

    pub fn name(&self) -> XorName {
        self.name
    }

    pub fn tag(&self) -> u64 {
        self.tag
    }

    pub fn owners(&self) -> PublicKey {
        self.owners
    }

    pub fn permissions(&self) -> BTreeMap<User, BTreeSet<Permission>> {
        self.permissions.clone()
    }
 }

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct Value {
    /// Actual data.
    data: Vec<u8>,
    /// SHALL be incremented sequentially for any change to `data`.
    version: u64,
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct Permissions {
    permissions: BTreeMap<User, BTreeSet<Permission>>,
    /// The current index of the data when this permission change happened
    data_index: u64,
    /// The current index of the owners when this permission change happened
    owner_entry_index: u64,
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum User {
    Key(PublicKey),
    Anyone,
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
        MutableDataRef {
            name,
            tag
        }
    }

    pub fn name(&self) -> XorName {
        self.name
    }

    pub fn tag(&self) -> u64 {
        self.tag
    }
}
