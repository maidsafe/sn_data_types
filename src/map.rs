// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#![allow(dead_code)]

use crate::permissions::{
    Permissions, PrivatePermissionSet, PrivatePermissions, PublicPermissionSet, PublicPermissions,
    Request,
};
use crate::shared_data::{
    to_absolute_index, to_absolute_range, Address, ExpectedIndices, Index, Key, Kind, KvPair,
    NonSentried, Owner, Sentried, User, Value,
};
use crate::{EntryError, Error, PublicKey, Result, XorName};
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    mem,
};

pub type PublicSentriedMap = Map<PublicPermissions, Sentried>;
pub type PublicMap = Map<PublicPermissions, NonSentried>;
pub type PrivateSentriedMap = Map<PrivatePermissions, Sentried>;
pub type PrivateMap = Map<PrivatePermissions, NonSentried>;
pub type DataHistories = BTreeMap<Key, Vec<StoredValue>>;
pub type Entries = Vec<DataEntry>;

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum MapPermissions {
    Public(PublicPermissions),
    Private(PrivatePermissions),
}

impl From<PrivatePermissions> for MapPermissions {
    fn from(permissions: PrivatePermissions) -> Self {
        MapPermissions::Private(permissions)
    }
}

impl From<PublicPermissions> for MapPermissions {
    fn from(permissions: PublicPermissions) -> Self {
        MapPermissions::Public(permissions)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default, Debug)]
pub struct DataEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl DataEntry {
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Self {
        Self { key, value }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct Map<P, S> {
    address: Address,
    data: DataHistories,
    permissions: Vec<P>,
    // This is the history of owners, with each entry representing an owner.  Each single owner
    // could represent an individual user, or a group of users, depending on the `PublicKey` type.
    owners: Vec<Owner>,
    /// Version should be increased for any changes to Map data entries,
    /// but not for permissions and owner changes.
    version: Option<u64>,
    _flavour: S,
}

/// Common methods for all `Map` flavours.
impl<P, S> Map<P, S>
where
    P: Permissions,
    S: Copy,
{
    /// Returns the data shell - that is - everything except the entries themselves.
    pub fn shell(&self, expected_data_index: impl Into<Index>) -> Result<Self> {
        let expected_data_index = to_absolute_index(
            expected_data_index.into(),
            self.expected_data_version().unwrap_or_default() as usize,
        )
        .ok_or(Error::NoSuchEntry)? as u64;

        let permissions = self
            .permissions
            .iter()
            .filter(|perm| perm.expected_data_index() <= expected_data_index)
            .cloned()
            .collect();

        let owners = self
            .owners
            .iter()
            .filter(|owner| owner.expected_data_index <= expected_data_index)
            .cloned()
            .collect();

        Ok(Self {
            address: self.address,
            data: BTreeMap::new(),
            permissions,
            owners,
            version: self.version,
            _flavour: self._flavour,
        })
    }

    /// Return a value for the given key (if it is present).
    pub fn get(&self, key: &Key) -> Option<&Value> {
        match self.data.get(key) {
            Some(history) => {
                match history.last() {
                    Some(StoredValue::Value(value)) => Some(value),
                    Some(StoredValue::Tombstone()) => None,
                    None => panic!(
                        "This is a bug! We are not supposed to have stored None under a key."
                    ), // should we panic here? Would like to return Error::NetworkOther(String)
                }
            }
            None => None,
        }
    }

    /// Return all data entries.
    pub fn data_entries(&self) -> Vec<DataEntry> {
        self.data
            .iter()
            .filter_map(move |(key, values)| match values.last() {
                Some(StoredValue::Value(val)) => Some(DataEntry {
                    key: key.clone(),
                    value: val.to_vec(),
                }),
                _ => None,
            })
            .collect()
    }

    /// Return the address of this Map.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Return the name of this Map.
    pub fn name(&self) -> &XorName {
        self.address.name()
    }

    /// Return the type tag of this Map.
    pub fn tag(&self) -> u64 {
        self.address.tag()
    }

    /// Return the expected data version.
    pub fn expected_data_version(&self) -> Option<u64> {
        self.version
    }

    /// Return the expected owners index.
    pub fn expected_owners_index(&self) -> u64 {
        self.owners.len() as u64
    }

    /// Return the expected permissions index.
    pub fn expected_permissions_index(&self) -> u64 {
        self.permissions.len() as u64
    }

    /// Get history of permissions within the range of indices specified.
    pub fn permission_history_range(&self, start: Index, end: Index) -> Option<&[P]> {
        let range = to_absolute_range(start, end, self.permissions.len())?;
        Some(&self.permissions[range])
    }

    /// Set permissions.
    /// The `Permissions` struct needs to contain the correct expected indices.
    pub fn set_permissions(&mut self, permissions: P, index: u64) -> Result<()> {
        if permissions.expected_data_index() != self.expected_data_version().unwrap_or_default() {
            return Err(Error::InvalidSuccessor(
                self.expected_data_version().unwrap_or_default(),
            ));
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

    /// Get permissions at index.
    pub fn permissions_at(&self, index: impl Into<Index>) -> Option<&P> {
        let index = to_absolute_index(index.into(), self.permissions.len())?;
        self.permissions.get(index)
    }

    pub fn is_permitted(&self, user: PublicKey, request: Request) -> bool {
        match self.owner_at(Index::FromEnd(1)) {
            Some(owner) => {
                if owner.public_key == user {
                    return true;
                }
            }
            None => (),
        }
        match self.permissions_at(Index::FromEnd(1)) {
            Some(permissions) => permissions.is_permitted(&user, &request),
            None => false,
        }
    }

    /// Get owner at index.
    pub fn owner_at(&self, index: impl Into<Index>) -> Option<&Owner> {
        let index = to_absolute_index(index.into(), self.owners.len())?;
        self.owners.get(index)
    }

    /// Get history of owners within the range of indices specified.
    pub fn owner_history_range(&self, start: Index, end: Index) -> Option<&[Owner]> {
        let range = to_absolute_range(start, end, self.owners.len())?;
        Some(&self.owners[range])
    }

    /// Set owner.
    pub fn set_owner(&mut self, owner: Owner, index: u64) -> Result<()> {
        if owner.expected_data_index != self.expected_data_version().unwrap_or_default() {
            return Err(Error::InvalidSuccessor(
                self.expected_data_version().unwrap_or_default(),
            ));
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

    /// Returns true if the user is the current owner, false if not.
    pub fn is_owner(&self, user: PublicKey) -> bool {
        match self.owner_at(Index::FromEnd(1)) {
            Some(owner) => user == owner.public_key,
            _ => false,
        }
    }

    pub fn indices(&self) -> ExpectedIndices {
        ExpectedIndices::new(
            self.expected_data_version().unwrap_or_default(),
            self.expected_owners_index(),
            self.expected_permissions_index(),
        )
    }
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub enum Cmd {
    /// Inserts a new entry
    Insert(KvPair),
    /// Updates an entry with a new value
    Update(KvPair),
    /// Deletes an entry
    Delete(Key),
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub enum SentriedCmd {
    /// Inserts a new entry
    Insert(SentriedKvPair),
    /// Updates an entry with a new value
    Update(SentriedKvPair),
    /// Deletes an entry
    Delete(SentriedKey),
}

pub enum MapTransaction {
    Commit(SentryOption),
    HardCommit(SentryOption),
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub enum SentryOption {
    AnyVersion(Transaction),
    ExpectVersion(SentriedTransaction),
}

pub type Transaction = Vec<Cmd>;

pub type ExpectedVersion = u64;
pub type SentriedKey = (Key, ExpectedVersion);
pub type SentriedKvPair = (KvPair, ExpectedVersion);
pub type SentriedTransaction = Vec<SentriedCmd>;

/// Common methods for NonSentried flavours.
impl<P: Permissions> Map<P, NonSentried> {
    /// Commit transaction.
    ///
    /// If the specified `expected_index` does not equal the entries count in data, an
    /// error will be returned.
    pub fn commit(&mut self, tx: Transaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: Operations = tx.into_iter().fold(
            (
                BTreeSet::<KvPair>::new(),
                BTreeSet::<KvPair>::new(),
                BTreeSet::<Key>::new(),
            ),
            |(mut insert, mut update, mut delete), cmd| {
                match cmd {
                    Cmd::Insert(kv_pair) => {
                        let _ = insert.insert(kv_pair);
                    }
                    Cmd::Update(kv_pair) => {
                        let _ = update.insert(kv_pair);
                    }
                    Cmd::Delete(key) => {
                        let _ = delete.insert(key);
                    }
                };
                (insert, update, delete)
            },
        );

        self.apply(operations)
    }

    fn apply(&mut self, tx: Operations) -> Result<()> {
        let (insert, update, delete) = tx;
        if insert.is_empty() && update.is_empty() && delete.is_empty() {
            return Err(Error::InvalidOperation);
        }
        let mut new_data = self.data.clone();
        let mut errors = BTreeMap::new();

        for (key, val) in insert {
            match new_data.entry(key) {
                Entry::Occupied(mut entry) => {
                    let history = entry.get_mut();
                    match history.last() {
                        Some(StoredValue::Value(_)) => {
                            let _ = errors.insert(
                                entry.key().clone(),
                                EntryError::EntryExists(entry.get().len() as u8),
                            );
                        }
                        Some(StoredValue::Tombstone()) => {
                            let _ = history.push(StoredValue::Value(val));
                            // todo: fix From impl
                        }
                        None => {
                            let _ = history.push(StoredValue::Value(val));
                            // todo: fix From impl
                        }
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = entry.insert(vec![StoredValue::Value(val)]); // todo: fix From impl
                }
            }
        }

        for (key, val) in update {
            match new_data.entry(key) {
                Entry::Occupied(mut entry) => {
                    let history = entry.get_mut();
                    match history.last() {
                        Some(StoredValue::Value(_)) => {
                            let _ = history.push(StoredValue::Value(val));
                            // todo: fix From impl
                        }
                        Some(StoredValue::Tombstone()) => {
                            let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                        }
                        None => panic!("This is a bug! We are not supposed to have stored None."), // should we panic here? Would like to return Error::NetworkOther(String)
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        for key in delete {
            match new_data.entry(key.clone()) {
                Entry::Occupied(mut entry) => {
                    let history = entry.get_mut();
                    match history.last() {
                        Some(StoredValue::Value(_)) => {
                            let _ = history.push(StoredValue::Tombstone());
                        }
                        Some(StoredValue::Tombstone()) => {
                            let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                        }
                        None => panic!("This is a bug! We are not supposed to have stored None."), // should we panic here? Would like to return Error::NetworkOther(String)
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

/// Common methods for Sentried flavours.
impl<P: Permissions> Map<P, Sentried> {
    /// Commit transaction.
    ///
    /// If the specified `expected_index` does not equal the entries count in data, an
    /// error will be returned.
    pub fn commit(&mut self, tx: SentriedTransaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: SentriedOperations = tx.into_iter().fold(
            (BTreeSet::new(), BTreeSet::new(), BTreeSet::new()),
            |(mut insert, mut update, mut delete), cmd| {
                match cmd {
                    SentriedCmd::Insert(sentried_kvpair) => {
                        let _ = insert.insert(sentried_kvpair);
                    }
                    SentriedCmd::Update(sentried_kvpair) => {
                        let _ = update.insert(sentried_kvpair);
                    }
                    SentriedCmd::Delete(sentried_key) => {
                        let _ = delete.insert(sentried_key);
                    }
                };
                (insert, update, delete)
            },
        );

        self.apply(operations)
    }

    fn apply(&mut self, tx: SentriedOperations) -> Result<()> {
        let (insert, update, delete) = tx;
        let op_count = insert.len() + update.len() + delete.len();
        if op_count == 0 {
            return Err(Error::InvalidOperation);
        }
        let mut new_data = self.data.clone();
        let mut errors = BTreeMap::new();

        for ((key, val), version) in insert {
            match new_data.entry(key) {
                Entry::Occupied(mut entry) => match entry.get().last() {
                    Some(value) => match value {
                        StoredValue::Tombstone() => {
                            let expected_version = entry.get().len() as u64;
                            if version == expected_version {
                                let _ = &mut entry.get_mut().push(StoredValue::Value(val));
                            } else {
                                let _ = errors.insert(
                                    entry.key().clone(),
                                    EntryError::InvalidSuccessor(expected_version as u8),
                                );
                            }
                        }
                        StoredValue::Value(_) => {
                            let _ = errors.insert(
                                entry.key().clone(),
                                EntryError::EntryExists(entry.get().len() as u8),
                            );
                        }
                    },
                    None => panic!("This is a bug! We are not supposed to have stored None."), // should we panic here? Would like to return Error::NetworkOther(String)
                },
                Entry::Vacant(entry) => {
                    if version == 0 {
                        let _ = entry.insert(vec![StoredValue::Value(val)]);
                    } else {
                        let _ = errors.insert(entry.key().clone(), EntryError::InvalidSuccessor(0));
                    }
                }
            }
        }

        for ((key, val), version) in update {
            match new_data.entry(key) {
                Entry::Occupied(mut entry) => {
                    match entry.get().last() {
                        Some(StoredValue::Value(_)) => {
                            let history = entry.get_mut();
                            let expected_version = history.len() as u64;
                            if version == expected_version {
                                let _ = history.push(StoredValue::Value(val));
                            } else {
                                let _ = errors.insert(
                                    entry.key().clone(),
                                    EntryError::InvalidSuccessor(expected_version as u8),
                                );
                            }
                        }
                        Some(StoredValue::Tombstone()) => {
                            let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                        }
                        None => panic!("This is a bug! We are not supposed to have stored None."), // should we panic here? Would like to return Error::NetworkOther(String)
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        for (key, version) in delete {
            match new_data.entry(key.clone()) {
                Entry::Occupied(mut entry) => {
                    let history = entry.get_mut();
                    match history.last() {
                        Some(StoredValue::Value(_)) => {
                            let expected_version = history.len() as u64;
                            if version == expected_version {
                                let _ = history.push(StoredValue::Tombstone());
                            } else {
                                let _ = errors.insert(
                                    entry.key().clone(),
                                    EntryError::InvalidSuccessor(expected_version as u8),
                                );
                            }
                        }
                        Some(StoredValue::Tombstone()) => {
                            let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                        }
                        None => panic!("This is a bug! We are not supposed to have stored None."), // should we panic here? Would like to return Error::NetworkOther(String)
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

        self.version = Some(self.version.unwrap() + 1);
        let _old_data = mem::replace(&mut self.data, new_data);
        Ok(())
    }
}

type Operations = (BTreeSet<KvPair>, BTreeSet<KvPair>, BTreeSet<Key>);
type SentriedOperations = (
    BTreeSet<SentriedKvPair>,
    BTreeSet<SentriedKvPair>,
    BTreeSet<SentriedKey>,
);

enum OperationSet {
    Private(Operations),
    Public(Operations),
    PrivateSentried(SentriedOperations),
    PublicSentried(SentriedOperations),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StoredValue {
    Value(Value),
    Tombstone(),
}

/// Public + Sentried
impl Map<PublicPermissions, Sentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PublicSentried { name, tag },
            data: BTreeMap::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
            version: Some(0),
            _flavour: Sentried,
        }
    }
}

impl Debug for Map<PublicPermissions, Sentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicSentriedMap {:?}", self.name())
    }
}

/// Public + NonSentried
impl Map<PublicPermissions, NonSentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Public { name, tag },
            data: BTreeMap::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
            version: None,
            _flavour: NonSentried,
        }
    }
}

impl Debug for Map<PublicPermissions, NonSentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicMap {:?}", self.name())
    }
}

/// Private + Sentried
impl Map<PrivatePermissions, Sentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PrivateSentried { name, tag },
            data: BTreeMap::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
            version: Some(0),
            _flavour: Sentried,
        }
    }

    /// Commit transaction.
    ///
    /// If the specified `expected_index` does not equal the entries count in data, an
    /// error will be returned.
    pub fn hard_commit(&mut self, tx: SentriedTransaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: SentriedOperations = tx.into_iter().fold(
            (BTreeSet::new(), BTreeSet::new(), BTreeSet::new()),
            |(mut insert, mut update, mut delete), cmd| {
                match cmd {
                    SentriedCmd::Insert(sentried_kvpair) => {
                        let _ = insert.insert(sentried_kvpair);
                    }
                    SentriedCmd::Update(sentried_kvpair) => {
                        let _ = update.insert(sentried_kvpair);
                    }
                    SentriedCmd::Delete(sentried_key) => {
                        let _ = delete.insert(sentried_key);
                    }
                };
                (insert, update, delete)
            },
        );

        self.hard_apply(operations)
    }

    fn hard_apply(&mut self, operations: SentriedOperations) -> Result<()> {
        let (insert, update, delete) = operations;
        let op_count = insert.len() + update.len() + delete.len();
        if op_count == 0 {
            return Err(Error::InvalidOperation);
        }
        let mut new_data = self.data.clone();
        let mut errors = BTreeMap::new();

        for ((key, val), version) in insert {
            match new_data.entry(key.clone()) {
                Entry::Occupied(mut entry) => {
                    let history = entry.get_mut();
                    match history.last() {
                        Some(StoredValue::Value(_)) => {
                            let _ = errors.insert(
                                entry.key().clone(),
                                EntryError::EntryExists(entry.get().len() as u8),
                            );
                        }
                        Some(StoredValue::Tombstone()) => {
                            if version == history.len() as u64 {
                                let _ = history.push(StoredValue::Value(val));
                            } else {
                                let _ = errors.insert(
                                    key,
                                    EntryError::InvalidSuccessor(entry.get().len() as u8), // I assume we are here letting caller know what successor is expected
                                );
                            }
                        }
                        None => {
                            panic!("This would be a bug! We are not supposed to store empty vecs!")
                        }
                    }
                }
                Entry::Vacant(entry) => {
                    if version == 0 {
                        // still make sure the val.version == 0
                        let _ = entry.insert(vec![StoredValue::Value(val)]);
                    } else {
                        let _ = errors.insert(
                            key,
                            EntryError::InvalidSuccessor(0), // I assume we are here letting caller know what successor is expected
                        );
                    }
                }
            }
        }

        // overwrites old data, while also incrementing version
        for ((key, val), version) in update {
            match new_data.entry(key) {
                Entry::Occupied(mut entry) => {
                    let history = entry.get_mut();
                    match history.last() {
                        Some(StoredValue::Value(_)) => {
                            let expected_version = history.len() as u64;
                            if version == expected_version {
                                let _old_value = mem::replace(
                                    &mut history.last(),
                                    Some(&StoredValue::Tombstone()),
                                ); // remove old value, as to properly owerwrite on update, but keep the index, as to increment history length (i.e. version)
                                let _ = history.push(StoredValue::Value(val));
                            } else {
                                let _ = errors.insert(
                                    entry.key().clone(),
                                    EntryError::InvalidSuccessor(expected_version as u8), // I assume we are here letting caller know what successor is expected
                                );
                            }
                        }
                        Some(StoredValue::Tombstone()) => {
                            let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                        }
                        None => {
                            panic!("This would be a bug! We are not supposed to store empty vecs!")
                        }
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        // removes old data, while also incrementing version
        for (key, version) in delete {
            match new_data.entry(key.clone()) {
                Entry::Occupied(mut entry) => {
                    let history = entry.get_mut();
                    match history.last() {
                        Some(StoredValue::Value(_)) => {
                            let expected_version = history.len() as u64;
                            if version == expected_version {
                                let _old_value = mem::replace(
                                    &mut history.last(),
                                    Some(&StoredValue::Tombstone()),
                                ); // remove old value, as to properly delete, but keep the index, as to increment history length (i.e. version)
                                let _ = history.push(StoredValue::Tombstone());
                            } else {
                                let _ = errors.insert(
                                    entry.key().clone(),
                                    EntryError::InvalidSuccessor(expected_version as u8), // I assume we are here letting caller know what successor is expected
                                );
                            }
                        }
                        Some(StoredValue::Tombstone()) => {
                            let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                        }
                        None => {
                            panic!("This would be a bug! We are not supposed to store empty vecs!")
                        }
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

        self.version = Some(self.version.unwrap() + 1);
        let _old_data = mem::replace(&mut self.data, new_data);
        Ok(())
    }
}

impl Debug for Map<PrivatePermissions, Sentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateSentriedMap {:?}", self.name())
    }
}

/// Private + NonSentried
impl Map<PrivatePermissions, NonSentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Private { name, tag },
            data: BTreeMap::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
            version: None,
            _flavour: NonSentried,
        }
    }

    /// Commit transaction that potentially hard deletes data.
    ///
    /// If the specified `expected_index` does not equal the entries count in data, an
    /// error will be returned.
    pub fn hard_commit(&mut self, tx: Transaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: Operations = tx.into_iter().fold(
            (
                BTreeSet::<KvPair>::new(),
                BTreeSet::<KvPair>::new(),
                BTreeSet::<Key>::new(),
            ),
            |(mut insert, mut update, mut delete), cmd| {
                match cmd {
                    Cmd::Insert(kv_pair) => {
                        let _ = insert.insert(kv_pair);
                    }
                    Cmd::Update(kv_pair) => {
                        let _ = update.insert(kv_pair);
                    }
                    Cmd::Delete(key) => {
                        let _ = delete.insert(key);
                    }
                };
                (insert, update, delete)
            },
        );

        self.hard_apply(operations)
    }

    fn hard_apply(&mut self, operations: Operations) -> Result<()> {
        let (insert, update, delete) = operations;
        let op_count = insert.len() + update.len() + delete.len();
        if op_count == 0 {
            return Err(Error::InvalidOperation);
        }
        let mut new_data = self.data.clone();
        let mut errors = BTreeMap::new();

        for (key, val) in insert {
            match new_data.entry(key.clone()) {
                Entry::Occupied(mut entry) => {
                    let history = entry.get_mut();
                    match history.last() {
                        Some(StoredValue::Value(_)) => {
                            let _ = errors.insert(
                                entry.key().clone(),
                                EntryError::EntryExists(entry.get().len() as u8),
                            );
                        }
                        Some(StoredValue::Tombstone()) => {
                            let _ = history.push(StoredValue::Value(val));
                        }
                        None => {
                            panic!("This would be a bug! We are not supposed to store empty vecs!")
                        }
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = entry.insert(vec![StoredValue::Value(val)]);
                }
            }
        }

        // hard-updates old data
        for (key, val) in update {
            match new_data.entry(key) {
                Entry::Occupied(mut entry) => {
                    let history = entry.get_mut();
                    match history.last() {
                        Some(StoredValue::Value(_)) => {
                            let _old_value =
                                mem::replace(&mut history.last(), Some(&StoredValue::Tombstone())); // remove old value, as to properly owerwrite on update, but keep the index, as to increment history length (i.e. version)
                            let _ = history.push(StoredValue::Value(val));
                        }
                        Some(StoredValue::Tombstone()) => {
                            let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                        }
                        None => {
                            panic!("This would be a bug! We are not supposed to store empty vecs!")
                        }
                    }
                }
                Entry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        // hard-deletes old data
        for key in delete {
            match new_data.entry(key.clone()) {
                Entry::Occupied(mut entry) => {
                    let history = entry.get_mut();
                    match history.last() {
                        Some(StoredValue::Value(_)) => {
                            let _old_value =
                                mem::replace(&mut history.last(), Some(&StoredValue::Tombstone())); // remove old value, as to properly delete, but keep the index, as to increment history length (i.e. version)
                            let _ = history.push(StoredValue::Tombstone());
                        }
                        Some(StoredValue::Tombstone()) => {
                            let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                        }
                        None => {
                            panic!("This would be a bug! We are not supposed to store empty vecs!")
                        }
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

impl Debug for Map<PrivatePermissions, NonSentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateMap {:?}", self.name())
    }
}

/// Object storing a Map variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    PublicSentried(PublicSentriedMap),
    Public(PublicMap),
    PrivateSentried(PrivateSentriedMap),
    Private(PrivateMap),
}

impl Data {
    pub fn is_permitted(&self, request: Request, user: PublicKey) -> bool {
        match (self, request) {
            (Data::PublicSentried(_), Request::Query(_)) | (Data::Public(_), Request::Query(_)) => {
                return true
            }
            _ => (),
        }
        match self {
            Data::PublicSentried(data) => data.is_permitted(user, request),
            Data::Public(data) => data.is_permitted(user, request),
            Data::PrivateSentried(data) => data.is_permitted(user, request),
            Data::Private(data) => data.is_permitted(user, request),
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

    pub fn expected_data_index(&self) -> u64 {
        match self {
            Data::PublicSentried(data) => data.expected_data_version().unwrap_or_default(),
            Data::Public(data) => data.expected_data_version().unwrap_or_default(),
            Data::PrivateSentried(data) => data.expected_data_version().unwrap_or_default(),
            Data::Private(data) => data.expected_data_version().unwrap_or_default(),
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

    // pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
    //     match self {
    //         Data::PublicSentried(data) => data.in_range(start, end),
    //         Data::Public(data) => data.in_range(start, end),
    //         Data::PrivateSentried(data) => data.in_range(start, end),
    //         Data::Private(data) => data.in_range(start, end),
    //     }
    // }

    pub fn get(&self, key: &Key) -> Option<&Value> {
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

    pub fn owner_at(&self, index: impl Into<Index>) -> Option<&Owner> {
        match self {
            Data::PublicSentried(data) => data.owner_at(index),
            Data::Public(data) => data.owner_at(index),
            Data::PrivateSentried(data) => data.owner_at(index),
            Data::Private(data) => data.owner_at(index),
        }
    }

    pub fn is_owner(&self, user: PublicKey) -> bool {
        match self {
            Data::PublicSentried(data) => data.is_owner(user),
            Data::Public(data) => data.is_owner(user),
            Data::PrivateSentried(data) => data.is_owner(user),
            Data::Private(data) => data.is_owner(user),
        }
    }

    pub fn public_user_permissions_at(
        &self,
        user: User,
        index: impl Into<Index>,
    ) -> Result<PublicPermissionSet> {
        self.public_permissions_at(index)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    pub fn private_user_permissions_at(
        &self,
        user: PublicKey,
        index: impl Into<Index>,
    ) -> Result<PrivatePermissionSet> {
        self.private_permissions_at(index)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    pub fn public_permissions_at(&self, index: impl Into<Index>) -> Result<&PublicPermissions> {
        let permissions = match self {
            Data::PublicSentried(data) => data.permissions_at(index),
            Data::Public(data) => data.permissions_at(index),
            _ => return Err(Error::NoSuchData),
        };
        permissions.ok_or(Error::NoSuchEntry)
    }

    pub fn private_permissions_at(&self, index: impl Into<Index>) -> Result<&PrivatePermissions> {
        let permissions = match self {
            Data::PrivateSentried(data) => data.permissions_at(index),
            Data::Private(data) => data.permissions_at(index),
            _ => return Err(Error::NoSuchData),
        };
        permissions.ok_or(Error::NoSuchEntry)
    }

    pub fn shell(&self, index: impl Into<Index>) -> Result<Self> {
        match self {
            Data::PublicSentried(map) => map.shell(index).map(Data::PublicSentried),
            Data::Public(map) => map.shell(index).map(Data::Public),
            Data::PrivateSentried(map) => map.shell(index).map(Data::PrivateSentried),
            Data::Private(map) => map.shell(index).map(Data::Private),
        }
    }

    /// Commits transaction.
    pub fn commit(&mut self, tx: MapTransaction) -> Result<()> {
        match self {
            Data::PrivateSentried(map) => match tx {
                MapTransaction::Commit(options) => {
                    if let SentryOption::ExpectVersion(stx) = options {
                        return map.commit(stx);
                    }
                }
                MapTransaction::HardCommit(options) => {
                    if let SentryOption::ExpectVersion(stx) = options {
                        return map.hard_commit(stx);
                    }
                }
            },
            Data::Private(map) => match tx {
                MapTransaction::Commit(options) => {
                    if let SentryOption::AnyVersion(tx) = options {
                        return map.commit(tx);
                    }
                }
                MapTransaction::HardCommit(options) => {
                    if let SentryOption::AnyVersion(tx) = options {
                        return map.hard_commit(tx);
                    }
                }
            },
            Data::PublicSentried(map) => match tx {
                MapTransaction::Commit(options) => {
                    if let SentryOption::ExpectVersion(stx) = options {
                        return map.commit(stx);
                    }
                }
                _ => return Err(Error::InvalidOperation),
            },
            Data::Public(map) => match tx {
                MapTransaction::Commit(options) => {
                    if let SentryOption::AnyVersion(tx) = options {
                        return map.commit(tx);
                    }
                }
                _ => return Err(Error::InvalidOperation),
            },
        }

        Err(Error::InvalidOperation)
    }
}

impl From<PublicSentriedMap> for Data {
    fn from(data: PublicSentriedMap) -> Self {
        Data::PublicSentried(data)
    }
}

impl From<PublicMap> for Data {
    fn from(data: PublicMap) -> Self {
        Data::Public(data)
    }
}

impl From<PrivateSentriedMap> for Data {
    fn from(data: PrivateSentriedMap) -> Self {
        Data::PrivateSentried(data)
    }
}

impl From<PrivateMap> for Data {
    fn from(data: PrivateMap) -> Self {
        Data::Private(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{
        CmdType, HardErasureCmd, MapCmd, MapQuery, MapWrite, ModifyableMapPermissions, QueryType,
    };
    use std::collections::BTreeMap;
    use threshold_crypto::SecretKey;
    use unwrap::{unwrap, unwrap_err};

    pub fn get_insert_cmd() -> Request {
        Request::Cmd(CmdType::Map(MapCmd::Insert))
    }

    fn get_read_query(query: MapQuery) -> Request {
        Request::Query(QueryType::Map(query))
    }

    fn get_full_read_permissions() -> Vec<Request> {
        vec![
            Request::Query(QueryType::Map(MapQuery::ReadData)),
            Request::Query(QueryType::Map(MapQuery::ReadOwners)),
            Request::Query(QueryType::Map(MapQuery::ReadPermissions)),
        ]
    }

    fn get_modify_permissions(permission: ModifyableMapPermissions) -> Request {
        Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(permission)))
    }

    fn get_full_modify_permissions() -> Vec<Request> {
        vec![
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::ReadData,
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::ReadOwners,
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::ReadPermissions,
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::Write(MapWrite::Insert),
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::Write(MapWrite::Update),
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::Write(MapWrite::Delete),
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::Write(MapWrite::ModifyPermissions),
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::Write(MapWrite::HardErasure(HardErasureCmd::HardDelete)),
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::Write(MapWrite::HardErasure(HardErasureCmd::HardUpdate)),
            ))),
        ]
    }

    pub fn assert_read_permitted(data: &Data, public_key: PublicKey, permitted: bool) {
        assert_eq!(
            data.is_permitted(get_read_query(MapQuery::ReadData), public_key),
            permitted
        );
        assert_eq!(
            data.is_permitted(get_read_query(MapQuery::ReadOwners), public_key),
            permitted
        );
        assert_eq!(
            data.is_permitted(get_read_query(MapQuery::ReadPermissions), public_key),
            permitted
        );
    }

    pub fn assert_modify_permissions_permitted(
        data: &Data,
        public_key: PublicKey,
        permitted: bool,
    ) {
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::ReadData),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::ReadOwners),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::ReadPermissions),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::Write(MapWrite::Insert)),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::Write(MapWrite::Update)),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::Write(MapWrite::Delete)),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::Write(
                    MapWrite::ModifyPermissions
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::Write(MapWrite::HardErasure(
                    HardErasureCmd::HardDelete
                ))),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::Write(MapWrite::HardErasure(
                    HardErasureCmd::HardUpdate
                ))),
                public_key
            ),
            permitted
        );
    }

    #[test]
    fn insert() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let insert_1 = SentriedCmd::Insert(((vec![1], vec![0]), 0));
        let insert_2 = SentriedCmd::Insert(((vec![2], vec![0]), 0));
        let tx = vec![insert_0, insert_1, insert_2];
        unwrap!(data.commit(tx));

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let insert_1 = SentriedCmd::Insert(((vec![1], vec![0]), 0));
        let insert_2 = SentriedCmd::Insert(((vec![2], vec![0]), 0));
        let tx = vec![insert_0, insert_1, insert_2];
        unwrap!(data.commit(tx));

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let insert_1 = Cmd::Insert((vec![1], vec![0]));
        let insert_2 = Cmd::Insert((vec![2], vec![0]));
        let tx = vec![insert_0, insert_1, insert_2];
        unwrap!(data.commit(tx));

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let insert_1 = Cmd::Insert((vec![1], vec![0]));
        let insert_2 = Cmd::Insert((vec![2], vec![0]));
        let tx = vec![insert_0, insert_1, insert_2];
        unwrap!(data.commit(tx))
    }

    #[test]
    fn update() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let update_2 = SentriedCmd::Update(((vec![0], vec![0]), 2));
        let tx = vec![insert_0, update_1, update_2];
        unwrap!(data.commit(tx));

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let update_2 = SentriedCmd::Update(((vec![0], vec![0]), 2));
        let tx = vec![insert_0, update_1, update_2];
        unwrap!(data.commit(tx));

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let update_1 = Cmd::Update((vec![0], vec![0]));
        let update_2 = Cmd::Update((vec![0], vec![0]));
        let tx = vec![insert_0, update_1, update_2];
        unwrap!(data.commit(tx));

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let update_1 = Cmd::Update((vec![0], vec![0]));
        let update_2 = Cmd::Update((vec![0], vec![0]));
        let tx = vec![insert_0, update_1, update_2];
        unwrap!(data.commit(tx))
    }

    #[test]
    fn delete() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx));

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx));

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let update_1 = Cmd::Update((vec![0], vec![0]));
        let delete_2 = Cmd::Delete(vec![0]);
        let tx = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx));

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let update_1 = Cmd::Update((vec![0], vec![0]));
        let delete_2 = Cmd::Delete(vec![0]);
        let tx = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx))
    }

    #[test]
    fn re_insert() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx_0 = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx_0));
        let insert_3 = SentriedCmd::Insert(((vec![0], vec![0]), 3));
        let tx_1 = vec![insert_3];
        unwrap!(data.commit(tx_1));

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx_0 = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx_0));
        let insert_3 = SentriedCmd::Insert(((vec![0], vec![0]), 3));
        let tx_1 = vec![insert_3];
        unwrap!(data.commit(tx_1));

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let update_1 = Cmd::Update((vec![0], vec![0]));
        let delete_2 = Cmd::Delete(vec![0]);
        let tx_0 = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx_0));
        let insert_3 = Cmd::Insert((vec![0], vec![0]));
        let tx_1 = vec![insert_3];
        unwrap!(data.commit(tx_1));

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let update_1 = Cmd::Update((vec![0], vec![0]));
        let delete_2 = Cmd::Delete(vec![0]);
        let tx_0 = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx_0));
        let insert_3 = Cmd::Insert((vec![0], vec![0]));
        let tx_1 = vec![insert_3];
        unwrap!(data.commit(tx_1));
    }

    #[test]
    fn insert_when_exists_fails() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let tx = vec![insert_0];
        unwrap!(data.commit(tx));
        let insert_1 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let tx = vec![insert_1];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::EntryExists(1), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let tx = vec![insert_0];
        unwrap!(data.commit(tx));
        let insert_1 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let tx = vec![insert_1];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::EntryExists(1), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let tx = vec![insert_0];
        unwrap!(data.commit(tx));
        let insert_1 = Cmd::Insert((vec![0], vec![0]));
        let tx = vec![insert_1];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::EntryExists(1), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let tx = vec![insert_0];
        unwrap!(data.commit(tx));
        let insert_1 = Cmd::Insert((vec![0], vec![0]));
        let tx = vec![insert_1];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::EntryExists(1), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }

    #[test]
    fn update_with_wrong_version_fails() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let update_2 = SentriedCmd::Update(((vec![0], vec![0]), 3)); // <-- wrong version
        let tx = vec![insert_0, update_1, update_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(2), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let update_2 = SentriedCmd::Update(((vec![0], vec![0]), 3)); // <-- wrong version
        let tx = vec![insert_0, update_1, update_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(2), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }

    #[test]
    fn delete_with_wrong_version_fails() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let delete_1 = SentriedCmd::Delete((vec![0], 3)); // <-- wrong version
        let tx = vec![insert_0, delete_1];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(1), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let delete_1 = SentriedCmd::Delete((vec![0], 3)); // <-- wrong version
        let tx = vec![insert_0, delete_1];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(1), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }

    #[test]
    fn re_insert_with_wrong_version_fails() {
        // PublicSentriedMap
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let delete_1 = SentriedCmd::Delete((vec![0], 1));
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(tx));
        let insert_2 = SentriedCmd::Insert(((vec![0], vec![0]), 3)); // <-- wrong version
        let tx = vec![insert_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(2), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PrivateSentriedMap
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let delete_1 = SentriedCmd::Delete((vec![0], 1));
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(tx));
        let insert_2 = SentriedCmd::Insert(((vec![0], vec![0]), 3)); // <-- wrong version
        let tx = vec![insert_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(2), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }
    #[test]
    fn delete_or_update_nonexisting_fails() {
        // PublicSentriedMap
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        // Delete
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = SentriedCmd::Update(((vec![0], vec![0]), 3));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PrivateSentriedMap
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        // Delete
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = SentriedCmd::Update(((vec![0], vec![0]), 3));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PublicMap
        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        // Delete
        let delete_2 = Cmd::Delete(vec![0]);
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = Cmd::Update((vec![0], vec![0]));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PrivateMap
        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        // Delete
        let delete_2 = Cmd::Delete(vec![0]);
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = Cmd::Update((vec![0], vec![0]));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }

    #[test]
    fn delete_or_update_deleted_fails() {
        // PublicSentriedMap
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let delete_1 = SentriedCmd::Delete((vec![0], 1));
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(tx));
        // Delete
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = SentriedCmd::Update(((vec![0], vec![0]), 3));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PrivateSentriedMap
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let delete_1 = SentriedCmd::Delete((vec![0], 1));
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(tx));
        // Delete
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = SentriedCmd::Update(((vec![0], vec![0]), 3));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PublicMap
        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let delete_1 = Cmd::Delete(vec![0]);
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(tx));
        // Delete
        let delete_2 = Cmd::Delete(vec![0]);
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = Cmd::Update((vec![0], vec![0]));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PrivateMap
        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let delete_1 = Cmd::Delete(vec![0]);
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(tx));
        // Delete
        let delete_2 = Cmd::Delete(vec![0]);
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = Cmd::Update((vec![0], vec![0]));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }

    #[test]
    fn set_permissions() {
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);

        // Set the first permission set with correct ExpectedIndices - should pass.
        let res = data.set_permissions(
            PrivatePermissions {
                permissions: BTreeMap::new(),
                expected_data_index: 0,
                expected_owners_index: 0,
            },
            0,
        );

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }

        // Verify that the permissions are part of the history.
        assert_eq!(
            unwrap!(data.permission_history_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );

        // Set permissions with incorrect ExpectedIndices - should fail.
        let res = data.set_permissions(
            PrivatePermissions {
                permissions: BTreeMap::new(),
                expected_data_index: 64,
                expected_owners_index: 0,
            },
            1,
        );

        match res {
            Err(_) => (),
            Ok(()) => panic!("Unexpected Ok(()) result"),
        }

        // Verify that the history of permissions remains unchanged.
        assert_eq!(
            unwrap!(data.permission_history_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );
    }

    #[test]
    fn set_owner() {
        let owner_pk = gen_public_key();

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);

        // Set the first owner with correct ExpectedIndices - should pass.
        let res = data.set_owner(
            Owner {
                public_key: owner_pk,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        );

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }

        // Verify that the owner is part of history.
        assert_eq!(
            unwrap!(data.owner_history_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );

        // Set new owner with incorrect ExpectedIndices - should fail.
        let res = data.set_owner(
            Owner {
                public_key: owner_pk,
                expected_data_index: 64,
                expected_permissions_index: 0,
            },
            1,
        );

        match res {
            Err(_) => (),
            Ok(()) => panic!("Unexpected Ok(()) result"),
        }

        // Verify that the history of owners remains unchanged.
        assert_eq!(
            unwrap!(data.owner_history_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );
    }

    #[test]
    fn assert_shell() {
        let owner_pk = gen_public_key();
        let owner_pk1 = gen_public_key();

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);

        let _ = data.set_owner(
            Owner {
                public_key: owner_pk,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        );

        let _ = data.set_owner(
            Owner {
                public_key: owner_pk1,
                expected_data_index: 0,
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

    // #[test]
    // fn in_range() {
    //     let mut data = PublicSentriedMap::new(rand::random(), 10);
    //     let entries = vec![
    //         Entry::new(b"key0".to_vec(), b"value0".to_vec()),
    //         Entry::new(b"key1".to_vec(), b"value1".to_vec()),
    //     ];
    //     unwrap!(data.append(entries, 0));

    //     assert_eq!(
    //         data.in_range(Index::FromStart(0), Index::FromStart(0)),
    //         Some(vec![])
    //     );
    //     assert_eq!(
    //         data.in_range(Index::FromStart(0), Index::FromStart(1)),
    //         Some(vec![Entry::new(b"key0".to_vec(), b"value0".to_vec())])
    //     );
    //     assert_eq!(
    //         data.in_range(Index::FromStart(0), Index::FromStart(2)),
    //         Some(vec![
    //             Entry::new(b"key0".to_vec(), b"value0".to_vec()),
    //             Entry::new(b"key1".to_vec(), b"value1".to_vec())
    //         ])
    //     );

    //     assert_eq!(
    //         data.in_range(Index::FromEnd(2), Index::FromEnd(1)),
    //         Some(vec![Entry::new(b"key0".to_vec(), b"value0".to_vec()),])
    //     );
    //     assert_eq!(
    //         data.in_range(Index::FromEnd(2), Index::FromEnd(0)),
    //         Some(vec![
    //             Entry::new(b"key0".to_vec(), b"value0".to_vec()),
    //             Entry::new(b"key1".to_vec(), b"value1".to_vec())
    //         ])
    //     );

    //     assert_eq!(
    //         data.in_range(Index::FromStart(0), Index::FromEnd(0)),
    //         Some(vec![
    //             Entry::new(b"key0".to_vec(), b"value0".to_vec()),
    //             Entry::new(b"key1".to_vec(), b"value1".to_vec())
    //         ])
    //     );

    //     // start > end
    //     assert_eq!(
    //         data.in_range(Index::FromStart(1), Index::FromStart(0)),
    //         None
    //     );
    //     assert_eq!(data.in_range(Index::FromEnd(1), Index::FromEnd(2)), None);

    //     // overflow
    //     assert_eq!(
    //         data.in_range(Index::FromStart(0), Index::FromStart(3)),
    //         None
    //     );
    //     assert_eq!(data.in_range(Index::FromEnd(3), Index::FromEnd(0)), None);
    // }

    #[test]
    fn can_retrieve_permissions() {
        let public_key = gen_public_key();
        let invalid_public_key = gen_public_key();

        let mut pub_permissions = PublicPermissions {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 0,
        };
        let _ = pub_permissions.permissions.insert(
            User::Specific(public_key),
            PublicPermissionSet::new(BTreeMap::new()),
        );

        let mut private_permissions = PrivatePermissions {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 0,
        };
        let _ = private_permissions
            .permissions
            .insert(public_key, PrivatePermissionSet::new(BTreeMap::new()));

        // pub, unseq
        let mut data = PublicMap::new(rand::random(), 20);
        unwrap!(data.set_permissions(pub_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.public_permissions_at(0), Ok(&pub_permissions));
        assert_eq!(data.private_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Ok(PublicPermissionSet::new(BTreeMap::new()))
        );
        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.public_user_permissions_at(User::Specific(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // pub, seq
        let mut data = PublicSentriedMap::new(rand::random(), 20);
        unwrap!(data.set_permissions(pub_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.public_permissions_at(0), Ok(&pub_permissions));
        assert_eq!(data.private_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Ok(PublicPermissionSet::new(BTreeMap::new()))
        );
        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.public_user_permissions_at(User::Specific(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // Private, unseq
        let mut data = PrivateMap::new(rand::random(), 20);
        unwrap!(data.set_permissions(private_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.private_permissions_at(0), Ok(&private_permissions));
        assert_eq!(data.public_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Ok(PrivatePermissionSet::new(BTreeMap::new()))
        );
        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.private_user_permissions_at(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );

        // Private, seq
        let mut data = PrivateSentriedMap::new(rand::random(), 20);
        unwrap!(data.set_permissions(private_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.private_permissions_at(0), Ok(&private_permissions));
        assert_eq!(data.public_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Ok(PrivatePermissionSet::new(BTreeMap::new()))
        );
        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.private_user_permissions_at(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );
    }

    fn gen_public_key() -> PublicKey {
        PublicKey::Bls(SecretKey::random().public_key())
    }

    #[test]
    fn validates_public_permissions() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut map = PublicSentriedMap::new(XorName([1; 32]), 100);

        // no owner
        let data = Data::from(map.clone());
        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_0), false);
        // data is Public - read always allowed
        assert_read_permitted(&data, public_key_0, true);

        // no permissions
        unwrap!(map.set_owner(
            Owner {
                public_key: public_key_0,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        ));
        let data = Data::from(map.clone());

        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_0), true);
        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_1), false);
        // data is Public - read always allowed
        assert_read_permitted(&data, public_key_0, true);
        assert_read_permitted(&data, public_key_1, true);

        // with permissions
        let mut permissions = PublicPermissions {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 1,
        };
        let mut set = BTreeMap::new();
        let _ = set.insert(get_insert_cmd(), true);
        let _ = permissions
            .permissions
            .insert(User::Anyone, PublicPermissionSet::new(set));
        let mut set = BTreeMap::new();
        for cmd in get_full_modify_permissions() {
            let _ = set.insert(cmd, true);
        }
        let _ = permissions
            .permissions
            .insert(User::Specific(public_key_1), PublicPermissionSet::new(set));
        unwrap!(map.set_permissions(permissions, 0));
        let data = Data::from(map);

        // existing key fallback
        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_1), true);
        // existing key override
        assert_modify_permissions_permitted(&data, public_key_1, true);
        // non-existing keys are handled by `Anyone`
        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_2), true);
        assert_modify_permissions_permitted(&data, public_key_2, false);
        // data is Public - read always allowed
        assert_read_permitted(&data, public_key_0, true);
        assert_read_permitted(&data, public_key_1, true);
        assert_read_permitted(&data, public_key_2, true);
    }

    #[test]
    fn validates_private_permissions() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut map = PrivateSentriedMap::new(XorName([1; 32]), 100);

        // no owner
        let data = Data::from(map.clone());
        assert_read_permitted(&data, public_key_0, false);

        // no permissions
        unwrap!(map.set_owner(
            Owner {
                public_key: public_key_0,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        ));
        let data = Data::from(map.clone());

        assert_read_permitted(&data, public_key_0, true);
        assert_read_permitted(&data, public_key_1, false);

        // with permissions
        let mut permissions = PrivatePermissions {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 1,
        };
        let mut set = BTreeMap::new();
        let _ = set.insert(get_insert_cmd(), true);
        for query in get_full_read_permissions() {
            let _ = set.insert(query, true);
        }
        for cmd in get_full_modify_permissions() {
            let _ = set.insert(cmd, false);
        }
        let _ = permissions
            .permissions
            .insert(public_key_1, PrivatePermissionSet::new(set));
        unwrap!(map.set_permissions(permissions, 0));
        let data = Data::from(map);

        // existing key
        assert_read_permitted(&data, public_key_1, true);
        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_1), true);
        assert_modify_permissions_permitted(&data, public_key_1, false);

        // non-existing key
        assert_read_permitted(&data, public_key_2, false);
        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_2), false);
        assert_modify_permissions_permitted(&data, public_key_2, false);
    }
}
