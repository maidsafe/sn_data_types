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
