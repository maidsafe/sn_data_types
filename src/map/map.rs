// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::access_control::{
    AccessListTrait, AccessType, PrivateAccessList, PrivateUserAccess, PublicAccessList,
    PublicUserAccess,
};
use crate::shared_data::{
    to_absolute_range, to_absolute_version, Address, ExpectedVersions, Key, Kind, KvPair,
    NonSentried, Owner, Sentried, User, Value, Version,
};
use crate::{EntryError, Error, PublicKey, Result, XorName};
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    mem,
};

pub type PublicSentriedMap = MapBase<PublicAccessList, Sentried>;
pub type PublicMap = MapBase<PublicAccessList, NonSentried>;
pub type PrivateSentriedMap = MapBase<PrivateAccessList, Sentried>;
pub type PrivateMap = MapBase<PrivateAccessList, NonSentried>;
pub type DataHistories = BTreeMap<Key, Vec<StoredValue>>;
pub type DataEntries = Vec<DataEntry>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default, Debug)]
pub struct DataEntry {
    pub key: Key,
    pub value: Value,
}

impl DataEntry {
    pub fn new(key: Key, value: Value) -> Self {
        Self { key, value }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct MapBase<C, S> {
    address: Address,
    data: DataHistories,
    access_list: Vec<C>,
    // This is the history of owners, with each entry representing an owner.  Each single owner
    // could represent an individual user, or a group of users, depending on the `PublicKey` type.
    owners: Vec<Owner>,
    /// Version should be increased for any changes to Map data entries,
    /// but not for permissions and owner changes.
    version: Option<u64>,
    _flavour: S,
}

/// Common methods for all `Map` flavours.
impl<C, S> MapBase<C, S>
where
    C: AccessListTrait,
    S: Copy,
{
    pub fn is_allowed(&self, user: PublicKey, access: AccessType) -> bool {
        match self.owner_at(Version::FromEnd(1)) {
            Some(owner) => {
                if owner.public_key == user {
                    return true;
                }
            }
            None => (),
        }
        match self.access_list_at(Version::FromEnd(1)) {
            Some(access_list) => access_list.is_allowed(&user, &access),
            None => false,
        }
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

    /// Returns true if the user is the current owner, false if not.
    pub fn is_owner(&self, user: PublicKey) -> bool {
        match self.owner_at(Version::FromEnd(1)) {
            Some(owner) => user == owner.public_key,
            _ => false,
        }
    }

    /// Return the expected data version.
    pub fn expected_data_version(&self) -> Option<u64> {
        self.version
    }

    /// Return the expected owners version.
    pub fn expected_owners_version(&self) -> u64 {
        self.owners.len() as u64
    }

    /// Return the expected access list version.
    pub fn expected_access_list_version(&self) -> u64 {
        self.access_list.len() as u64
    }

    pub fn versions(&self) -> ExpectedVersions {
        ExpectedVersions::new(
            self.expected_data_version().unwrap_or_default(),
            self.expected_owners_version(),
            self.expected_access_list_version(),
        )
    }

    /// Returns the data shell - that is - everything except the entries themselves.
    pub fn shell(&self, expected_data_version: impl Into<Version>) -> Result<Self> {
        let expected_data_version = to_absolute_version(
            expected_data_version.into(),
            self.expected_data_version().unwrap_or_default() as usize,
        )
        .ok_or(Error::NoSuchEntry)? as u64;

        let access_list = self
            .access_list
            .iter()
            .filter(|ac| ac.expected_data_version() <= expected_data_version)
            .cloned()
            .collect();

        let owners = self
            .owners
            .iter()
            .filter(|owner| owner.expected_data_version <= expected_data_version)
            .cloned()
            .collect();

        Ok(Self {
            address: self.address,
            data: BTreeMap::new(),
            access_list,
            owners,
            version: self.version,
            _flavour: self._flavour,
        })
    }

    /// Return a value for the given key (if it is present).
    pub fn get_value(&self, key: &Key) -> Option<&Value> {
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

    /// Return a value for the given key (if it is present).
    pub fn get_value_at(&self, key: &Key, version: Version) -> Option<&Value> {
        match self.data.get(key) {
            Some(history) => {
                let abs_ver = to_absolute_version(version, history.len())?;
                match history.get(abs_ver) {
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
    pub fn data_entries(&self) -> DataEntries {
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

    /// Returns history of all keys
    pub fn key_histories(&self) -> &DataHistories {
        &self.data
    }

    // Returns the history of a specified key.
    pub fn key_history(&self, key: &Key) -> Option<&StoredValues> {
        match self.data.get(key) {
            Some(history) => Some(history),
            None => None,
        }
    }

    /// Returns a range in the history of a specified key.
    pub fn key_history_range(
        &self,
        key: &Key,
        start: Version,
        end: Version,
    ) -> Option<StoredValues> {
        let range = to_absolute_range(start, end, self.data.len())?;
        match self.data.get(key) {
            Some(history) => Some(history[range].to_vec()),
            None => None,
        }
    }

    /// Get owner at version.
    pub fn owner_at(&self, version: impl Into<Version>) -> Option<&Owner> {
        let version = to_absolute_version(version.into(), self.owners.len())?;
        self.owners.get(version)
    }

    /// Returns history of all owners
    pub fn owner_history(&self) -> Vec<Owner> {
        self.owners.clone()
    }

    /// Get history of owners within the range of versions specified.
    pub fn owner_history_range(&self, start: Version, end: Version) -> Option<Vec<Owner>> {
        let range = to_absolute_range(start, end, self.owners.len())?;
        Some(self.owners[range].iter().map(|c| *c).collect())
    }

    /// Get access list at version.
    pub fn access_list_at(&self, version: impl Into<Version>) -> Option<&C> {
        let version = to_absolute_version(version.into(), self.access_list.len())?;
        self.access_list.get(version)
    }

    /// Returns history of all access list states
    pub fn access_list_history(&self) -> Vec<C> {
        self.access_list.clone()
    }

    /// Get history of access list within the range of versions specified.
    pub fn access_list_history_range(&self, start: Version, end: Version) -> Option<Vec<C>> {
        let range = to_absolute_range(start, end, self.access_list.len())?;
        Some(self.access_list[range].iter().map(|c| c.clone()).collect())
    }

    /// Set owner.
    pub fn set_owner(&mut self, owner: Owner, version: u64) -> Result<()> {
        if owner.expected_data_version != self.expected_data_version().unwrap_or_default() {
            return Err(Error::InvalidSuccessor(
                self.expected_data_version().unwrap_or_default(),
            ));
        }
        if owner.expected_access_list_version != self.expected_access_list_version() {
            return Err(Error::InvalidPermissionsSuccessor(
                self.expected_access_list_version(),
            ));
        }
        if self.expected_owners_version() != version {
            return Err(Error::InvalidSuccessor(self.expected_owners_version()));
        }
        self.owners.push(owner);
        Ok(())
    }

    /// Set access list.
    /// The `AccessList` struct needs to contain the correct expected versions.
    pub fn set_access_list(&mut self, access_list: &C, version: u64) -> Result<()> {
        if access_list.expected_data_version() != self.expected_data_version().unwrap_or_default() {
            return Err(Error::InvalidSuccessor(
                self.expected_data_version().unwrap_or_default(),
            ));
        }
        if access_list.expected_owners_version() != self.expected_owners_version() {
            return Err(Error::InvalidOwnersSuccessor(
                self.expected_owners_version(),
            ));
        }
        if self.expected_access_list_version() != version {
            return Err(Error::InvalidSuccessor(self.expected_access_list_version()));
        }
        self.access_list.push(access_list.clone()); // hmm... do we have to clone in situations like these?
        Ok(())
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

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
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
impl<P: AccessListTrait> MapBase<P, NonSentried> {
    /// Commit transaction.
    ///
    /// If the specified `expected_version` does not equal the entries count in data, an
    /// error will be returned.
    pub fn commit(&mut self, tx: &Transaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: Operations = tx.into_iter().fold(
            Default::default(),
            |(mut insert, mut update, mut delete), cmd| {
                match cmd {
                    Cmd::Insert(kv_pair) => {
                        let _ = insert.insert(kv_pair.clone());
                    }
                    Cmd::Update(kv_pair) => {
                        let _ = update.insert(kv_pair.clone());
                    }
                    Cmd::Delete(key) => {
                        let _ = delete.insert(key.clone());
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
                                EntryError::EntryExists(entry.get().len() as u64),
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
impl<P: AccessListTrait> MapBase<P, Sentried> {
    /// Commit transaction.
    ///
    /// If the specified `expected_version` does not equal the entries count in data, an
    /// error will be returned.
    pub fn commit(&mut self, tx: &SentriedTransaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: SentriedOperations = tx.into_iter().fold(
            Default::default(),
            |(mut insert, mut update, mut delete), cmd| {
                match cmd {
                    SentriedCmd::Insert(sentried_kvpair) => {
                        let _ = insert.insert(sentried_kvpair.clone());
                    }
                    SentriedCmd::Update(sentried_kvpair) => {
                        let _ = update.insert(sentried_kvpair.clone());
                    }
                    SentriedCmd::Delete(sentried_key) => {
                        let _ = delete.insert(sentried_key.clone());
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
                                    EntryError::InvalidSuccessor(expected_version),
                                );
                            }
                        }
                        StoredValue::Value(_) => {
                            let _ = errors.insert(
                                entry.key().clone(),
                                EntryError::EntryExists(entry.get().len() as u64),
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
                                    EntryError::InvalidSuccessor(expected_version),
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
                                    EntryError::InvalidSuccessor(expected_version),
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

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StoredValue {
    Value(Value),
    Tombstone(),
}

pub type StoredValues = Vec<StoredValue>;

/// Public + Sentried
impl MapBase<PublicAccessList, Sentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PublicSentried { name, tag },
            data: BTreeMap::new(),
            access_list: Vec::new(),
            owners: Vec::new(),
            version: Some(0),
            _flavour: Sentried,
        }
    }
}

impl Debug for MapBase<PublicAccessList, Sentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicSentriedMap {:?}", self.name())
    }
}

/// Public + NonSentried
impl MapBase<PublicAccessList, NonSentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Public { name, tag },
            data: BTreeMap::new(),
            access_list: Vec::new(),
            owners: Vec::new(),
            version: None,
            _flavour: NonSentried,
        }
    }
}

impl Debug for MapBase<PublicAccessList, NonSentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicMap {:?}", self.name())
    }
}

/// Private + Sentried
impl MapBase<PrivateAccessList, Sentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PrivateSentried { name, tag },
            data: BTreeMap::new(),
            access_list: Vec::new(),
            owners: Vec::new(),
            version: Some(0),
            _flavour: Sentried,
        }
    }

    /// Commit transaction.
    ///
    /// If the specified `expected_version` does not equal the entries count in data, an
    /// error will be returned.
    pub fn hard_commit(&mut self, tx: &SentriedTransaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: SentriedOperations = tx.into_iter().fold(
            Default::default(),
            |(mut insert, mut update, mut delete), cmd| {
                match cmd {
                    SentriedCmd::Insert(sentried_kvpair) => {
                        let _ = insert.insert(sentried_kvpair.clone());
                    }
                    SentriedCmd::Update(sentried_kvpair) => {
                        let _ = update.insert(sentried_kvpair.clone());
                    }
                    SentriedCmd::Delete(sentried_key) => {
                        let _ = delete.insert(sentried_key.clone());
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
                                EntryError::EntryExists(entry.get().len() as u64),
                            );
                        }
                        Some(StoredValue::Tombstone()) => {
                            if version == history.len() as u64 {
                                let _ = history.push(StoredValue::Value(val));
                            } else {
                                let _ = errors.insert(
                                    key,
                                    EntryError::InvalidSuccessor(entry.get().len() as u64), // I assume we are here letting caller know what successor is expected
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
                                ); // remove old value, as to properly owerwrite on update, but keep the Version, as to increment history length (i.e. version)
                                let _ = history.push(StoredValue::Value(val));
                            } else {
                                let _ = errors.insert(
                                    entry.key().clone(),
                                    EntryError::InvalidSuccessor(expected_version), // I assume we are here letting caller know what successor is expected
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
                                ); // remove old value, as to properly delete, but keep the Version, as to increment history length (i.e. version)
                                let _ = history.push(StoredValue::Tombstone());
                            } else {
                                let _ = errors.insert(
                                    entry.key().clone(),
                                    EntryError::InvalidSuccessor(expected_version), // I assume we are here letting caller know what successor is expected
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

impl Debug for MapBase<PrivateAccessList, Sentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateSentriedMap {:?}", self.name())
    }
}

/// Private + NonSentried
impl MapBase<PrivateAccessList, NonSentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Private { name, tag },
            data: BTreeMap::new(),
            access_list: Vec::new(),
            owners: Vec::new(),
            version: None,
            _flavour: NonSentried,
        }
    }

    /// Commit transaction that potentially hard deletes data.
    ///
    /// If the specified `expected_version` does not equal the entries count in data, an
    /// error will be returned.
    pub fn hard_commit(&mut self, tx: &Transaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: Operations = tx.into_iter().fold(
            Default::default(),
            |(mut insert, mut update, mut delete), cmd| {
                match cmd {
                    Cmd::Insert(kv_pair) => {
                        let _ = insert.insert(kv_pair.clone());
                    }
                    Cmd::Update(kv_pair) => {
                        let _ = update.insert(kv_pair.clone());
                    }
                    Cmd::Delete(key) => {
                        let _ = delete.insert(key.clone());
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
                                EntryError::EntryExists(entry.get().len() as u64),
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
                                mem::replace(&mut history.last(), Some(&StoredValue::Tombstone())); // remove old value, as to properly owerwrite on update, but keep the Version, as to increment history length (i.e. version)
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
                                mem::replace(&mut history.last(), Some(&StoredValue::Tombstone())); // remove old value, as to properly delete, but keep the Version, as to increment history length (i.e. version)
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

impl Debug for MapBase<PrivateAccessList, NonSentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateMap {:?}", self.name())
    }
}

/// Object storing a Map variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum MapData {
    PublicSentried(PublicSentriedMap),
    Public(PublicMap),
    PrivateSentried(PrivateSentriedMap),
    Private(PrivateMap),
}

impl MapData {
    pub fn is_allowed(&self, access: AccessType, user: PublicKey) -> bool {
        use AccessType::*;
        use MapData::*;
        // Public flavours automatically allows all reads.
        match (self, access) {
            (PublicSentried(_), Read) | (Public(_), Read) => return true,
            _ => (),
        }
        match (self, access) {
            (PublicSentried(data), Insert)
            | (PublicSentried(data), Update)
            | (PublicSentried(data), Delete)
            | (PublicSentried(data), ModifyPermissions) => data.is_allowed(user, access),
            (Public(data), Insert)
            | (Public(data), Update)
            | (Public(data), Delete)
            | (Public(data), ModifyPermissions) => data.is_allowed(user, access),
            (PrivateSentried(data), Insert)
            | (PrivateSentried(data), Update)
            | (PrivateSentried(data), Delete)
            | (PrivateSentried(data), HardUpdate)
            | (PrivateSentried(data), HardDelete)
            | (PrivateSentried(data), ModifyPermissions) => data.is_allowed(user, access),
            (Private(data), Insert)
            | (Private(data), Update)
            | (Private(data), Delete)
            | (Private(data), HardUpdate)
            | (Private(data), HardDelete)
            | (Private(data), ModifyPermissions) => data.is_allowed(user, access),
            (PrivateSentried(data), Read) => data.is_allowed(user, access),
            (Private(data), Read) => data.is_allowed(user, access),
            _ => false,
        }
    }

    pub fn address(&self) -> &Address {
        use MapData::*;
        match self {
            PublicSentried(data) => data.address(),
            Public(data) => data.address(),
            PrivateSentried(data) => data.address(),
            Private(data) => data.address(),
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

    pub fn is_owner(&self, user: PublicKey) -> bool {
        use MapData::*;
        match self {
            PublicSentried(data) => data.is_owner(user),
            Public(data) => data.is_owner(user),
            PrivateSentried(data) => data.is_owner(user),
            Private(data) => data.is_owner(user),
        }
    }

    pub fn expected_data_version(&self) -> u64 {
        use MapData::*;
        match self {
            PublicSentried(data) => data.expected_data_version().unwrap_or_default(),
            Public(data) => data.expected_data_version().unwrap_or_default(),
            PrivateSentried(data) => data.expected_data_version().unwrap_or_default(),
            Private(data) => data.expected_data_version().unwrap_or_default(),
        }
    }

    pub fn expected_access_list_version(&self) -> u64 {
        use MapData::*;
        match self {
            PublicSentried(data) => data.expected_access_list_version(),
            Public(data) => data.expected_access_list_version(),
            PrivateSentried(data) => data.expected_access_list_version(),
            Private(data) => data.expected_access_list_version(),
        }
    }

    pub fn expected_owners_version(&self) -> u64 {
        use MapData::*;
        match self {
            PublicSentried(data) => data.expected_owners_version(),
            Public(data) => data.expected_owners_version(),
            PrivateSentried(data) => data.expected_owners_version(),
            Private(data) => data.expected_owners_version(),
        }
    }

    pub fn versions(&self) -> ExpectedVersions {
        use MapData::*;
        match self {
            PublicSentried(data) => data.versions(),
            Public(data) => data.versions(),
            PrivateSentried(data) => data.versions(),
            Private(data) => data.versions(),
        }
    }

    pub fn get_value(&self, key: &Key) -> Option<&Value> {
        use MapData::*;
        match self {
            PublicSentried(data) => data.get_value(key),
            Public(data) => data.get_value(key),
            PrivateSentried(data) => data.get_value(key),
            Private(data) => data.get_value(key),
        }
    }

    pub fn get_value_at(&self, key: &Key, version: Version) -> Option<&Value> {
        use MapData::*;
        match self {
            PublicSentried(data) => data.get_value_at(key, version),
            Public(data) => data.get_value_at(key, version),
            PrivateSentried(data) => data.get_value_at(key, version),
            Private(data) => data.get_value_at(key, version),
        }
    }

    // Returns the history of a specified key.
    pub fn key_history(&self, key: &Key) -> Option<&StoredValues> {
        use MapData::*;
        match self {
            PublicSentried(data) => data.key_history(key),
            Public(data) => data.key_history(key),
            PrivateSentried(data) => data.key_history(key),
            Private(data) => data.key_history(key),
        }
    }

    /// Returns a range in the history of a specified key.
    pub fn key_history_range(&self, key: &Key, from: Version, to: Version) -> Option<StoredValues> {
        use MapData::*;
        match self {
            PublicSentried(data) => data.key_history_range(key, from, to),
            Public(data) => data.key_history_range(key, from, to),
            PrivateSentried(data) => data.key_history_range(key, from, to),
            Private(data) => data.key_history_range(key, from, to),
        }
    }

    /// Returns history for all keys
    pub fn key_histories(&self) -> &DataHistories {
        use MapData::*;
        match self {
            PublicSentried(data) => data.key_histories(),
            Public(data) => data.key_histories(),
            PrivateSentried(data) => data.key_histories(),
            Private(data) => data.key_histories(),
        }
    }

    pub fn owner_at(&self, version: impl Into<Version>) -> Option<&Owner> {
        use MapData::*;
        match self {
            PublicSentried(data) => data.owner_at(version),
            Public(data) => data.owner_at(version),
            PrivateSentried(data) => data.owner_at(version),
            Private(data) => data.owner_at(version),
        }
    }

    /// Returns history of all owners
    pub fn owner_history(&self) -> Result<Vec<Owner>> {
        use MapData::*;
        let result = match self {
            PublicSentried(data) => Some(data.owner_history()),
            Public(data) => Some(data.owner_history()),
            PrivateSentried(data) => Some(data.owner_history()),
            Private(data) => Some(data.owner_history()),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    /// Get history of owners within the range of versions specified.
    pub fn owner_history_range(&self, start: Version, end: Version) -> Result<Vec<Owner>> {
        use MapData::*;
        let result = match self {
            PublicSentried(data) => data.owner_history_range(start, end),
            Public(data) => data.owner_history_range(start, end),
            PrivateSentried(data) => data.owner_history_range(start, end),
            Private(data) => data.owner_history_range(start, end),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    pub fn public_user_access_at(
        &self,
        user: User,
        version: impl Into<Version>,
    ) -> Result<PublicUserAccess> {
        self.public_access_list_at(version)?
            .access_list()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    pub fn private_user_access_at(
        &self,
        user: PublicKey,
        version: impl Into<Version>,
    ) -> Result<PrivateUserAccess> {
        self.private_access_list_at(version)?
            .access_list()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    pub fn public_access_list_at(&self, version: impl Into<Version>) -> Result<&PublicAccessList> {
        use MapData::*;
        let access_list = match self {
            PublicSentried(data) => data.access_list_at(version),
            Public(data) => data.access_list_at(version),
            _ => return Err(Error::InvalidOperation),
        };
        access_list.ok_or(Error::NoSuchEntry)
    }

    pub fn private_access_list_at(
        &self,
        version: impl Into<Version>,
    ) -> Result<&PrivateAccessList> {
        use MapData::*;
        let access_list = match self {
            PrivateSentried(data) => data.access_list_at(version),
            Private(data) => data.access_list_at(version),
            _ => return Err(Error::InvalidOperation),
        };
        access_list.ok_or(Error::NoSuchEntry)
    }

    /// Returns history of all access list states
    pub fn public_access_list_history(&self) -> Result<Vec<PublicAccessList>> {
        use MapData::*;
        let result = match self {
            PublicSentried(data) => Some(data.access_list_history()),
            Public(data) => Some(data.access_list_history()),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    /// Returns history of all access list states
    pub fn private_access_list_history(&self) -> Result<Vec<PrivateAccessList>> {
        use MapData::*;
        let result = match self {
            PrivateSentried(data) => Some(data.access_list_history()),
            Private(data) => Some(data.access_list_history()),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    /// Get history of access list within the range of versions specified.
    pub fn public_access_list_history_range(
        &self,
        start: Version,
        end: Version,
    ) -> Result<Vec<PublicAccessList>> {
        use MapData::*;
        let result = match self {
            PublicSentried(data) => data.access_list_history_range(start, end),
            Public(data) => data.access_list_history_range(start, end),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    /// Get history of access list within the range of versions specified.
    pub fn private_access_list_history_range(
        &self,
        start: Version,
        end: Version,
    ) -> Result<Vec<PrivateAccessList>> {
        use MapData::*;
        let result = match self {
            PrivateSentried(data) => data.access_list_history_range(start, end),
            Private(data) => data.access_list_history_range(start, end),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    pub fn shell(&self, version: impl Into<Version>) -> Result<Self> {
        use MapData::*;
        match self {
            PublicSentried(map) => map.shell(version).map(PublicSentried),
            Public(map) => map.shell(version).map(Public),
            PrivateSentried(map) => map.shell(version).map(PrivateSentried),
            Private(map) => map.shell(version).map(Private),
        }
    }

    pub fn set_owner(&mut self, owner: Owner, expected_version: u64) -> Result<()> {
        use MapData::*;
        match self {
            PublicSentried(adata) => adata.set_owner(owner, expected_version),
            Public(adata) => adata.set_owner(owner, expected_version),
            PrivateSentried(adata) => adata.set_owner(owner, expected_version),
            Private(adata) => adata.set_owner(owner, expected_version),
        }
    }

    pub fn set_private_access_list(
        &mut self,
        access_list: &PrivateAccessList,
        expected_version: u64,
    ) -> Result<()> {
        use MapData::*;
        match self {
            Private(data) => data.set_access_list(access_list, expected_version),
            PrivateSentried(data) => data.set_access_list(access_list, expected_version),
            _ => Err(Error::InvalidOperation),
        }
    }

    pub fn set_public_access_list(
        &mut self,
        access_list: &PublicAccessList,
        expected_version: u64,
    ) -> Result<()> {
        use MapData::*;
        match self {
            Public(data) => data.set_access_list(access_list, expected_version),
            PublicSentried(data) => data.set_access_list(access_list, expected_version),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Commits transaction.
    pub fn commit(&mut self, tx: &MapTransaction) -> Result<()> {
        use MapData::*;
        use MapTransaction::*;
        use SentryOption::*;
        match self {
            PrivateSentried(map) => match tx {
                Commit(options) => {
                    if let ExpectVersion(stx) = options {
                        return map.commit(stx);
                    }
                }
                HardCommit(options) => {
                    if let ExpectVersion(stx) = options {
                        return map.hard_commit(stx);
                    }
                }
            },
            Private(map) => match tx {
                Commit(options) => {
                    if let AnyVersion(tx) = options {
                        return map.commit(tx);
                    }
                }
                HardCommit(options) => {
                    if let AnyVersion(tx) = options {
                        return map.hard_commit(tx);
                    }
                }
            },
            PublicSentried(map) => match tx {
                Commit(options) => {
                    if let ExpectVersion(stx) = options {
                        return map.commit(stx);
                    }
                }
                _ => return Err(Error::InvalidOperation),
            },
            Public(map) => match tx {
                Commit(options) => {
                    if let AnyVersion(tx) = options {
                        return map.commit(tx);
                    }
                }
                _ => return Err(Error::InvalidOperation),
            },
        }

        Err(Error::InvalidOperation)
    }
}

impl From<PublicSentriedMap> for MapData {
    fn from(data: PublicSentriedMap) -> Self {
        MapData::PublicSentried(data)
    }
}

impl From<PublicMap> for MapData {
    fn from(data: PublicMap) -> Self {
        MapData::Public(data)
    }
}

impl From<PrivateSentriedMap> for MapData {
    fn from(data: PrivateSentriedMap) -> Self {
        MapData::PrivateSentried(data)
    }
}

impl From<PrivateMap> for MapData {
    fn from(data: PrivateMap) -> Self {
        MapData::Private(data)
    }
}
