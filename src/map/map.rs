// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::auth::{
    AccessType, Auth, PrivateAuth, PrivatePermissions, PublicAuth, PublicPermissions,
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

pub type PublicSentriedMap = MapBase<PublicAuth, Sentried>;
pub type PublicMap = MapBase<PublicAuth, NonSentried>;
pub type PrivateSentriedMap = MapBase<PrivateAuth, Sentried>;
pub type PrivateMap = MapBase<PrivateAuth, NonSentried>;
pub type DataHistories = BTreeMap<Key, Vec<StoredValue>>;
pub type DataEntries = Vec<DataEntry>;

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum MapAuth {
    Public(PublicAuth),
    Private(PrivateAuth),
}

impl From<PrivateAuth> for MapAuth {
    fn from(auth: PrivateAuth) -> Self {
        MapAuth::Private(auth)
    }
}

impl From<PublicAuth> for MapAuth {
    fn from(auth: PublicAuth) -> Self {
        MapAuth::Public(auth)
    }
}

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
    auth: Vec<C>,
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
    C: Auth,
    S: Copy,
{
    /// Returns the data shell - that is - everything except the entries themselves.
    pub fn shell(&self, expected_data_version: impl Into<Version>) -> Result<Self> {
        let expected_data_version = to_absolute_version(
            expected_data_version.into(),
            self.expected_data_version().unwrap_or_default() as usize,
        )
        .ok_or(Error::NoSuchEntry)? as u64;

        let auth = self
            .auth
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
            auth,
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

    /// Return the expected owners version.
    pub fn expected_owners_version(&self) -> u64 {
        self.owners.len() as u64
    }

    /// Return the expected authorization version.
    pub fn expected_auth_version(&self) -> u64 {
        self.auth.len() as u64
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

    /// Get auth at version.
    pub fn auth_at(&self, version: impl Into<Version>) -> Option<&C> {
        let version = to_absolute_version(version.into(), self.auth.len())?;
        self.auth.get(version)
    }

    /// Returns history of all authorization states
    pub fn auth_histories(&self) -> &Vec<C> {
        &self.auth
    }

    /// Get history of authorization within the range of versions specified.
    pub fn auth_history_range(&self, start: Version, end: Version) -> Option<&[C]> {
        let range = to_absolute_range(start, end, self.auth.len())?;
        Some(&self.auth[range])
    }

    /// Set authorization.
    /// The `Auth` struct needs to contain the correct expected versions.
    pub fn set_auth(&mut self, auth: C, version: u64) -> Result<()> {
        if auth.expected_data_version() != self.expected_data_version().unwrap_or_default() {
            return Err(Error::InvalidSuccessor(
                self.expected_data_version().unwrap_or_default(),
            ));
        }
        if auth.expected_owners_version() != self.expected_owners_version() {
            return Err(Error::InvalidOwnersSuccessor(
                self.expected_owners_version(),
            ));
        }
        if self.expected_auth_version() != version {
            return Err(Error::InvalidSuccessor(self.expected_auth_version()));
        }
        self.auth.push(auth);
        Ok(())
    }

    pub fn is_allowed(&self, user: PublicKey, access: AccessType) -> bool {
        match self.owner_at(Version::FromEnd(1)) {
            Some(owner) => {
                if owner.public_key == user {
                    return true;
                }
            }
            None => (),
        }
        match self.auth_at(Version::FromEnd(1)) {
            Some(auth) => auth.is_allowed(&user, &access),
            None => false,
        }
    }

    /// Get owner at version.
    pub fn owner_at(&self, version: impl Into<Version>) -> Option<&Owner> {
        let version = to_absolute_version(version.into(), self.owners.len())?;
        self.owners.get(version)
    }

    /// Returns history of all owners
    pub fn owner_histories(&self) -> &Vec<Owner> {
        &self.owners
    }

    /// Get history of owners within the range of versions specified.
    pub fn owner_history_range(&self, start: Version, end: Version) -> Option<&[Owner]> {
        let range = to_absolute_range(start, end, self.owners.len())?;
        Some(&self.owners[range])
    }

    /// Set owner.
    pub fn set_owner(&mut self, owner: Owner, version: u64) -> Result<()> {
        if owner.expected_data_version != self.expected_data_version().unwrap_or_default() {
            return Err(Error::InvalidSuccessor(
                self.expected_data_version().unwrap_or_default(),
            ));
        }
        if owner.expected_auth_version != self.expected_auth_version() {
            return Err(Error::InvalidPermissionsSuccessor(
                self.expected_auth_version(),
            ));
        }
        if self.expected_owners_version() != version {
            return Err(Error::InvalidSuccessor(self.expected_owners_version()));
        }
        self.owners.push(owner);
        Ok(())
    }

    /// Returns true if the user is the current owner, false if not.
    pub fn is_owner(&self, user: PublicKey) -> bool {
        match self.owner_at(Version::FromEnd(1)) {
            Some(owner) => user == owner.public_key,
            _ => false,
        }
    }

    pub fn versions(&self) -> ExpectedVersions {
        ExpectedVersions::new(
            self.expected_data_version().unwrap_or_default(),
            self.expected_owners_version(),
            self.expected_auth_version(),
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
impl<P: Auth> MapBase<P, NonSentried> {
    /// Commit transaction.
    ///
    /// If the specified `expected_version` does not equal the entries count in data, an
    /// error will be returned.
    pub fn commit(&mut self, tx: Transaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: Operations = tx.into_iter().fold(
            Default::default(),
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
impl<P: Auth> MapBase<P, Sentried> {
    /// Commit transaction.
    ///
    /// If the specified `expected_version` does not equal the entries count in data, an
    /// error will be returned.
    pub fn commit(&mut self, tx: SentriedTransaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: SentriedOperations = tx.into_iter().fold(
            Default::default(),
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
impl MapBase<PublicAuth, Sentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PublicSentried { name, tag },
            data: BTreeMap::new(),
            auth: Vec::new(),
            owners: Vec::new(),
            version: Some(0),
            _flavour: Sentried,
        }
    }
}

impl Debug for MapBase<PublicAuth, Sentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicSentriedMap {:?}", self.name())
    }
}

/// Public + NonSentried
impl MapBase<PublicAuth, NonSentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Public { name, tag },
            data: BTreeMap::new(),
            auth: Vec::new(),
            owners: Vec::new(),
            version: None,
            _flavour: NonSentried,
        }
    }
}

impl Debug for MapBase<PublicAuth, NonSentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicMap {:?}", self.name())
    }
}

/// Private + Sentried
impl MapBase<PrivateAuth, Sentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PrivateSentried { name, tag },
            data: BTreeMap::new(),
            auth: Vec::new(),
            owners: Vec::new(),
            version: Some(0),
            _flavour: Sentried,
        }
    }

    /// Commit transaction.
    ///
    /// If the specified `expected_version` does not equal the entries count in data, an
    /// error will be returned.
    pub fn hard_commit(&mut self, tx: SentriedTransaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: SentriedOperations = tx.into_iter().fold(
            Default::default(),
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

impl Debug for MapBase<PrivateAuth, Sentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateSentriedMap {:?}", self.name())
    }
}

/// Private + NonSentried
impl MapBase<PrivateAuth, NonSentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Private { name, tag },
            data: BTreeMap::new(),
            auth: Vec::new(),
            owners: Vec::new(),
            version: None,
            _flavour: NonSentried,
        }
    }

    /// Commit transaction that potentially hard deletes data.
    ///
    /// If the specified `expected_version` does not equal the entries count in data, an
    /// error will be returned.
    pub fn hard_commit(&mut self, tx: Transaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: Operations = tx.into_iter().fold(
            Default::default(),
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

impl Debug for MapBase<PrivateAuth, NonSentried> {
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
        match (self, access) {
            (MapData::PublicSentried(_), AccessType::Read(_))
            | (MapData::Public(_), AccessType::Read(_)) => return true,
            _ => (),
        }
        match self {
            MapData::PublicSentried(data) => data.is_allowed(user, access),
            MapData::Public(data) => data.is_allowed(user, access),
            MapData::PrivateSentried(data) => data.is_allowed(user, access),
            MapData::Private(data) => data.is_allowed(user, access),
        }
    }

    pub fn address(&self) -> &Address {
        match self {
            MapData::PublicSentried(data) => data.address(),
            MapData::Public(data) => data.address(),
            MapData::PrivateSentried(data) => data.address(),
            MapData::Private(data) => data.address(),
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
        match self {
            MapData::PublicSentried(data) => data.is_owner(user),
            MapData::Public(data) => data.is_owner(user),
            MapData::PrivateSentried(data) => data.is_owner(user),
            MapData::Private(data) => data.is_owner(user),
        }
    }

    pub fn get(&self, key: &Key) -> Option<&Value> {
        match self {
            MapData::PublicSentried(data) => data.get(key),
            MapData::Public(data) => data.get(key),
            MapData::PrivateSentried(data) => data.get(key),
            MapData::Private(data) => data.get(key),
        }
    }

    pub fn expected_data_version(&self) -> u64 {
        match self {
            MapData::PublicSentried(data) => data.expected_data_version().unwrap_or_default(),
            MapData::Public(data) => data.expected_data_version().unwrap_or_default(),
            MapData::PrivateSentried(data) => data.expected_data_version().unwrap_or_default(),
            MapData::Private(data) => data.expected_data_version().unwrap_or_default(),
        }
    }

    pub fn expected_auth_version(&self) -> u64 {
        match self {
            MapData::PublicSentried(data) => data.expected_auth_version(),
            MapData::Public(data) => data.expected_auth_version(),
            MapData::PrivateSentried(data) => data.expected_auth_version(),
            MapData::Private(data) => data.expected_auth_version(),
        }
    }

    pub fn expected_owners_version(&self) -> u64 {
        match self {
            MapData::PublicSentried(data) => data.expected_owners_version(),
            MapData::Public(data) => data.expected_owners_version(),
            MapData::PrivateSentried(data) => data.expected_owners_version(),
            MapData::Private(data) => data.expected_owners_version(),
        }
    }

    pub fn versions(&self) -> ExpectedVersions {
        match self {
            MapData::PublicSentried(data) => data.versions(),
            MapData::Public(data) => data.versions(),
            MapData::PrivateSentried(data) => data.versions(),
            MapData::Private(data) => data.versions(),
        }
    }

    // Returns the history of a specified key.
    pub fn key_history(&self, key: &Key) -> Option<&StoredValues> {
        match self {
            MapData::PublicSentried(data) => data.key_history(key),
            MapData::Public(data) => data.key_history(key),
            MapData::PrivateSentried(data) => data.key_history(key),
            MapData::Private(data) => data.key_history(key),
        }
    }

    /// Returns a range in the history of a specified key.
    pub fn key_history_range(&self, key: &Key, from: Version, to: Version) -> Option<StoredValues> {
        match self {
            MapData::PublicSentried(data) => data.key_history_range(key, from, to),
            MapData::Public(data) => data.key_history_range(key, from, to),
            MapData::PrivateSentried(data) => data.key_history_range(key, from, to),
            MapData::Private(data) => data.key_history_range(key, from, to),
        }
    }

    /// Returns history for all keys
    pub fn key_histories(&self) -> &DataHistories {
        match self {
            MapData::PublicSentried(data) => data.key_histories(),
            MapData::Public(data) => data.key_histories(),
            MapData::PrivateSentried(data) => data.key_histories(),
            MapData::Private(data) => data.key_histories(),
        }
    }

    pub fn owner_at(&self, version: impl Into<Version>) -> Option<&Owner> {
        match self {
            MapData::PublicSentried(data) => data.owner_at(version),
            MapData::Public(data) => data.owner_at(version),
            MapData::PrivateSentried(data) => data.owner_at(version),
            MapData::Private(data) => data.owner_at(version),
        }
    }

    /// Returns history of all owners
    pub fn public_owner_histories(&self) -> Result<&Vec<Owner>> {
        let result = match self {
            MapData::PublicSentried(data) => Some(data.owner_histories()),
            MapData::Public(data) => Some(data.owner_histories()),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    /// Returns history of all owners
    pub fn private_owner_histories(&self) -> Result<&Vec<Owner>> {
        let result = match self {
            MapData::PrivateSentried(data) => Some(data.owner_histories()),
            MapData::Private(data) => Some(data.owner_histories()),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    /// Get history of owners within the range of versions specified.
    pub fn public_owner_history_range(&self, start: Version, end: Version) -> Result<&[Owner]> {
        let result = match self {
            MapData::PublicSentried(data) => data.owner_history_range(start, end),
            MapData::Public(data) => data.owner_history_range(start, end),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    /// Get history of owners within the range of versions specified.
    pub fn private_owner_history_range(&self, start: Version, end: Version) -> Result<&[Owner]> {
        let result = match self {
            MapData::PrivateSentried(data) => data.owner_history_range(start, end),
            MapData::Private(data) => data.owner_history_range(start, end),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    pub fn public_permissions_at(
        &self,
        user: User,
        version: impl Into<Version>,
    ) -> Result<PublicPermissions> {
        self.public_auth_at(version)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    pub fn private_permissions_at(
        &self,
        user: PublicKey,
        version: impl Into<Version>,
    ) -> Result<PrivatePermissions> {
        self.private_auth_at(version)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    pub fn public_auth_at(&self, version: impl Into<Version>) -> Result<&PublicAuth> {
        let auth = match self {
            MapData::PublicSentried(data) => data.auth_at(version),
            MapData::Public(data) => data.auth_at(version),
            _ => return Err(Error::InvalidOperation),
        };
        auth.ok_or(Error::NoSuchEntry)
    }

    pub fn private_auth_at(&self, version: impl Into<Version>) -> Result<&PrivateAuth> {
        let auth = match self {
            MapData::PrivateSentried(data) => data.auth_at(version),
            MapData::Private(data) => data.auth_at(version),
            _ => return Err(Error::InvalidOperation),
        };
        auth.ok_or(Error::NoSuchEntry)
    }

    /// Returns history of all authorization states
    pub fn public_auth_histories(&self) -> Result<&Vec<PublicAuth>> {
        let result = match self {
            MapData::PublicSentried(data) => Some(data.auth_histories()),
            MapData::Public(data) => Some(data.auth_histories()),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    /// Returns history of all authorization states
    pub fn private_auth_histories(&self) -> Result<&Vec<PrivateAuth>> {
        let result = match self {
            MapData::PrivateSentried(data) => Some(data.auth_histories()),
            MapData::Private(data) => Some(data.auth_histories()),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    /// Get history of authorization within the range of versions specified.
    pub fn public_auth_history_range(&self, start: Version, end: Version) -> Result<&[PublicAuth]> {
        let result = match self {
            MapData::PublicSentried(data) => data.auth_history_range(start, end),
            MapData::Public(data) => data.auth_history_range(start, end),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    /// Get history of authorization within the range of versions specified.
    pub fn private_auth_history_range(
        &self,
        start: Version,
        end: Version,
    ) -> Result<&[PrivateAuth]> {
        let result = match self {
            MapData::PrivateSentried(data) => data.auth_history_range(start, end),
            MapData::Private(data) => data.auth_history_range(start, end),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    pub fn shell(&self, version: impl Into<Version>) -> Result<Self> {
        match self {
            MapData::PublicSentried(map) => map.shell(version).map(MapData::PublicSentried),
            MapData::Public(map) => map.shell(version).map(MapData::Public),
            MapData::PrivateSentried(map) => map.shell(version).map(MapData::PrivateSentried),
            MapData::Private(map) => map.shell(version).map(MapData::Private),
        }
    }

    /// Commits transaction.
    pub fn commit(&mut self, tx: MapTransaction) -> Result<()> {
        match self {
            MapData::PrivateSentried(map) => match tx {
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
            MapData::Private(map) => match tx {
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
            MapData::PublicSentried(map) => match tx {
                MapTransaction::Commit(options) => {
                    if let SentryOption::ExpectVersion(stx) = options {
                        return map.commit(stx);
                    }
                }
                _ => return Err(Error::InvalidOperation),
            },
            MapData::Public(map) => match tx {
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
