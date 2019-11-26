// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#![allow(dead_code)]

use crate::shared_data::{
    to_absolute_index, to_absolute_range, Action, Address, ExpectedIndices, Index, Kind,
    NonSentried, Owner, Permissions, PrivatePermissionSet, PrivatePermissions, PublicPermissionSet,
    PublicPermissions, Sentried, User,
};
use crate::{EntryError, Error, PublicKey, Result, XorName};
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map::Entry as DataEntry, BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    mem,
};

pub type PublicSentriedMap = Map<PublicPermissions, Sentried>;
pub type PublicMap = Map<PublicPermissions, NonSentried>;
pub type PrivateSentriedMap = Map<PrivatePermissions, Sentried>;
pub type PrivateMap = Map<PrivatePermissions, NonSentried>;
pub type EntryHistories = BTreeMap<Key, Vec<StoredValue>>;
pub type Entries = Vec<Entry>;

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
pub struct Entry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl Entry {
    pub fn new(key: Vec<u8>, value: Vec<u8>) -> Self {
        Self { key, value }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct Map<P, S> {
    address: Address,
    data: EntryHistories,
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

    /// Return all entries.
    pub fn entries(&self) -> Vec<Entry> {
        self.data
            .iter()
            .filter_map(move |(key, values)| match values.last() {
                Some(StoredValue::Value(val)) => Some(Entry {
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

    /// Get a complete list of permissions from the entry in the permissions list at the specified
    /// index.
    pub fn permissions_range(&self, start: Index, end: Index) -> Option<&[P]> {
        let range = to_absolute_range(start, end, self.permissions.len())?;
        Some(&self.permissions[range])
    }

    /// Add a new permissions entry.
    /// The `Perm` struct should contain valid indices.
    pub fn append_permissions(&mut self, permissions: P, index: u64) -> Result<()> {
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

    /// Fetch permissions at index.
    pub fn permissions(&self, index: impl Into<Index>) -> Option<&P> {
        let index = to_absolute_index(index.into(), self.permissions.len())?;
        self.permissions.get(index)
    }

    pub fn check_permission(&self, user: PublicKey, action: Action) -> Result<()> {
        if self
            .owner(Index::FromEnd(1))
            .ok_or(Error::InvalidOwners)?
            .public_key
            == user
        {
            Ok(())
        } else {
            self.permissions(Index::FromEnd(1))
                .ok_or(Error::InvalidPermissions)?
                .is_action_allowed(user, action)
        }
    }

    /// Fetch owner at index.
    pub fn owner(&self, index: impl Into<Index>) -> Option<&Owner> {
        let index = to_absolute_index(index.into(), self.owners.len())?;
        self.owners.get(index)
    }

    /// Get a complete list of owners from the entry in the permissions list at the specified index.
    pub fn owners_range(&self, start: Index, end: Index) -> Option<&[Owner]> {
        let range = to_absolute_range(start, end, self.owners.len())?;
        Some(&self.owners[range])
    }

    /// Add a new owner entry.
    pub fn append_owner(&mut self, owner: Owner, index: u64) -> Result<()> {
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

    /// Check if the user is the current owner.
    pub fn check_is_current_owner(&self, user: PublicKey) -> Result<()> {
        if self
            .owner(Index::FromEnd(1))
            .ok_or_else(|| Error::InvalidOwners)?
            .public_key
            == user
        {
            Ok(())
        } else {
            Err(Error::AccessDenied)
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

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub enum MapTransaction {
    AnyVersion(Transaction),
    ExpectVersion(SentriedTransaction),
}

pub type Key = Vec<u8>;
pub type Value = Vec<u8>;
pub type KvPair = (Key, Value);
pub type Transaction = Vec<Cmd>;

pub type ExpectedVersion = u64;
pub type SentriedKey = (Key, ExpectedVersion);
pub type SentriedKvPair = (KvPair, ExpectedVersion);
pub type SentriedTransaction = Vec<SentriedCmd>;

// /// Common methods for NonSentried flavours.
// impl<P: Permissions> Map<P, NonSentried> {
//     fn commit(&mut self, tx: Transaction) -> Result<()> {
//         let operations: Operations<P> = tx.into_iter().fold(
//             (
//                 BTreeSet::<KvPair>::new(),
//                 BTreeSet::<KvPair>::new(),
//                 BTreeSet::<Key>::new(),
//                 PhantomData::<P>,
//             ),
//             |(mut insert, mut update, mut delete, phantom), cmd| {
//                 match cmd {
//                     Cmd::Insert(kv_pair) => {
//                         let _ = insert.insert(kv_pair);
//                     }
//                     Cmd::Update(kv_pair) => {
//                         let _ = update.insert(kv_pair);
//                     }
//                     Cmd::Delete(key) => {
//                         let _ = delete.insert(key);
//                     }
//                 };
//                 (insert, update, delete, phantom)
//             },
//         );

//         self.apply(operations)
//     }
// }

// /// Common methods for Sentried flavours.
// impl<P: Permissions> Map<P, Sentried> {
//     /// Commit transaction.
//     ///
//     /// If the specified `expected_index` does not equal the entries count in data, an
//     /// error will be returned.
//     pub fn commit_sentried(&mut self, tx: SentriedTransaction) -> Result<()> {
//         // Deconstruct actions into inserts, updates, and deletes
//         let operations: SentriedOperations<P> = tx.into_iter().fold(
//             (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), PhantomData::<P>),
//             |(mut insert, mut update, mut delete, phantom), cmd| {
//                 match cmd {
//                     SentriedCmd::Insert(sentried_kvpair) => {
//                         let _ = insert.insert(sentried_kvpair);
//                     }
//                     SentriedCmd::Update(sentried_kvpair) => {
//                         let _ = update.insert(sentried_kvpair);
//                     }
//                     SentriedCmd::Delete(sentried_key) => {
//                         let _ = delete.insert(sentried_key);
//                     }
//                 };
//                 (insert, update, delete, phantom)
//             },
//         );

//         self.apply(operations)
//     }
// }

type PrivateOperations = (
    BTreeSet<KvPair>,
    BTreeSet<KvPair>,
    BTreeSet<Key>,
    PhantomData<PrivatePermissions>,
);
type PublicOperations = (
    BTreeSet<KvPair>,
    BTreeSet<KvPair>,
    BTreeSet<Key>,
    PhantomData<PublicPermissions>,
);
type PrivateSentriedOperations = (
    BTreeSet<SentriedKvPair>,
    BTreeSet<SentriedKvPair>,
    BTreeSet<SentriedKey>,
    PhantomData<PrivatePermissions>,
);
type PublicSentriedOperations = (
    BTreeSet<SentriedKvPair>,
    BTreeSet<SentriedKvPair>,
    BTreeSet<SentriedKey>,
    PhantomData<PublicPermissions>,
);

enum OperationSet {
    Private(PrivateOperations),
    Public(PublicOperations),
    PrivateSentried(PrivateSentriedOperations),
    PublicSentried(PublicSentriedOperations),
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

    /// Commit transaction.
    ///
    /// If the specified `expected_index` does not equal the entries count in data, an
    /// error will be returned.
    pub fn commit(&mut self, tx: SentriedTransaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: PublicSentriedOperations = tx.into_iter().fold(
            (
                BTreeSet::new(),
                BTreeSet::new(),
                BTreeSet::new(),
                PhantomData::<PublicPermissions>,
            ),
            |(mut insert, mut update, mut delete, phantom), cmd| {
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
                (insert, update, delete, phantom)
            },
        );

        self.apply(operations)
    }

    fn apply(&mut self, tx: PublicSentriedOperations) -> Result<()> {
        let (insert, update, delete, _) = tx;
        let op_count = insert.len() + update.len() + delete.len();
        if op_count == 0 {
            return Err(Error::InvalidOperation);
        }
        let mut new_data = self.data.clone();
        let mut errors = BTreeMap::new();

        for ((key, val), version) in insert {
            match new_data.entry(key) {
                DataEntry::Occupied(mut entry) => match entry.get().last() {
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
                DataEntry::Vacant(entry) => {
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
                DataEntry::Occupied(mut entry) => {
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
                DataEntry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        for (key, version) in delete {
            match new_data.entry(key.clone()) {
                DataEntry::Occupied(mut entry) => {
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
                DataEntry::Vacant(entry) => {
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

    /// Commit transaction.
    ///
    /// If the specified `expected_index` does not equal the entries count in data, an
    /// error will be returned.
    pub fn commit(&mut self, tx: Transaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: PublicOperations = tx.into_iter().fold(
            (
                BTreeSet::<KvPair>::new(),
                BTreeSet::<KvPair>::new(),
                BTreeSet::<Key>::new(),
                PhantomData::<PublicPermissions>,
            ),
            |(mut insert, mut update, mut delete, phantom), cmd| {
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
                (insert, update, delete, phantom)
            },
        );

        self.apply(operations)
    }

    fn apply(&mut self, tx: PublicOperations) -> Result<()> {
        let (insert, update, delete, _) = tx;
        if insert.is_empty() && update.is_empty() && delete.is_empty() {
            return Err(Error::InvalidOperation);
        }
        let mut new_data = self.data.clone();
        let mut errors = BTreeMap::new();

        for (key, val) in insert {
            match new_data.entry(key) {
                DataEntry::Occupied(mut entry) => {
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
                DataEntry::Vacant(entry) => {
                    let _ = entry.insert(vec![StoredValue::Value(val)]); // todo: fix From impl
                }
            }
        }

        // maintains history
        for (key, val) in update {
            match new_data.entry(key) {
                DataEntry::Occupied(mut entry) => {
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
                DataEntry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        // maintains history
        for key in delete {
            match new_data.entry(key.clone()) {
                DataEntry::Occupied(mut entry) => {
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
                DataEntry::Vacant(entry) => {
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
    pub fn commit(&mut self, tx: SentriedTransaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: PrivateSentriedOperations = tx.into_iter().fold(
            (
                BTreeSet::new(),
                BTreeSet::new(),
                BTreeSet::new(),
                PhantomData::<PrivatePermissions>,
            ),
            |(mut insert, mut update, mut delete, phantom), cmd| {
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
                (insert, update, delete, phantom)
            },
        );

        self.apply(operations)
    }

    fn apply(&mut self, operations: PrivateSentriedOperations) -> Result<()> {
        let (insert, update, delete, _) = operations;
        let op_count = insert.len() + update.len() + delete.len();
        if op_count == 0 {
            return Err(Error::InvalidOperation);
        }
        let mut new_data = self.data.clone();
        let mut errors = BTreeMap::new();

        for ((key, val), version) in insert {
            match new_data.entry(key.clone()) {
                DataEntry::Occupied(mut entry) => {
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
                DataEntry::Vacant(entry) => {
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
                DataEntry::Occupied(mut entry) => {
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
                DataEntry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        // removes old data, while also incrementing version
        for (key, version) in delete {
            match new_data.entry(key.clone()) {
                DataEntry::Occupied(mut entry) => {
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
                DataEntry::Vacant(entry) => {
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

    /// Commit transaction.
    ///
    /// If the specified `expected_index` does not equal the entries count in data, an
    /// error will be returned.
    pub fn commit(&mut self, tx: Transaction) -> Result<()> {
        // Deconstruct tx into inserts, updates, and deletes
        let operations: PrivateOperations = tx.into_iter().fold(
            (
                BTreeSet::<KvPair>::new(),
                BTreeSet::<KvPair>::new(),
                BTreeSet::<Key>::new(),
                PhantomData::<PrivatePermissions>,
            ),
            |(mut insert, mut update, mut delete, phantom), cmd| {
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
                (insert, update, delete, phantom)
            },
        );

        self.apply(operations)
    }

    fn apply(&mut self, operations: PrivateOperations) -> Result<()> {
        let (insert, update, delete, _) = operations;
        if insert.is_empty() && update.is_empty() && delete.is_empty() {
            return Err(Error::InvalidOperation);
        }
        let mut new_data = self.data.clone();
        let mut errors = BTreeMap::new();

        for (key, val) in insert {
            match new_data.entry(key) {
                DataEntry::Occupied(entry) => {
                    let _ = errors.insert(
                        entry.key().clone(),
                        EntryError::EntryExists(entry.get().len() as u8),
                    );
                }
                DataEntry::Vacant(entry) => {
                    let _ = entry.insert(vec![StoredValue::Value(val)]);
                }
            }
        }

        for (key, val) in update {
            match new_data.entry(key) {
                DataEntry::Occupied(mut entry) => {
                    let _ = entry.insert(vec![StoredValue::Value(val)]); // replace the vec, which always has 1 single value if it exists
                }
                DataEntry::Vacant(entry) => {
                    let _ = errors.insert(entry.key().clone(), EntryError::NoSuchEntry);
                }
            }
        }

        for key in delete {
            match new_data.entry(key.clone()) {
                DataEntry::Occupied(_) => {
                    let _ = new_data.remove(&key);
                }
                DataEntry::Vacant(entry) => {
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
    pub fn check_permission(&self, action: Action, user: PublicKey) -> Result<()> {
        match (self, action) {
            (Data::PublicSentried(_), Action::Read) | (Data::Public(_), Action::Read) => {
                return Ok(())
            }
            _ => (),
        }

        match self {
            Data::PublicSentried(data) => data.check_permission(user, action),
            Data::Public(data) => data.check_permission(user, action),
            Data::PrivateSentried(data) => data.check_permission(user, action),
            Data::Private(data) => data.check_permission(user, action),
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

    pub fn owner(&self, index: impl Into<Index>) -> Option<&Owner> {
        match self {
            Data::PublicSentried(data) => data.owner(index),
            Data::Public(data) => data.owner(index),
            Data::PrivateSentried(data) => data.owner(index),
            Data::Private(data) => data.owner(index),
        }
    }

    pub fn check_is_current_owner(&self, user: PublicKey) -> Result<()> {
        match self {
            Data::PublicSentried(data) => data.check_is_current_owner(user),
            Data::Public(data) => data.check_is_current_owner(user),
            Data::PrivateSentried(data) => data.check_is_current_owner(user),
            Data::Private(data) => data.check_is_current_owner(user),
        }
    }

    pub fn public_user_permissions(
        &self,
        user: User,
        index: impl Into<Index>,
    ) -> Result<PublicPermissionSet> {
        self.public_permissions(index)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    pub fn private_user_permissions(
        &self,
        user: PublicKey,
        index: impl Into<Index>,
    ) -> Result<PrivatePermissionSet> {
        self.private_permissions(index)?
            .permissions()
            .get(&user)
            .cloned()
            .ok_or(Error::NoSuchEntry)
    }

    pub fn public_permissions(&self, index: impl Into<Index>) -> Result<&PublicPermissions> {
        let permissions = match self {
            Data::PublicSentried(data) => data.permissions(index),
            Data::Public(data) => data.permissions(index),
            _ => return Err(Error::NoSuchData),
        };
        permissions.ok_or(Error::NoSuchEntry)
    }

    pub fn private_permissions(&self, index: impl Into<Index>) -> Result<&PrivatePermissions> {
        let permissions = match self {
            Data::PrivateSentried(data) => data.permissions(index),
            Data::Private(data) => data.permissions(index),
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
            Data::PrivateSentried(map) => {
                if let MapTransaction::ExpectVersion(stx) = tx {
                    return map.commit(stx);
                }
            }
            Data::Private(map) => {
                if let MapTransaction::AnyVersion(atx) = tx {
                    return map.commit(atx);
                }
            }
            Data::PublicSentried(map) => {
                if let MapTransaction::ExpectVersion(stx) = tx {
                    return map.commit(stx);
                }
            }
            Data::Public(map) => {
                if let MapTransaction::AnyVersion(atx) = tx {
                    return map.commit(atx);
                }
            }
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
    use std::collections::BTreeMap;
    use threshold_crypto::SecretKey;
    use unwrap::{unwrap, unwrap_err};

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
    fn append_permissions() {
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);

        // Append the first permission set with correct ExpectedIndices - should pass.
        let res = data.append_permissions(
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

        // Verify that the permissions have been added.
        assert_eq!(
            unwrap!(data.permissions_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );

        // Append another permissions entry with incorrect ExpectedIndices - should fail.
        let res = data.append_permissions(
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

        // Verify that the number of permissions has not been changed.
        assert_eq!(
            unwrap!(data.permissions_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );
    }

    #[test]
    fn append_owners() {
        let owner_pk = gen_public_key();

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);

        // Append the first owner with correct ExpectedIndices - should pass.
        let res = data.append_owner(
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

        // Verify that the owner has been added.
        assert_eq!(
            unwrap!(data.owners_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );

        // Append another owners entry with incorrect ExpectedIndices - should fail.
        let res = data.append_owner(
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

        // Verify that the number of owners has not been changed.
        assert_eq!(
            unwrap!(data.owners_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );
    }

    #[test]
    fn assert_shell() {
        let owner_pk = gen_public_key();
        let owner_pk1 = gen_public_key();

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);

        let _ = data.append_owner(
            Owner {
                public_key: owner_pk,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        );

        let _ = data.append_owner(
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
    fn get_permissions() {
        let public_key = gen_public_key();
        let invalid_public_key = gen_public_key();

        let mut pub_permissions = PublicPermissions {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 0,
        };
        let _ = pub_permissions.permissions.insert(
            User::Specific(public_key),
            PublicPermissionSet::new(false, false),
        );

        let mut private_permissions = PrivatePermissions {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 0,
        };
        let _ = private_permissions
            .permissions
            .insert(public_key, PrivatePermissionSet::new(false, false, false));

        // pub, unseq
        let mut data = PublicMap::new(rand::random(), 20);
        unwrap!(data.append_permissions(pub_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.public_permissions(0), Ok(&pub_permissions));
        assert_eq!(data.private_permissions(0), Err(Error::NoSuchData));

        assert_eq!(
            data.public_user_permissions(User::Specific(public_key), 0),
            Ok(PublicPermissionSet::new(false, false))
        );
        assert_eq!(
            data.private_user_permissions(public_key, 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.public_user_permissions(User::Specific(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // pub, seq
        let mut data = PublicSentriedMap::new(rand::random(), 20);
        unwrap!(data.append_permissions(pub_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.public_permissions(0), Ok(&pub_permissions));
        assert_eq!(data.private_permissions(0), Err(Error::NoSuchData));

        assert_eq!(
            data.public_user_permissions(User::Specific(public_key), 0),
            Ok(PublicPermissionSet::new(false, false))
        );
        assert_eq!(
            data.private_user_permissions(public_key, 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.public_user_permissions(User::Specific(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // Private, unseq
        let mut data = PrivateMap::new(rand::random(), 20);
        unwrap!(data.append_permissions(private_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.private_permissions(0), Ok(&private_permissions));
        assert_eq!(data.public_permissions(0), Err(Error::NoSuchData));

        assert_eq!(
            data.private_user_permissions(public_key, 0),
            Ok(PrivatePermissionSet::new(false, false, false))
        );
        assert_eq!(
            data.public_user_permissions(User::Specific(public_key), 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.private_user_permissions(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );

        // Private, seq
        let mut data = PrivateSentriedMap::new(rand::random(), 20);
        unwrap!(data.append_permissions(private_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.private_permissions(0), Ok(&private_permissions));
        assert_eq!(data.public_permissions(0), Err(Error::NoSuchData));

        assert_eq!(
            data.private_user_permissions(public_key, 0),
            Ok(PrivatePermissionSet::new(false, false, false))
        );
        assert_eq!(
            data.public_user_permissions(User::Specific(public_key), 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.private_user_permissions(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );
    }

    fn gen_public_key() -> PublicKey {
        PublicKey::Bls(SecretKey::random().public_key())
    }

    #[test]
    fn check_pub_permission() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut inner = PublicSentriedMap::new(XorName([1; 32]), 100);

        // no owner
        let data = Data::from(inner.clone());
        assert_eq!(
            data.check_permission(Action::Append, public_key_0),
            Err(Error::InvalidOwners)
        );
        // data is Public - read always allowed
        assert_eq!(data.check_permission(Action::Read, public_key_0), Ok(()));

        // no permissions
        unwrap!(inner.append_owner(
            Owner {
                public_key: public_key_0,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        ));
        let data = Data::from(inner.clone());

        assert_eq!(data.check_permission(Action::Append, public_key_0), Ok(()));
        assert_eq!(
            data.check_permission(Action::Append, public_key_1),
            Err(Error::InvalidPermissions)
        );
        // data is Public - read always allowed
        assert_eq!(data.check_permission(Action::Read, public_key_0), Ok(()));
        assert_eq!(data.check_permission(Action::Read, public_key_1), Ok(()));

        // with permissions
        let mut permissions = PublicPermissions {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 1,
        };
        let _ = permissions
            .permissions
            .insert(User::Anyone, PublicPermissionSet::new(true, false));
        let _ = permissions.permissions.insert(
            User::Specific(public_key_1),
            PublicPermissionSet::new(None, true),
        );
        unwrap!(inner.append_permissions(permissions, 0));
        let data = Data::from(inner);

        // existing key fallback
        assert_eq!(data.check_permission(Action::Append, public_key_1), Ok(()));
        // existing key override
        assert_eq!(
            data.check_permission(Action::ManagePermissions, public_key_1),
            Ok(())
        );
        // non-existing keys are handled by `Anyone`
        assert_eq!(data.check_permission(Action::Append, public_key_2), Ok(()));
        assert_eq!(
            data.check_permission(Action::ManagePermissions, public_key_2),
            Err(Error::AccessDenied)
        );
        // data is Public - read always allowed
        assert_eq!(data.check_permission(Action::Read, public_key_0), Ok(()));
        assert_eq!(data.check_permission(Action::Read, public_key_1), Ok(()));
        assert_eq!(data.check_permission(Action::Read, public_key_2), Ok(()));
    }

    #[test]
    fn check_private_permission() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut inner = PrivateSentriedMap::new(XorName([1; 32]), 100);

        // no owner
        let data = Data::from(inner.clone());
        assert_eq!(
            data.check_permission(Action::Read, public_key_0),
            Err(Error::InvalidOwners)
        );

        // no permissions
        unwrap!(inner.append_owner(
            Owner {
                public_key: public_key_0,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        ));
        let data = Data::from(inner.clone());

        assert_eq!(data.check_permission(Action::Read, public_key_0), Ok(()));
        assert_eq!(
            data.check_permission(Action::Read, public_key_1),
            Err(Error::InvalidPermissions)
        );

        // with permissions
        let mut permissions = PrivatePermissions {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 1,
        };
        let _ = permissions
            .permissions
            .insert(public_key_1, PrivatePermissionSet::new(true, true, false));
        unwrap!(inner.append_permissions(permissions, 0));
        let data = Data::from(inner);

        // existing key
        assert_eq!(data.check_permission(Action::Read, public_key_1), Ok(()));
        assert_eq!(data.check_permission(Action::Append, public_key_1), Ok(()));
        assert_eq!(
            data.check_permission(Action::ManagePermissions, public_key_1),
            Err(Error::AccessDenied)
        );

        // non-existing key
        assert_eq!(
            data.check_permission(Action::Read, public_key_2),
            Err(Error::InvalidPermissions)
        );
        assert_eq!(
            data.check_permission(Action::Append, public_key_2),
            Err(Error::InvalidPermissions)
        );
        assert_eq!(
            data.check_permission(Action::ManagePermissions, public_key_2),
            Err(Error::InvalidPermissions)
        );
    }
}
