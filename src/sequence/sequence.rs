// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::permissions::{
    DataPermissions, PrivatePermissionSet, PrivatePermissions, PublicPermissionSet,
    PublicPermissions, Request,
};
use crate::shared_data::{
    to_absolute_index, to_absolute_range, Address, ExpectedIndices, Index, Kind, NonSentried,
    Owner, Sentried, User, Value,
};
use crate::{Error, PublicKey, Result, XorName};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Formatter};

pub type PublicSentriedSequence = SequenceBase<PublicPermissions, Sentried>;
pub type PublicSequence = SequenceBase<PublicPermissions, NonSentried>;
pub type PrivateSentriedSequence = SequenceBase<PrivatePermissions, Sentried>;
pub type PrivateSequence = SequenceBase<PrivatePermissions, NonSentried>;
pub type Values = Vec<Value>;

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum SequencePermissions {
    Public(PublicPermissions),
    Private(PrivatePermissions),
}

impl From<PrivatePermissions> for SequencePermissions {
    fn from(permissions: PrivatePermissions) -> Self {
        SequencePermissions::Private(permissions)
    }
}

impl From<PublicPermissions> for SequencePermissions {
    fn from(permissions: PublicPermissions) -> Self {
        SequencePermissions::Public(permissions)
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default, Debug)]
pub struct DataEntry {
    pub index: u64,
    pub value: Vec<u8>,
}

impl DataEntry {
    pub fn new(index: u64, value: Vec<u8>) -> Self {
        Self { index, value }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct SequenceBase<P, S> {
    address: Address,
    data: Values,
    permissions: Vec<P>,
    // This is the history of owners, with each entry representing an owner.  Each single owner
    // could represent an individual user, or a group of users, depending on the `PublicKey` type.
    owners: Vec<Owner>,
    _flavour: S,
}

/// Common methods for all `Sequence` flavours.
impl<P, S> SequenceBase<P, S>
where
    P: DataPermissions,
    S: Copy,
{
    /// Returns the data shell - that is - everything except the Values themselves.
    pub fn shell(&self, expected_data_index: impl Into<Index>) -> Result<Self> {
        let expected_data_index = to_absolute_index(
            expected_data_index.into(),
            self.expected_data_index() as usize,
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
            data: Vec::new(),
            permissions,
            owners,
            _flavour: self._flavour,
        })
    }

    /// Return a value for the given index (if it is present).
    pub fn get(&self, index: u64) -> Option<&Value> {
        self.data.get(index as usize)
    }

    /// Return the current data entry (if it is present).
    pub fn current_data_entry(&self) -> Option<DataEntry> {
        match self.data.last() {
            Some(value) => Some(DataEntry::new(self.data.len() as u64, value.to_vec())),
            None => None,
        }
    }

    /// Get a range of values within the given indices.
    pub fn in_range(&self, start: Index, end: Index) -> Option<Values> {
        let range = to_absolute_range(start, end, self.data.len())?;
        Some(self.data[range].to_vec())
    }

    /// Return all Values.
    pub fn values(&self) -> &Values {
        &self.data
    }

    /// Return the address of this Sequence.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Return the name of this Sequence.
    pub fn name(&self) -> &XorName {
        self.address.name()
    }

    /// Return the type tag of this Sequence.
    pub fn tag(&self) -> u64 {
        self.address.tag()
    }

    /// Return the expected data index.
    pub fn expected_data_index(&self) -> u64 {
        self.data.len() as u64
    }

    /// Return the expected owners index.
    pub fn expected_owners_index(&self) -> u64 {
        self.owners.len() as u64
    }

    /// Return the expected permissions index.
    pub fn expected_permissions_index(&self) -> u64 {
        self.permissions.len() as u64
    }

    /// Get history of permission within the range of indices specified.
    pub fn permission_history_range(&self, start: Index, end: Index) -> Option<&[P]> {
        let range = to_absolute_range(start, end, self.permissions.len())?;
        Some(&self.permissions[range])
    }

    /// Set permissions.
    /// The `Permissions` struct needs to contain the correct expected indices.
    pub fn set_permissions(&mut self, permissions: P, index: u64) -> Result<()> {
        if permissions.expected_data_index() != self.expected_data_index() {
            return Err(Error::InvalidSuccessor(self.expected_data_index()));
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
        if owner.expected_data_index != self.expected_data_index() {
            return Err(Error::InvalidSuccessor(self.expected_data_index()));
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

    /// Returns true if the user is the current owner.
    pub fn is_owner(&self, user: PublicKey) -> bool {
        match self.owner_at(Index::FromEnd(1)) {
            Some(owner) => user == owner.public_key,
            _ => false,
        }
    }

    pub fn indices(&self) -> ExpectedIndices {
        ExpectedIndices::new(
            self.expected_data_index(),
            self.expected_owners_index(),
            self.expected_permissions_index(),
        )
    }
}

/// Common methods for NonSentried flavours.
impl<P: DataPermissions> SequenceBase<P, NonSentried> {
    /// Append new Values.
    pub fn append(&mut self, values: Values) -> Result<()> {
        self.data.extend(values);
        Ok(())
    }
}

/// Common methods for Sentried flavours.
impl<P: DataPermissions> SequenceBase<P, Sentried> {
    /// Append new Values.
    ///
    /// If the specified `expected_index` does not equal the Values count in data, an
    /// error will be returned.
    pub fn append(&mut self, values: Values, expected_index: u64) -> Result<()> {
        if expected_index != self.data.len() as u64 {
            return Err(Error::InvalidSuccessor(self.data.len() as u64));
        }

        self.data.extend(values);
        Ok(())
    }
}

/// Public + Sentried
impl SequenceBase<PublicPermissions, Sentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PublicSentried { name, tag },
            data: Vec::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
            _flavour: Sentried,
        }
    }
}

impl Debug for SequenceBase<PublicPermissions, Sentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicSentriedSequence {:?}", self.name())
    }
}

/// Public + NonSentried
impl SequenceBase<PublicPermissions, NonSentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Public { name, tag },
            data: Vec::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
            _flavour: NonSentried,
        }
    }
}

impl Debug for SequenceBase<PublicPermissions, NonSentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicSequence {:?}", self.name())
    }
}

/// Private + Sentried
impl SequenceBase<PrivatePermissions, Sentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PrivateSentried { name, tag },
            data: Vec::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
            _flavour: Sentried,
        }
    }
}

impl Debug for SequenceBase<PrivatePermissions, Sentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateSentriedSequence {:?}", self.name())
    }
}

/// Private + NonSentried
impl SequenceBase<PrivatePermissions, NonSentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Private { name, tag },
            data: Vec::new(),
            permissions: Vec::new(),
            owners: Vec::new(),
            _flavour: NonSentried,
        }
    }
}

impl Debug for SequenceBase<PrivatePermissions, NonSentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateSequence {:?}", self.name())
    }
}

/// Object storing a Sequence variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum SequenceData {
    PublicSentried(PublicSentriedSequence),
    Public(PublicSequence),
    PrivateSentried(PrivateSentriedSequence),
    Private(PrivateSequence),
}

impl SequenceData {
    pub fn is_permitted(&self, request: Request, user: PublicKey) -> bool {
        match (self, request) {
            (SequenceData::PublicSentried(_), Request::Query(_))
            | (SequenceData::Public(_), Request::Query(_)) => return true,
            _ => (),
        }
        match self {
            SequenceData::PublicSentried(data) => data.is_permitted(user, request),
            SequenceData::Public(data) => data.is_permitted(user, request),
            SequenceData::PrivateSentried(data) => data.is_permitted(user, request),
            SequenceData::Private(data) => data.is_permitted(user, request),
        }
    }

    pub fn address(&self) -> &Address {
        match self {
            SequenceData::PublicSentried(data) => data.address(),
            SequenceData::Public(data) => data.address(),
            SequenceData::PrivateSentried(data) => data.address(),
            SequenceData::Private(data) => data.address(),
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
            SequenceData::PublicSentried(data) => data.expected_data_index(),
            SequenceData::Public(data) => data.expected_data_index(),
            SequenceData::PrivateSentried(data) => data.expected_data_index(),
            SequenceData::Private(data) => data.expected_data_index(),
        }
    }

    pub fn expected_permissions_index(&self) -> u64 {
        match self {
            SequenceData::PublicSentried(data) => data.expected_permissions_index(),
            SequenceData::Public(data) => data.expected_permissions_index(),
            SequenceData::PrivateSentried(data) => data.expected_permissions_index(),
            SequenceData::Private(data) => data.expected_permissions_index(),
        }
    }

    pub fn expected_owners_index(&self) -> u64 {
        match self {
            SequenceData::PublicSentried(data) => data.expected_owners_index(),
            SequenceData::Public(data) => data.expected_owners_index(),
            SequenceData::PrivateSentried(data) => data.expected_owners_index(),
            SequenceData::Private(data) => data.expected_owners_index(),
        }
    }

    pub fn in_range(&self, start: Index, end: Index) -> Option<Values> {
        match self {
            SequenceData::PublicSentried(data) => data.in_range(start, end),
            SequenceData::Public(data) => data.in_range(start, end),
            SequenceData::PrivateSentried(data) => data.in_range(start, end),
            SequenceData::Private(data) => data.in_range(start, end),
        }
    }

    pub fn get(&self, index: u64) -> Option<&Value> {
        match self {
            SequenceData::PublicSentried(data) => data.get(index),
            SequenceData::Public(data) => data.get(index),
            SequenceData::PrivateSentried(data) => data.get(index),
            SequenceData::Private(data) => data.get(index),
        }
    }

    pub fn indices(&self) -> ExpectedIndices {
        match self {
            SequenceData::PublicSentried(data) => data.indices(),
            SequenceData::Public(data) => data.indices(),
            SequenceData::PrivateSentried(data) => data.indices(),
            SequenceData::Private(data) => data.indices(),
        }
    }

    pub fn current_data_entry(&self) -> Option<DataEntry> {
        match self {
            SequenceData::PublicSentried(data) => data.current_data_entry(),
            SequenceData::Public(data) => data.current_data_entry(),
            SequenceData::PrivateSentried(data) => data.current_data_entry(),
            SequenceData::Private(data) => data.current_data_entry(),
        }
    }

    pub fn owner_at(&self, index: impl Into<Index>) -> Option<&Owner> {
        match self {
            SequenceData::PublicSentried(data) => data.owner_at(index),
            SequenceData::Public(data) => data.owner_at(index),
            SequenceData::PrivateSentried(data) => data.owner_at(index),
            SequenceData::Private(data) => data.owner_at(index),
        }
    }

    pub fn is_owner(&self, user: PublicKey) -> bool {
        match self {
            SequenceData::PublicSentried(data) => data.is_owner(user),
            SequenceData::Public(data) => data.is_owner(user),
            SequenceData::PrivateSentried(data) => data.is_owner(user),
            SequenceData::Private(data) => data.is_owner(user),
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
            SequenceData::PublicSentried(data) => data.permissions_at(index),
            SequenceData::Public(data) => data.permissions_at(index),
            _ => return Err(Error::NoSuchData),
        };
        permissions.ok_or(Error::NoSuchEntry)
    }

    pub fn private_permissions_at(&self, index: impl Into<Index>) -> Result<&PrivatePermissions> {
        let permissions = match self {
            SequenceData::PrivateSentried(data) => data.permissions_at(index),
            SequenceData::Private(data) => data.permissions_at(index),
            _ => return Err(Error::NoSuchData),
        };
        permissions.ok_or(Error::NoSuchEntry)
    }

    pub fn shell(&self, index: impl Into<Index>) -> Result<Self> {
        match self {
            SequenceData::PublicSentried(adata) => {
                adata.shell(index).map(SequenceData::PublicSentried)
            }
            SequenceData::Public(adata) => adata.shell(index).map(SequenceData::Public),
            SequenceData::PrivateSentried(adata) => {
                adata.shell(index).map(SequenceData::PrivateSentried)
            }
            SequenceData::Private(adata) => adata.shell(index).map(SequenceData::Private),
        }
    }
}

impl From<PublicSentriedSequence> for SequenceData {
    fn from(data: PublicSentriedSequence) -> Self {
        SequenceData::PublicSentried(data)
    }
}

impl From<PublicSequence> for SequenceData {
    fn from(data: PublicSequence) -> Self {
        SequenceData::Public(data)
    }
}

impl From<PrivateSentriedSequence> for SequenceData {
    fn from(data: PrivateSentriedSequence) -> Self {
        SequenceData::PrivateSentried(data)
    }
}

impl From<PrivateSequence> for SequenceData {
    fn from(data: PrivateSequence) -> Self {
        SequenceData::Private(data)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct AppendOperation {
    // Address of an Sequence object on the network.
    pub address: Address,
    // A list of Values to append.
    pub values: Values,
}
