// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::access_control::{
    AccessList as AccessListTrait, AccessType, PrivateAccessList, PrivateUserAccess,
    PublicAccessList, PublicUserAccess,
};
use crate::shared_data::{
    to_absolute_range, to_absolute_version, Address, ExpectedVersions, Kind, NonSentried, Owner,
    Sentried, User, Value, Version,
};
use crate::{Error, PublicKey, Result, XorName};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Formatter};

pub type PublicSentriedSequence = SequenceBase<PublicAccessList, Sentried>;
pub type PublicSequence = SequenceBase<PublicAccessList, NonSentried>;
pub type PrivateSentriedSequence = SequenceBase<PrivateAccessList, Sentried>;
pub type PrivateSequence = SequenceBase<PrivateAccessList, NonSentried>;
pub type Values = Vec<Value>;

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum AccessList {
    Public(PublicAccessList),
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default, Debug)]
pub struct DataEntry {
    pub version: u64,
    pub value: Vec<u8>,
}

impl DataEntry {
    pub fn new(version: u64, value: Vec<u8>) -> Self {
        Self { version, value }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct SequenceBase<P, S> {
    address: Address,
    data: Values,
    access_list: Vec<P>,
    // This is the history of owners, with each entry representing an owner.  Each single owner
    // could represent an individual user, or a group of users, depending on the `PublicKey` type.
    owners: Vec<Owner>,
    _flavour: S,
}

/// Common methods for all `Sequence` flavours.
impl<C, S> SequenceBase<C, S>
where
    C: AccessListTrait,
    S: Copy,
{
    /// Returns the data shell - that is - everything except the Values themselves.
    pub fn shell(&self, expected_data_version: impl Into<Version>) -> Result<Self> {
        let expected_data_version = to_absolute_version(
            expected_data_version.into(),
            self.expected_data_version() as usize,
        )
        .ok_or(Error::NoSuchEntry)? as u64;

        let access_list = self
            .access_list
            .iter()
            .filter(|a| a.expected_data_version() <= expected_data_version)
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
            data: Vec::new(),
            access_list,
            owners,
            _flavour: self._flavour,
        })
    }

    /// Return a value for the given Version (if it is present).
    pub fn get(&self, version: Version) -> Option<&Value> {
        let absolute_version = to_absolute_version(version, self.data.len())?;
        self.data.get(absolute_version)
    }

    /// Return the current data entry (if it is present).
    pub fn current_data_entry(&self) -> Option<DataEntry> {
        match self.data.last() {
            Some(value) => Some(DataEntry::new(self.data.len() as u64, value.to_vec())),
            None => None,
        }
    }

    /// Get a range of values within the given versions.
    pub fn in_range(&self, start: Version, end: Version) -> Option<Values> {
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

    /// Return the expected data version.
    pub fn expected_data_version(&self) -> u64 {
        self.data.len() as u64
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
            self.expected_data_version(),
            self.expected_owners_version(),
            self.expected_access_list_version(),
        )
    }

    /// Get history of owners within the range of versions specified.
    pub fn owner_history_range(&self, start: Version, end: Version) -> Option<&[Owner]> {
        let range = to_absolute_range(start, end, self.owners.len())?;
        Some(&self.owners[range])
    }

    /// Get history of permission within the range of versions specified.
    pub fn access_list_history_range(&self, start: Version, end: Version) -> Option<&[C]> {
        let range = to_absolute_range(start, end, self.access_list.len())?;
        Some(&self.access_list[range])
    }

    /// Get owner at version.
    pub fn owner_at(&self, version: impl Into<Version>) -> Option<&Owner> {
        let version = to_absolute_version(version.into(), self.owners.len())?;
        self.owners.get(version)
    }

    /// Get access control at version.
    pub fn access_list_at(&self, version: impl Into<Version>) -> Option<&C> {
        let version = to_absolute_version(version.into(), self.access_list.len())?;
        self.access_list.get(version)
    }

    /// Returns true if the user is the current owner.
    pub fn is_owner(&self, user: PublicKey) -> bool {
        match self.owner_at(Version::FromEnd(1)) {
            Some(owner) => user == owner.public_key,
            _ => false,
        }
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
        match self.access_list_at(Version::FromEnd(1)) {
            Some(list) => list.is_allowed(&user, &access),
            None => false,
        }
    }

    /// Set owner.
    pub fn set_owner(&mut self, owner: Owner, expected_version: u64) -> Result<()> {
        if owner.expected_data_version != self.expected_data_version() {
            return Err(Error::InvalidSuccessor(self.expected_data_version()));
        }
        if owner.expected_access_list_version != self.expected_access_list_version() {
            return Err(Error::InvalidPermissionsSuccessor(
                self.expected_access_list_version(),
            ));
        }
        if self.expected_owners_version() != expected_version {
            return Err(Error::InvalidSuccessor(self.expected_owners_version()));
        }
        self.owners.push(owner);
        Ok(())
    }

    /// Set access list.
    /// The `AccessList` struct needs to contain the correct expected versions.
    pub fn set_access_list(&mut self, access_list: &C, expected_version: u64) -> Result<()> {
        if access_list.expected_data_version() != self.expected_data_version() {
            return Err(Error::InvalidSuccessor(self.expected_data_version()));
        }
        if access_list.expected_owners_version() != self.expected_owners_version() {
            return Err(Error::InvalidOwnersSuccessor(
                self.expected_owners_version(),
            ));
        }
        if self.expected_access_list_version() != expected_version {
            return Err(Error::InvalidSuccessor(self.expected_access_list_version()));
        }
        self.access_list.push(access_list.clone()); // hmm... do we have to clone in situations like these?
        Ok(())
    }
}

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct AppendOperation {
    address: Address,
    values: Values,
    expected_version: Option<ExpectedVersion>,
}

pub type ExpectedVersion = u64;

/// Common methods for NonSentried flavours.
impl<P: AccessListTrait> SequenceBase<P, NonSentried> {
    /// Append new Values.
    pub fn append(&mut self, values: Values) -> Result<()> {
        self.data.extend(values);
        Ok(())
    }
}

/// Common methods for Sentried flavours.
impl<P: AccessListTrait> SequenceBase<P, Sentried> {
    /// Append new Values.
    ///
    /// If the specified `expected_version` does not equal the Values count in data, an
    /// error will be returned.
    pub fn append(&mut self, values: Values, expected_version: u64) -> Result<()> {
        if expected_version != self.data.len() as u64 {
            return Err(Error::InvalidSuccessor(self.data.len() as u64));
        }

        self.data.extend(values);
        Ok(())
    }
}

/// Public + Sentried
impl SequenceBase<PublicAccessList, Sentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PublicSentried { name, tag },
            data: Vec::new(),
            access_list: Vec::new(),
            owners: Vec::new(),
            _flavour: Sentried,
        }
    }
}

impl Debug for SequenceBase<PublicAccessList, Sentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicSentriedSequence {:?}", self.name())
    }
}

/// Public + NonSentried
impl SequenceBase<PublicAccessList, NonSentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Public { name, tag },
            data: Vec::new(),
            access_list: Vec::new(),
            owners: Vec::new(),
            _flavour: NonSentried,
        }
    }
}

impl Debug for SequenceBase<PublicAccessList, NonSentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicSequence {:?}", self.name())
    }
}

/// Private + Sentried
impl SequenceBase<PrivateAccessList, Sentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PrivateSentried { name, tag },
            data: Vec::new(),
            access_list: Vec::new(),
            owners: Vec::new(),
            _flavour: Sentried,
        }
    }
}

impl Debug for SequenceBase<PrivateAccessList, Sentried> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateSentriedSequence {:?}", self.name())
    }
}

/// Private + NonSentried
impl SequenceBase<PrivateAccessList, NonSentried> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Private { name, tag },
            data: Vec::new(),
            access_list: Vec::new(),
            owners: Vec::new(),
            _flavour: NonSentried,
        }
    }
}

impl Debug for SequenceBase<PrivateAccessList, NonSentried> {
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
    pub fn is_allowed(&self, access: AccessType, user: PublicKey) -> bool {
        use AccessType::*;
        use SequenceData::*;
        // Public flavours automatically allows all reads.
        match (self, access) {
            (PublicSentried(_), Read) | (Public(_), Read) => return true,
            _ => (),
        }
        match (self, access) {
            (PublicSentried(data), Append) | (PublicSentried(data), ModifyPermissions) => {
                data.is_allowed(user, access)
            }
            (Public(data), Append) | (Public(data), ModifyPermissions) => {
                data.is_allowed(user, access)
            }

            (PrivateSentried(data), Append) | (PrivateSentried(data), ModifyPermissions) => {
                data.is_allowed(user, access)
            }
            (Private(data), Append) | (Private(data), ModifyPermissions) => {
                data.is_allowed(user, access)
            }
            (PrivateSentried(data), Read) => data.is_allowed(user, access),
            (Private(data), Read) => data.is_allowed(user, access),
            _ => false,
        }
    }

    pub fn address(&self) -> &Address {
        use SequenceData::*;
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
        use SequenceData::*;
        match self {
            PublicSentried(data) => data.is_owner(user),
            Public(data) => data.is_owner(user),
            PrivateSentried(data) => data.is_owner(user),
            Private(data) => data.is_owner(user),
        }
    }

    pub fn get(&self, version: Version) -> Option<&Value> {
        use SequenceData::*;
        match self {
            PublicSentried(data) => data.get(version),
            Public(data) => data.get(version),
            PrivateSentried(data) => data.get(version),
            Private(data) => data.get(version),
        }
    }

    pub fn expected_data_version(&self) -> u64 {
        use SequenceData::*;
        match self {
            PublicSentried(data) => data.expected_data_version(),
            Public(data) => data.expected_data_version(),
            PrivateSentried(data) => data.expected_data_version(),
            Private(data) => data.expected_data_version(),
        }
    }

    pub fn expected_access_list_version(&self) -> u64 {
        use SequenceData::*;
        match self {
            PublicSentried(data) => data.expected_access_list_version(),
            Public(data) => data.expected_access_list_version(),
            PrivateSentried(data) => data.expected_access_list_version(),
            Private(data) => data.expected_access_list_version(),
        }
    }

    pub fn expected_owners_version(&self) -> u64 {
        use SequenceData::*;
        match self {
            PublicSentried(data) => data.expected_owners_version(),
            Public(data) => data.expected_owners_version(),
            PrivateSentried(data) => data.expected_owners_version(),
            Private(data) => data.expected_owners_version(),
        }
    }

    pub fn versions(&self) -> ExpectedVersions {
        use SequenceData::*;
        match self {
            PublicSentried(data) => data.versions(),
            Public(data) => data.versions(),
            PrivateSentried(data) => data.versions(),
            Private(data) => data.versions(),
        }
    }

    pub fn current_data_entry(&self) -> Option<DataEntry> {
        use SequenceData::*;
        match self {
            PublicSentried(data) => data.current_data_entry(),
            Public(data) => data.current_data_entry(),
            PrivateSentried(data) => data.current_data_entry(),
            Private(data) => data.current_data_entry(),
        }
    }

    pub fn in_range(&self, start: Version, end: Version) -> Option<Values> {
        use SequenceData::*;
        match self {
            PublicSentried(data) => data.in_range(start, end),
            Public(data) => data.in_range(start, end),
            PrivateSentried(data) => data.in_range(start, end),
            Private(data) => data.in_range(start, end),
        }
    }

    pub fn owner_at(&self, version: impl Into<Version>) -> Option<&Owner> {
        use SequenceData::*;
        match self {
            PublicSentried(data) => data.owner_at(version),
            Public(data) => data.owner_at(version),
            PrivateSentried(data) => data.owner_at(version),
            Private(data) => data.owner_at(version),
        }
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
        use SequenceData::*;
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
        use SequenceData::*;
        let access_list = match self {
            PrivateSentried(data) => data.access_list_at(version),
            Private(data) => data.access_list_at(version),
            _ => return Err(Error::InvalidOperation),
        };
        access_list.ok_or(Error::NoSuchEntry)
    }

    pub fn shell(&self, version: impl Into<Version>) -> Result<Self> {
        use SequenceData::*;
        match self {
            PublicSentried(adata) => adata.shell(version).map(PublicSentried),
            Public(adata) => adata.shell(version).map(Public),
            PrivateSentried(adata) => adata.shell(version).map(PrivateSentried),
            Private(adata) => adata.shell(version).map(Private),
        }
    }

    pub fn set_owner(&mut self, owner: Owner, expected_version: u64) -> Result<()> {
        use SequenceData::*;
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
        use SequenceData::*;
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
        use SequenceData::*;
        match self {
            Public(data) => data.set_access_list(access_list, expected_version),
            PublicSentried(data) => data.set_access_list(access_list, expected_version),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Appends values.
    pub fn append(&mut self, operation: &AppendOperation) -> Result<()> {
        use SequenceData::*;
        match self {
            PrivateSentried(sequence) => match operation.expected_version {
                Some(expected_version) => {
                    return sequence.append(operation.values.to_vec(), expected_version);
                }
                _ => return Err(Error::InvalidOperation),
            },
            Private(sequence) => match operation.expected_version {
                None => {
                    return sequence.append(operation.values.to_vec());
                }
                _ => return Err(Error::InvalidOperation),
            },
            PublicSentried(sequence) => match operation.expected_version {
                Some(expected_version) => {
                    return sequence.append(operation.values.to_vec(), expected_version);
                }
                _ => return Err(Error::InvalidOperation),
            },
            Public(sequence) => match operation.expected_version {
                None => {
                    return sequence.append(operation.values.to_vec());
                }
                _ => return Err(Error::InvalidOperation),
            },
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
