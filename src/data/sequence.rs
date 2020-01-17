// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::data::access_control::{
    AccessListTrait, AccessType, PrivateAccessList, PrivateUserAccess, PublicAccessList,
    PublicUserAccess,
};
use crate::shared_types::{
    to_absolute_range, to_absolute_version, Address, ExpectedVersions, Flavour, Guarded,
    NonGuarded, Owner, User, Value, Version, CURRENT_VERSION,
};
use crate::{Error, PublicKey, Result, XorName};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Formatter};

/// The alias type for a Public Sequence with concurrency control.
pub type PublicGuardedSequence = SequenceBase<PublicAccessList, Guarded>;
/// The alias type for a Public Sequence.
pub type PublicSequence = SequenceBase<PublicAccessList, NonGuarded>;
/// The alias type for a Private Sequence with concurrency control.
pub type PrivateGuardedSequence = SequenceBase<PrivateAccessList, Guarded>;
/// The alias type for a Private Sequence.
pub type PrivateSequence = SequenceBase<PrivateAccessList, NonGuarded>;
/// The alias type for a list of values.
pub type Values = Vec<Value>;

/// A representation of data at some version.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default, Debug)]
pub struct DataEntry {
    /// Data version
    pub version: u64,
    /// Data value
    pub value: Vec<u8>,
}

impl DataEntry {
    /// Returns a new instance of a data entry.
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
    /// Returns true if the provided access type is allowed for the specific user (identified y their public key).
    pub fn is_allowed(&self, user: PublicKey, access: AccessType) -> bool {
        if let Some(owner) = self.owner_at(CURRENT_VERSION) {
            if owner.public_key == user {
                return true;
            }
        }
        match self.access_list_at(CURRENT_VERSION) {
            Some(list) => list.is_allowed(&user, access),
            None => false,
        }
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

    /// Returns true if the user is the current owner.
    pub fn is_owner(&self, user: PublicKey) -> bool {
        match self.owner_at(CURRENT_VERSION) {
            Some(owner) => user == owner.public_key,
            _ => false,
        }
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
        Some(self.owners[range].iter().copied().collect())
    }

    /// Get access control at version.
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
        Some(self.access_list[range].to_vec())
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

/// A struct used to append values
/// to a Sequence instance at a specific address.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize, Debug)]
pub struct AppendOperation {
    /// The address of the Sequence instance.
    pub address: Address,
    values: Values,
    expected_version: Option<ExpectedVersion>,
}

impl AppendOperation {
    /// An operation to append values to a sequence instance at an address,
    /// where an expected version needs to provided if the instance is Guarded.
    pub fn new(
        address: Address,
        values: Values,
        expected_version: Option<ExpectedVersion>,
    ) -> Self {
        Self {
            address,
            values,
            expected_version,
        }
    }
}

pub type ExpectedVersion = u64;

/// Common methods for NonGuarded flavours.
impl<P: AccessListTrait> SequenceBase<P, NonGuarded> {
    /// Append new Values.
    pub fn append(&mut self, values: Values) -> Result<()> {
        self.data.extend(values);
        Ok(())
    }
}

/// Common methods for Guarded flavours.
impl<P: AccessListTrait> SequenceBase<P, Guarded> {
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

/// Public + Guarded
impl SequenceBase<PublicAccessList, Guarded> {
    /// Returns new instance of public SequenceBase flavour with concurrency control.
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PublicGuarded { name, tag },
            data: Vec::new(),
            access_list: Vec::new(),
            owners: Vec::new(),
            _flavour: Guarded,
        }
    }
}

impl Debug for SequenceBase<PublicAccessList, Guarded> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicGuardedSequence {:?}", self.name())
    }
}

/// Public + NonGuarded
impl SequenceBase<PublicAccessList, NonGuarded> {
    /// Returns new instance of public SequenceBase flavour.
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Public { name, tag },
            data: Vec::new(),
            access_list: Vec::new(),
            owners: Vec::new(),
            _flavour: NonGuarded,
        }
    }
}

impl Debug for SequenceBase<PublicAccessList, NonGuarded> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PublicSequence {:?}", self.name())
    }
}

/// Private + Guarded
impl SequenceBase<PrivateAccessList, Guarded> {
    /// Returns new instance of private SequenceBase flavour with concurrency control.
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::PrivateGuarded { name, tag },
            data: Vec::new(),
            access_list: Vec::new(),
            owners: Vec::new(),
            _flavour: Guarded,
        }
    }
}

impl Debug for SequenceBase<PrivateAccessList, Guarded> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateGuardedSequence {:?}", self.name())
    }
}

/// Private + NonGuarded
impl SequenceBase<PrivateAccessList, NonGuarded> {
    /// Returns new instance of private SequenceBase flavour.
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            address: Address::Private { name, tag },
            data: Vec::new(),
            access_list: Vec::new(),
            owners: Vec::new(),
            _flavour: NonGuarded,
        }
    }
}

impl Debug for SequenceBase<PrivateAccessList, NonGuarded> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivateSequence {:?}", self.name())
    }
}

/// Object storing a Sequence variant.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Sequence {
    /// Public instance with concurrency control.
    PublicGuarded(PublicGuardedSequence),
    /// Public instance.
    Public(PublicSequence),
    /// Private instance with concurrency control.
    PrivateGuarded(PrivateGuardedSequence),
    /// Private instance.
    Private(PrivateSequence),
}

// Execute $expr on the current variant of $self.
macro_rules! state_dispatch {
    ($self:expr, $state:pat => $expr:expr) => {
        match $self {
            Sequence::PublicGuarded($state) => $expr,
            Sequence::Public($state) => $expr,
            Sequence::PrivateGuarded($state) => $expr,
            Sequence::Private($state) => $expr,
        }
    };
}

impl Sequence {
    /// Returns true if the provided access type is allowed for the specific user (identified y their public key).
    pub fn is_allowed(&self, access: AccessType, user: PublicKey) -> bool {
        use AccessType::*;
        use Sequence::*;
        // Public flavours automatically allows all reads.
        match (self, access) {
            (PublicGuarded(_), Read) | (Public(_), Read) => return true,
            _ => (),
        }
        match (self, access) {
            (PublicGuarded(data), Append) | (PublicGuarded(data), ModifyPermissions) => {
                data.is_allowed(user, access)
            }
            (Public(data), Append) | (Public(data), ModifyPermissions) => {
                data.is_allowed(user, access)
            }

            (PrivateGuarded(data), Append) | (PrivateGuarded(data), ModifyPermissions) => {
                data.is_allowed(user, access)
            }
            (Private(data), Append) | (Private(data), ModifyPermissions) => {
                data.is_allowed(user, access)
            }
            (PrivateGuarded(data), Read) => data.is_allowed(user, access),
            (Private(data), Read) => data.is_allowed(user, access),
            _ => false,
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        state_dispatch!(self, ref state => state.address())
    }

    /// Returns the data type flavour.
    pub fn flavour(&self) -> Flavour {
        self.address().flavour()
    }

    /// Returns the xor name.
    pub fn name(&self) -> &XorName {
        self.address().name()
    }

    /// Returns the tag type.
    pub fn tag(&self) -> u64 {
        self.address().tag()
    }

    /// Returns true if this instance is public.
    pub fn is_public(&self) -> bool {
        self.flavour().is_public()
    }

    /// Returns true if this instance is private.
    pub fn is_private(&self) -> bool {
        self.flavour().is_private()
    }

    /// Returns true if this instance employs concurrency control.
    pub fn is_guarded(&self) -> bool {
        self.flavour().is_guarded()
    }

    /// Returns true if the provided user (identified by their public key) is the current owner.
    pub fn is_owner(&self, user: PublicKey) -> bool {
        state_dispatch!(self, ref state => state.is_owner(user))
    }

    /// Returns expected version of the instance data.
    pub fn expected_data_version(&self) -> u64 {
        state_dispatch!(self, ref state => state.expected_data_version())
    }

    /// Returns expected version of the instance access list.
    pub fn expected_access_list_version(&self) -> u64 {
        state_dispatch!(self, ref state => state.expected_access_list_version())
    }

    /// Returns expected version of the instance owner.
    pub fn expected_owners_version(&self) -> u64 {
        state_dispatch!(self, ref state => state.expected_owners_version())
    }

    /// Returns expected versions of data, owner and access list.
    pub fn versions(&self) -> ExpectedVersions {
        state_dispatch!(self, ref state => state.versions())
    }

    /// Returns the data at a specific version.
    pub fn get(&self, version: Version) -> Option<&Value> {
        state_dispatch!(self, ref state => state.get(version))
    }

    /// Returns the current data entry.
    pub fn current_data_entry(&self) -> Option<DataEntry> {
        state_dispatch!(self, ref state => state.current_data_entry())
    }

    /// Returns a range in the history of data.
    pub fn in_range(&self, start: Version, end: Version) -> Option<Values> {
        state_dispatch!(self, ref state => state.in_range(start, end))
    }

    /// Returns the owner at a specific version of owners.
    pub fn owner_at(&self, version: impl Into<Version>) -> Option<&Owner> {
        state_dispatch!(self, ref state => state.owner_at(version))
    }

    /// Returns history of all owners
    pub fn owner_history(&self) -> Result<Vec<Owner>> {
        state_dispatch!(self, ref state => Some(state.owner_history())).ok_or(Error::NoSuchEntry)
    }

    /// Get history of owners within the range of versions specified.
    pub fn owner_history_range(&self, start: Version, end: Version) -> Result<Vec<Owner>> {
        state_dispatch!(self, ref state => state.owner_history_range(start, end))
            .ok_or(Error::NoSuchEntry)
    }

    /// Returns a specific user's access list of a public instance at a specific version.
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

    /// Returns a specific user's access list of a private instance at a specific version.
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

    /// Returns the access list of a public instance at a specific version.
    pub fn public_access_list_at(&self, version: impl Into<Version>) -> Result<&PublicAccessList> {
        use Sequence::*;
        let access_list = match self {
            PublicGuarded(data) => data.access_list_at(version),
            Public(data) => data.access_list_at(version),
            _ => return Err(Error::InvalidOperation),
        };
        access_list.ok_or(Error::NoSuchEntry)
    }

    /// Returns the access list of a private instance at a specific version.
    pub fn private_access_list_at(
        &self,
        version: impl Into<Version>,
    ) -> Result<&PrivateAccessList> {
        use Sequence::*;
        let access_list = match self {
            PrivateGuarded(data) => data.access_list_at(version),
            Private(data) => data.access_list_at(version),
            _ => return Err(Error::InvalidOperation),
        };
        access_list.ok_or(Error::NoSuchEntry)
    }

    /// Returns history of all access list states
    pub fn public_access_list_history(&self) -> Result<Vec<PublicAccessList>> {
        use Sequence::*;
        let result = match self {
            PublicGuarded(data) => Some(data.access_list_history()),
            Public(data) => Some(data.access_list_history()),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    /// Returns history of all access list states
    pub fn private_access_list_history(&self) -> Result<Vec<PrivateAccessList>> {
        use Sequence::*;
        let result = match self {
            PrivateGuarded(data) => Some(data.access_list_history()),
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
        use Sequence::*;
        let result = match self {
            PublicGuarded(data) => data.access_list_history_range(start, end),
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
        use Sequence::*;
        let result = match self {
            PrivateGuarded(data) => data.access_list_history_range(start, end),
            Private(data) => data.access_list_history_range(start, end),
            _ => return Err(Error::InvalidOperation),
        };
        result.ok_or(Error::NoSuchEntry)
    }

    /// Returns a shell without the data of the instance, as of a specific data version.
    pub fn shell(&self, version: impl Into<Version>) -> Result<Self> {
        use Sequence::*;
        match self {
            PublicGuarded(adata) => adata.shell(version).map(PublicGuarded),
            Public(adata) => adata.shell(version).map(Public),
            PrivateGuarded(adata) => adata.shell(version).map(PrivateGuarded),
            Private(adata) => adata.shell(version).map(Private),
        }
    }

    /// Sets a new owner.
    pub fn set_owner(&mut self, owner: Owner, expected_version: u64) -> Result<()> {
        state_dispatch!(self, ref mut state => state.set_owner(owner, expected_version))
    }

    /// Sets a new access list of a private instance.
    pub fn set_private_access_list(
        &mut self,
        access_list: &PrivateAccessList,
        expected_version: u64,
    ) -> Result<()> {
        use Sequence::*;
        match self {
            Private(data) => data.set_access_list(access_list, expected_version),
            PrivateGuarded(data) => data.set_access_list(access_list, expected_version),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Sets a new access list of a public instance.
    pub fn set_public_access_list(
        &mut self,
        access_list: &PublicAccessList,
        expected_version: u64,
    ) -> Result<()> {
        use Sequence::*;
        match self {
            Public(data) => data.set_access_list(access_list, expected_version),
            PublicGuarded(data) => data.set_access_list(access_list, expected_version),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Appends values.
    pub fn append(&mut self, operation: &AppendOperation) -> Result<()> {
        use Sequence::*;
        match self {
            PrivateGuarded(sequence) => match operation.expected_version {
                Some(expected_version) => {
                    sequence.append(operation.values.to_vec(), expected_version)
                }
                _ => Err(Error::InvalidOperation),
            },
            Private(sequence) => match operation.expected_version {
                None => sequence.append(operation.values.to_vec()),
                _ => Err(Error::InvalidOperation),
            },
            PublicGuarded(sequence) => match operation.expected_version {
                Some(expected_version) => {
                    sequence.append(operation.values.to_vec(), expected_version)
                }
                _ => Err(Error::InvalidOperation),
            },
            Public(sequence) => match operation.expected_version {
                None => sequence.append(operation.values.to_vec()),
                _ => Err(Error::InvalidOperation),
            },
        }
    }
}

impl From<PublicGuardedSequence> for Sequence {
    fn from(data: PublicGuardedSequence) -> Self {
        Sequence::PublicGuarded(data)
    }
}

impl From<PublicSequence> for Sequence {
    fn from(data: PublicSequence) -> Self {
        Sequence::Public(data)
    }
}

impl From<PrivateGuardedSequence> for Sequence {
    fn from(data: PrivateGuardedSequence) -> Self {
        Sequence::PrivateGuarded(data)
    }
}

impl From<PrivateSequence> for Sequence {
    fn from(data: PrivateSequence) -> Self {
        Sequence::Private(data)
    }
}
