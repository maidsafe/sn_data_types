use crate::{utils, Error, PublicKey, Result, XorName};
use multibase::Decodable;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::BTreeMap, hash::Hash, ops::Range};

/// Marker for sentried data.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Sentried;

/// Marker for non-sentried data.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct NonSentried;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub enum User {
    Anyone,
    Specific(PublicKey),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Action {
    Read,
    Append,
    ManagePermissions,
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Index {
    FromStart(u64), // Absolute index
    FromEnd(u64),   // Relative index - start counting from the end
}

impl From<u64> for Index {
    fn from(index: u64) -> Self {
        Index::FromStart(index)
    }
}

// Set of data, owners, permissions Indices.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExpectedIndices {
    expected_entries_index: u64,
    expected_owners_index: u64,
    expected_permissions_index: u64,
}

impl ExpectedIndices {
    pub fn new(
        expected_entries_index: u64,
        expected_owners_index: u64,
        expected_permissions_index: u64,
    ) -> Self {
        ExpectedIndices {
            expected_entries_index,
            expected_owners_index,
            expected_permissions_index,
        }
    }

    pub fn expected_entries_index(&self) -> u64 {
        self.expected_entries_index
    }

    pub fn expected_owners_index(&self) -> u64 {
        self.expected_owners_index
    }

    pub fn expected_permissions_index(&self) -> u64 {
        self.expected_permissions_index
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Owner {
    pub public_key: PublicKey,
    /// The expected index of the data at the time this ownership change is to become valid.
    pub expected_entries_index: u64,
    /// The expected index of the permissions at the time this ownership change is to become valid.
    pub expected_permissions_index: u64,
}

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivatePermissionSet {
    read: bool,
    append: bool,
    manage_permissions: bool,
}

impl PrivatePermissionSet {
    pub fn new(read: bool, append: bool, manage_permissions: bool) -> Self {
        PrivatePermissionSet {
            read,
            append,
            manage_permissions: manage_permissions,
        }
    }

    pub fn set_permissions(&mut self, read: bool, append: bool, manage_permissions: bool) {
        self.read = read;
        self.append = append;
        self.manage_permissions = manage_permissions;
    }

    pub fn is_allowed(self, action: Action) -> bool {
        match action {
            Action::Read => self.read,
            Action::Append => self.append,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PublicPermissionSet {
    append: Option<bool>,
    manage_permissions: Option<bool>,
}

impl PublicPermissionSet {
    pub fn new(
        append: impl Into<Option<bool>>,
        manage_permissions: impl Into<Option<bool>>,
    ) -> Self {
        PublicPermissionSet {
            append: append.into(),
            manage_permissions: manage_permissions.into(),
        }
    }

    pub fn set_permissions(
        &mut self,
        append: impl Into<Option<bool>>,
        manage_permissions: impl Into<Option<bool>>,
    ) {
        self.append = append.into();
        self.manage_permissions = manage_permissions.into();
    }

    pub fn is_allowed(self, action: Action) -> Option<bool> {
        match action {
            Action::Read => Some(true), // It's Public data, so it's always allowed to read it.
            Action::Append => self.append,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

pub trait Permissions: Clone + Eq + Ord + Hash + Serialize + DeserializeOwned {
    fn is_action_allowed(&self, user: PublicKey, action: Action) -> Result<()>;
    fn expected_entries_index(&self) -> u64;
    fn expected_owners_index(&self) -> u64;
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivatePermissions {
    pub permissions: BTreeMap<PublicKey, PrivatePermissionSet>,
    /// The expected index of the data at the time this permission change is to become valid.
    pub expected_entries_index: u64,
    /// The expected index of the owners at the time this permission change is to become valid.
    pub expected_owners_index: u64,
}

impl PrivatePermissions {
    pub fn permissions(&self) -> &BTreeMap<PublicKey, PrivatePermissionSet> {
        &self.permissions
    }
}

impl Permissions for PrivatePermissions {
    fn is_action_allowed(&self, user: PublicKey, action: Action) -> Result<()> {
        match self.permissions.get(&user) {
            Some(permissions) => {
                if permissions.is_allowed(action) {
                    Ok(())
                } else {
                    Err(Error::AccessDenied)
                }
            }
            None => Err(Error::InvalidPermissions),
        }
    }

    fn expected_entries_index(&self) -> u64 {
        self.expected_entries_index
    }

    fn expected_owners_index(&self) -> u64 {
        self.expected_owners_index
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PublicPermissions {
    pub permissions: BTreeMap<User, PublicPermissionSet>,
    /// The expected index of the data at the time this permission change is to become valid.
    pub expected_entries_index: u64,
    /// The expected index of the owners at the time this permission change is to become valid.
    pub expected_owners_index: u64,
}

impl PublicPermissions {
    fn is_action_allowed_by_user(&self, user: &User, action: Action) -> Option<bool> {
        self.permissions
            .get(user)
            .and_then(|permissions| permissions.is_allowed(action))
    }

    pub fn permissions(&self) -> &BTreeMap<User, PublicPermissionSet> {
        &self.permissions
    }
}

impl Permissions for PublicPermissions {
    fn is_action_allowed(&self, user: PublicKey, action: Action) -> Result<()> {
        match self
            .is_action_allowed_by_user(&User::Specific(user), action)
            .or_else(|| self.is_action_allowed_by_user(&User::Anyone, action))
        {
            Some(true) => Ok(()),
            Some(false) => Err(Error::AccessDenied),
            None => Err(Error::InvalidPermissions),
        }
    }

    fn expected_entries_index(&self) -> u64 {
        self.expected_entries_index
    }

    fn expected_owners_index(&self) -> u64 {
        self.expected_owners_index
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    PublicSentried,
    Public,
    PrivateSentried,
    Private,
}

impl Kind {
    pub fn is_public(self) -> bool {
        self == Kind::PublicSentried || self == Kind::Public
    }

    pub fn is_private(self) -> bool {
        !self.is_public()
    }

    pub fn is_sentried(self) -> bool {
        self == Kind::PublicSentried || self == Kind::PrivateSentried
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    PublicSentried { name: XorName, tag: u64 },
    Public { name: XorName, tag: u64 },
    PrivateSentried { name: XorName, tag: u64 },
    Private { name: XorName, tag: u64 },
}

impl Address {
    pub fn from_kind(kind: Kind, name: XorName, tag: u64) -> Self {
        match kind {
            Kind::PublicSentried => Address::PublicSentried { name, tag },
            Kind::Public => Address::Public { name, tag },
            Kind::PrivateSentried => Address::PrivateSentried { name, tag },
            Kind::Private => Address::Private { name, tag },
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            Address::PublicSentried { .. } => Kind::PublicSentried,
            Address::Public { .. } => Kind::Public,
            Address::PrivateSentried { .. } => Kind::PrivateSentried,
            Address::Private { .. } => Kind::Private,
        }
    }

    pub fn name(&self) -> &XorName {
        match self {
            Address::PublicSentried { ref name, .. }
            | Address::Public { ref name, .. }
            | Address::PrivateSentried { ref name, .. }
            | Address::Private { ref name, .. } => name,
        }
    }

    pub fn tag(&self) -> u64 {
        match self {
            Address::PublicSentried { tag, .. }
            | Address::Public { tag, .. }
            | Address::PrivateSentried { tag, .. }
            | Address::Private { tag, .. } => *tag,
        }
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

    /// Returns the Address serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Create from z-base-32 encoded string.
    pub fn decode_from_zbase32<I: Decodable>(encoded: I) -> Result<Self> {
        utils::decode(encoded)
    }
}

pub fn to_absolute_index(index: Index, count: usize) -> Option<usize> {
    match index {
        Index::FromStart(index) if index as usize <= count => Some(index as usize),
        Index::FromStart(_) => None,
        Index::FromEnd(index) => count.checked_sub(index as usize),
    }
}

pub fn to_absolute_range(start: Index, end: Index, count: usize) -> Option<Range<usize>> {
    let start = to_absolute_index(start, count)?;
    let end = to_absolute_index(end, count)?;

    if start <= end {
        Some(start..end)
    } else {
        None
    }
}
