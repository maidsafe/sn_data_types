// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{utils, Error, PublicKey, Result, XorName};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug, hash::Hash};

/// An action on Sequence data type.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Action {
    /// Read from the data.
    Read,
    /// Append to the data.
    Append,
    /// Manage permissions.
    ManagePermissions,
}

/// List of entries.
pub type Entries = Vec<Entry>;

/// An entry in a Sequence.
pub type Entry = Vec<u8>;

/// Address of a Sequence.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    /// Public sequence namespace.
    Public {
        /// Name.
        name: XorName,
        /// Tag.
        tag: u64,
    },
    /// Private sequence namespace.
    Private {
        /// Name.
        name: XorName,
        /// Tag.
        tag: u64,
    },
}

impl Address {
    /// Constructs a new `Address` given `kind`, `name`, and `tag`.
    pub fn from_kind(kind: Kind, name: XorName, tag: u64) -> Self {
        match kind {
            Kind::Public => Address::Public { name, tag },
            Kind::Private => Address::Private { name, tag },
        }
    }

    /// Returns the kind.
    pub fn kind(&self) -> Kind {
        match self {
            Address::Public { .. } => Kind::Public,
            Address::Private { .. } => Kind::Private,
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        match self {
            Address::Public { ref name, .. } | Address::Private { ref name, .. } => name,
        }
    }

    /// Returns the tag.
    pub fn tag(&self) -> u64 {
        match self {
            Address::Public { tag, .. } | Address::Private { tag, .. } => *tag,
        }
    }

    /// Returns true if public.
    pub fn is_pub(&self) -> bool {
        self.kind().is_pub()
    }

    /// Returns true if private.
    pub fn is_private(&self) -> bool {
        self.kind().is_private()
    }

    /// Returns the `Address` serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Creates from z-base-32 encoded string.
    pub fn decode_from_zbase32<I: AsRef<str>>(encoded: I) -> Result<Self> {
        utils::decode(encoded)
    }
}

/// Kind of a Sequence.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    /// Public sequence.
    Public,
    /// Private sequence.
    Private,
}

impl Kind {
    /// Returns true if public.
    pub fn is_pub(self) -> bool {
        self == Kind::Public
    }

    /// Returns true if private.
    pub fn is_private(self) -> bool {
        !self.is_pub()
    }
}

/// Index of some data.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Index {
    /// Absolute index.
    FromStart(u64),
    /// Relative index - start counting from the end.
    FromEnd(u64),
}

impl From<u64> for Index {
    fn from(index: u64) -> Self {
        Index::FromStart(index)
    }
}

/// Set of data, owners, permissions indices.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Indices {
    entries_index: u64,
    owners_index: u64,
    permissions_index: u64,
}

impl Indices {
    /// Constructs a new `Indices`.
    pub fn new(entries_index: u64, owners_index: u64, permissions_index: u64) -> Self {
        Indices {
            entries_index,
            owners_index,
            permissions_index,
        }
    }

    /// Returns the last entry index.
    pub fn entries_index(&self) -> u64 {
        self.entries_index
    }

    /// Returns the last owners index.
    pub fn owners_index(&self) -> u64 {
        self.owners_index
    }

    /// Returns the last permissions index.
    pub fn permissions_index(&self) -> u64 {
        self.permissions_index
    }
}

/// An owner could represent an individual user, or a group of users,
/// depending on the `public_key` type.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Owner {
    /// Public key.
    pub public_key: PublicKey,
    /// The current index of the data when this ownership change happened
    pub entries_index: u64,
    /// The current index of the permissions when this ownership change happened
    pub permissions_index: u64,
}

/// Set of public permissions for a user.
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PubUserPermissions {
    /// `Some(true)` if the user can append.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    append: Option<bool>,
    /// `Some(true)` if the user can manage permissions.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has required permissions).
    /// Use permissions for `Anyone` if `None`.
    manage_permissions: Option<bool>,
}

impl PubUserPermissions {
    /// Constructs a new public permission set.
    pub fn new(append: impl Into<Option<bool>>, manage_perms: impl Into<Option<bool>>) -> Self {
        Self {
            append: append.into(),
            manage_permissions: manage_perms.into(),
        }
    }

    /// Sets permissions.
    pub fn set_perms(
        &mut self,
        append: impl Into<Option<bool>>,
        manage_perms: impl Into<Option<bool>>,
    ) {
        self.append = append.into();
        self.manage_permissions = manage_perms.into();
    }

    /// Returns `Some(true)` if `action` is allowed and `Some(false)` if it's not permitted.
    /// `None` means that default permissions should be applied.
    pub fn is_allowed(self, action: Action) -> Option<bool> {
        match action {
            Action::Read => Some(true), // It's public data, so it's always allowed to read it.
            Action::Append => self.append,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

/// Set of private permissions for a user.
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivUserPermissions {
    /// `true` if the user can read.
    read: bool,
    /// `true` if the user can append.
    append: bool,
    /// `true` if the user can manage permissions.
    manage_permissions: bool,
}

impl PrivUserPermissions {
    /// Constructs a new private permission set.
    pub fn new(read: bool, append: bool, manage_perms: bool) -> Self {
        Self {
            read,
            append,
            manage_permissions: manage_perms,
        }
    }

    /// Sets permissions.
    pub fn set_perms(&mut self, read: bool, append: bool, manage_perms: bool) {
        self.read = read;
        self.append = append;
        self.manage_permissions = manage_perms;
    }

    /// Returns `true` if `action` is allowed.
    pub fn is_allowed(self, action: Action) -> bool {
        match action {
            Action::Read => self.read,
            Action::Append => self.append,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

/// User that can access Sequence.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub enum User {
    /// Any user.
    Anyone,
    /// User identified by its public key.
    Key(PublicKey),
}

/// Public permissions.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PublicPermissions {
    /// Map of users to their public permission set.
    pub permissions: BTreeMap<User, PubUserPermissions>,
    /// The current index of the data when this permission change happened.
    pub entries_index: u64,
    /// The current index of the owners when this permission change happened.
    pub owners_index: u64,
}

impl PublicPermissions {
    /// Returns `Some(true)` if `action` is allowed for the provided user and `Some(false)` if it's
    /// not permitted. `None` means that default permissions should be applied.
    fn is_action_allowed_by_user(&self, user: &User, action: Action) -> Option<bool> {
        self.permissions
            .get(user)
            .and_then(|perms| perms.is_allowed(action))
    }
}

/// Private permissions.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivatePermissions {
    /// Map of users to their private permission set.
    pub permissions: BTreeMap<PublicKey, PrivUserPermissions>,
    /// The current index of the data when this permission change happened.
    pub entries_index: u64,
    /// The current index of the owners when this permission change happened.
    pub owners_index: u64,
}

pub trait Perm {
    /// Returns true if `action` is allowed for the provided user.
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()>;
    /// Gets the permissions for a user if applicable.
    fn user_permissions(&self, user: User) -> Option<UserPermissions>;
    /// Gets the last entry index.
    fn entries_index(&self) -> u64;
    /// Gets the last owner index.
    fn owners_index(&self) -> u64;
}

impl Perm for PublicPermissions {
    /// Returns `Ok(())` if `action` is allowed for the provided user and `Err(AccessDenied)` if
    /// this action is not permitted.
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()> {
        match self
            .is_action_allowed_by_user(&User::Key(requester), action)
            .or_else(|| self.is_action_allowed_by_user(&User::Anyone, action))
        {
            Some(true) => Ok(()),
            Some(false) => Err(Error::AccessDenied),
            None => Err(Error::AccessDenied),
        }
    }

    /// Gets the permissions for a user if applicable.
    fn user_permissions(&self, user: User) -> Option<UserPermissions> {
        self.permissions
            .get(&user)
            .map(|p| UserPermissions::Public(*p))
    }

    /// Returns the last entry index.
    fn entries_index(&self) -> u64 {
        self.entries_index
    }

    /// Returns the last owners index.
    fn owners_index(&self) -> u64 {
        self.owners_index
    }
}

impl Perm for PrivatePermissions {
    /// Returns `Ok(())` if `action` is allowed for the provided user and `Err(AccessDenied)` if
    /// this action is not permitted.
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()> {
        match self.permissions.get(&requester) {
            Some(perms) => {
                if perms.is_allowed(action) {
                    Ok(())
                } else {
                    Err(Error::AccessDenied)
                }
            }
            None => Err(Error::AccessDenied),
        }
    }

    /// Gets the permissions for a user if applicable.
    fn user_permissions(&self, user: User) -> Option<UserPermissions> {
        match user {
            User::Anyone => None,
            User::Key(key) => self
                .permissions
                .get(&key)
                .map(|p| UserPermissions::Priv(*p)),
        }
    }

    /// Returns the last entry index.
    fn entries_index(&self) -> u64 {
        self.entries_index
    }

    /// Returns the last owners index.
    fn owners_index(&self) -> u64 {
        self.owners_index
    }
}

/// Wrapper type for permissions, which can be public or private.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum Permissions {
    /// Public permissions.
    Public(PublicPermissions),
    /// Private permissions.
    Priv(PrivatePermissions),
}

impl From<PrivatePermissions> for Permissions {
    fn from(permissions: PrivatePermissions) -> Self {
        Permissions::Priv(permissions)
    }
}

impl From<PublicPermissions> for Permissions {
    fn from(permissions: PublicPermissions) -> Self {
        Permissions::Public(permissions)
    }
}

/// Wrapper type for permissions set, which can be public or private.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum UserPermissions {
    /// Public permissions set.
    Public(PubUserPermissions),
    /// Private permissions set.
    Priv(PrivUserPermissions),
}

impl From<PrivUserPermissions> for UserPermissions {
    fn from(permission_set: PrivUserPermissions) -> Self {
        UserPermissions::Priv(permission_set)
    }
}

impl From<PubUserPermissions> for UserPermissions {
    fn from(permission_set: PubUserPermissions) -> Self {
        UserPermissions::Public(permission_set)
    }
}
