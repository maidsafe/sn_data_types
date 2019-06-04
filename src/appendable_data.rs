// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::errors::Error;
use crate::request::{Request, Requester};
use crate::XorName;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use threshold_crypto::{PublicKey, PublicKeySet};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum User {
    Anyone,
    Key(PublicKey),
}

pub fn check_permissions<P: Permissions>(
    _data: impl AppendOnlyData<P>,
    _rpc: &Request,
    _requester: Requester,
) -> Result<bool, Error> {
    // TODO
    Ok(true)
}

#[derive(Clone, Copy)]
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

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct UnpubPermissionSet {
    read: bool,
    append: bool,
    manage_permissions: bool,
}

impl UnpubPermissionSet {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn is_allowed(&self, action: Action) -> bool {
        match action {
            Action::Read => self.read,
            Action::Append => self.append,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct PubPermissionSet {
    append: Option<bool>,
    manage_permissions: Option<bool>,
}

impl PubPermissionSet {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn is_allowed(&self, action: Action) -> Option<bool> {
        match action {
            Action::Read => Some(true), // It's published data, so it's always allowed to read it.
            Action::Append => self.append,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

#[derive(Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct AppendOnlyDataRef {
    // Address of an AppendOnlyData object on the network.
    name: XorName,
    // Type tag.
    tag: u64,
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AppendOnlyKind {
    /// Published, sequenced append-only data
    PubSeq,
    /// Published, unsequenced append-only data
    PubUnseq,
    /// Unpublished, sequenced append-only data
    UnpubSeq,
    /// Unpublished, unsequenced append-only data
    UnpubUnseq,
}

pub trait Permissions {
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> bool;
    fn data_index(&self) -> u64;
    fn owner_entry_index(&self) -> u64;
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct UnpubPermissions {
    permissions: BTreeMap<PublicKey, UnpubPermissionSet>,
    /// The current index of the data when this permission change happened
    data_index: u64,
    /// The current index of the owners when this permission change happened
    owner_entry_index: u64,
}

impl Permissions for UnpubPermissions {
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> bool {
        match self.permissions.get(&requester) {
            Some(perms) => perms.is_allowed(action),
            None => false,
        }
    }

    fn data_index(&self) -> u64 {
        self.data_index
    }

    fn owner_entry_index(&self) -> u64 {
        self.owner_entry_index
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct PubPermissions {
    permissions: BTreeMap<User, PubPermissionSet>,
    /// The current index of the data when this permission change happened
    data_index: u64,
    /// The current index of the owners when this permission change happened
    owner_entry_index: u64,
}

impl PubPermissions {
    fn check_anyone_permissions(&self, action: Action) -> bool {
        match self.permissions.get(&User::Anyone) {
            None => false,
            Some(perms) => perms.is_allowed(action).unwrap_or(false),
        }
    }
}

impl Permissions for PubPermissions {
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> bool {
        match self.permissions.get(&User::Key(requester)) {
            Some(perms) => perms
                .is_allowed(action)
                .unwrap_or_else(|| self.check_anyone_permissions(action)),
            None => self.check_anyone_permissions(action),
        }
    }

    fn data_index(&self) -> u64 {
        self.data_index
    }

    fn owner_entry_index(&self) -> u64 {
        self.owner_entry_index
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Owners {
    owners: PublicKeySet,
    /// The current index of the data when this ownership change happened
    data_index: u64,
    /// The current index of the permissions when this ownership change happened
    permission_entry_index: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
struct AppendOnly<P: Permissions> {
    name: XorName,
    tag: u64,
    data: Vec<(Vec<u8>, Vec<u8>)>,
    permissions: Vec<P>,
    owners: Vec<Owners>,
}

/// Common methods for all `AppendOnlyData` flavours.
pub trait AppendOnlyData<P> {
    // /// Get a list of permissions for the provided user from the last entry in the permissions list.
    // fn user_permissions(&self, user: &User) -> Result<&PubPermissionSet, ClientError>;

    /// Return a value for the given key (if it is present).
    fn get(&self, key: &[u8]) -> Option<&Vec<u8>>;

    /// Get a list of keys and values with the given indices.
    fn in_range(&self, start: Index, end: Index) -> Option<&[(Vec<u8>, Vec<u8>)]>;

    /// Return all entries.
    fn entries(&self) -> &Vec<(Vec<u8>, Vec<u8>)>;

    /// Return the name of this AppendOnlyData.
    fn name(&self) -> XorName;

    /// Return the type tag of this AppendOnlyData.
    fn tag(&self) -> u64;

    /// Return the last entry index.
    fn entry_index(&self) -> u64;

    /// Return the last owners index.
    fn owners_index(&self) -> u64;

    /// Return the last permissions index.
    fn permissions_index(&self) -> u64;

    /// Get a complete list of permissions from the entry in the permissions list at the specified index.
    fn permissions_range(&self, start: Index, end: Index) -> Option<&[P]>;

    /// Add a new permissions entry.
    /// The `Permissions` struct should contain valid indexes.
    fn append_permissions(&mut self, permissions: P) -> Result<(), Error>;

    /// Get a complete list of owners from the entry in the permissions list at the specified index.
    fn owners_range(&self, start: Index, end: Index) -> Option<&[Owners]>;

    /// Add a new permissions entry.
    /// The `Owners` struct should contain valid indexes.
    fn append_owners(&mut self, owners: Owners) -> Result<(), Error>;
}

/// Common methods for published and unpublished unsequenced `AppendOnlyData`.
pub trait UnseqAppendOnly {
    /// Append new entries.
    fn append(&mut self, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<(), Error>;
}

/// Common methods for published and unpublished sequenced `AppendOnlyData`.
pub trait SeqAppendOnly {
    /// Append new entries.
    /// If the specified `last_entries_index` does not match the last recorded entries index, an error will be returned.
    fn append(
        &mut self,
        entries: &[(Vec<u8>, Vec<u8>)],
        last_entries_index: u64,
    ) -> Result<(), Error>;
}

macro_rules! impl_appendable_data {
    ($flavour:ident) => {
        #[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
        pub struct $flavour<P>
        where
            P: Permissions + std::hash::Hash,
        {
            inner: AppendOnly<P>,
        }

        impl<P> $flavour<P>
        where
            P: Permissions + std::hash::Hash,
        {
            pub fn new(name: XorName, tag: u64) -> Self {
                Self {
                    inner: AppendOnly {
                        name,
                        tag,
                        data: Vec::new(),
                        permissions: Vec::new(),
                        owners: Vec::new(),
                    },
                }
            }
        }

        impl<P> AppendOnlyData<P> for $flavour<P>
        where
            P: Permissions + std::hash::Hash,
        {
            fn name(&self) -> XorName {
                self.inner.name
            }

            fn tag(&self) -> u64 {
                self.inner.tag
            }

            fn entry_index(&self) -> u64 {
                self.inner.data.len() as u64
            }

            fn owners_index(&self) -> u64 {
                self.inner.owners.len() as u64
            }

            fn permissions_index(&self) -> u64 {
                self.inner.permissions.len() as u64
            }

            // fn user_permissions(&self, user: &User) -> Result<&PubPermissionSet, Error> {
            //     let perm_set = &self.inner.permissions[self.inner.permissions.len() - 1];
            //     perm_set.permissions.get(user).ok_or(Error::X)
            // }

            fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
                self.inner
                    .data
                    .iter()
                    .find_map(|(k, v)| if k.as_slice() == key { Some(v) } else { None })
            }

            fn in_range(&self, start: Index, end: Index) -> Option<&[(Vec<u8>, Vec<u8>)]> {
                let idx_start = match start {
                    Index::FromStart(idx) => idx as usize,
                    Index::FromEnd(idx) => self.inner.data.len() - (idx as usize),
                };
                let idx_end = match end {
                    Index::FromStart(idx) => idx as usize,
                    Index::FromEnd(idx) => self.inner.data.len() - (idx as usize),
                };

                // Check bounds
                if idx_start > self.inner.data.len() {
                    return None;
                }
                if idx_end < idx_start {
                    return None;
                }
                if idx_start == idx_end {
                    // Return empty slice because range len is 0
                    return Some(&[]);
                }

                Some(&self.inner.data[idx_start..idx_end])
            }

            fn entries(&self) -> &Vec<(Vec<u8>, Vec<u8>)> {
                &self.inner.data
            }

            fn permissions_range(&self, start: Index, end: Index) -> Option<&[P]> {
                // Check bounds
                let idx_start = match start {
                    Index::FromStart(idx) => idx as usize,
                    Index::FromEnd(idx) => self.inner.permissions.len() - (idx as usize),
                };
                let idx_end = match end {
                    Index::FromStart(idx) => idx as usize,
                    Index::FromEnd(idx) => self.inner.permissions.len() - (idx as usize),
                };
                if idx_start > self.inner.permissions.len() {
                    return None;
                }
                if idx_end < idx_start {
                    return None;
                }
                if idx_start == idx_end {
                    // Empty slice
                    return Some(&[]);
                }

                Some(&self.inner.permissions[idx_start..idx_end])
            }

            fn owners_range(&self, start: Index, end: Index) -> Option<&[Owners]> {
                // Check bounds
                let idx_start = match start {
                    Index::FromStart(idx) => idx as usize,
                    Index::FromEnd(idx) => self.inner.owners.len() - (idx as usize),
                };
                let idx_end = match end {
                    Index::FromStart(idx) => idx as usize,
                    Index::FromEnd(idx) => self.inner.owners.len() - (idx as usize),
                };
                if idx_start > self.inner.owners.len() {
                    return None;
                }
                if idx_end < idx_start {
                    return None;
                }
                if idx_start == idx_end {
                    // Empty slice
                    return Some(&[]);
                }

                Some(&self.inner.owners[idx_start..idx_end])
            }

            fn append_permissions(&mut self, permissions: P) -> Result<(), Error> {
                if permissions.data_index() != self.entry_index() {
                    return Err(Error::InvalidSuccessor(self.entry_index()));
                }
                if permissions.owner_entry_index() != self.owners_index() {
                    return Err(Error::InvalidOwnersSuccessor(self.owners_index()));
                }
                self.inner.permissions.push(permissions);
                Ok(())
            }

            fn append_owners(&mut self, owners: Owners) -> Result<(), Error> {
                if owners.data_index != self.entry_index() {
                    return Err(Error::InvalidSuccessor(self.entry_index()));
                }
                if owners.permission_entry_index != self.permissions_index() {
                    return Err(Error::InvalidPermissionsSuccessor(self.permissions_index()));
                }
                self.inner.owners.push(owners);
                Ok(())
            }
        }
    };
}

impl_appendable_data!(SeqAppendOnlyData);
impl_appendable_data!(UnseqAppendOnlyData);

impl<P> SeqAppendOnly for SeqAppendOnlyData<P>
where
    P: Permissions + std::hash::Hash,
{
    fn append(
        &mut self,
        entries: &[(Vec<u8>, Vec<u8>)],
        last_entries_index: u64,
    ) -> Result<(), Error> {
        if last_entries_index != self.inner.data.len() as u64 {
            return Err(Error::InvalidSuccessor(self.inner.data.len() as u64));
        }
        self.inner.data.extend(entries.iter().cloned());
        Ok(())
    }
}

impl<P> UnseqAppendOnly for UnseqAppendOnlyData<P>
where
    P: Permissions + std::hash::Hash,
{
    fn append(&mut self, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<(), Error> {
        self.inner.data.extend(entries.iter().cloned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand;
    use threshold_crypto::SecretKeySet;
    use unwrap::unwrap;

    #[test]
    fn append_permissions() {
        let mut data = SeqAppendOnlyData::<UnpubPermissions>::new(XorName([1; 32]), 10000);

        // Append the first permission set with correct indexes - should pass.
        let res = data.append_permissions(UnpubPermissions {
            permissions: BTreeMap::new(),
            data_index: 0,
            owner_entry_index: 0,
        });

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }

        // Verify that the permissions have been added.
        assert_eq!(
            unwrap!(data.permissions_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );

        // Append another permissions entry with incorrect indexes - should fail.
        let res = data.append_permissions(UnpubPermissions {
            permissions: BTreeMap::new(),
            data_index: 64,
            owner_entry_index: 0,
        });

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
        let mut rng = rand::thread_rng();
        let owners_pk_set = SecretKeySet::random(1, &mut rng);

        let mut data = SeqAppendOnlyData::<UnpubPermissions>::new(XorName([1; 32]), 10000);

        // Append the first owner with correct indexes - should pass.
        let res = data.append_owners(Owners {
            owners: owners_pk_set.public_keys(),
            data_index: 0,
            permission_entry_index: 0,
        });

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }

        // Verify that the owner has been added.
        assert_eq!(
            unwrap!(data.owners_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );

        // Append another owners entry with incorrect indexes - should fail.
        let res = data.append_owners(Owners {
            owners: owners_pk_set.public_keys(),
            data_index: 64,
            permission_entry_index: 0,
        });

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
    fn seq_append_entries() {
        let mut data = SeqAppendOnlyData::<PubPermissions>::new(XorName([1; 32]), 10000);
        let res = data.append(&[(b"hello".to_vec(), b"world".to_vec())], 0);

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }
    }
}
