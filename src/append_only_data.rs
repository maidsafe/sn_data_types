// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{Error, PublicKey, Request, Result, XorName};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use unwrap::unwrap;

pub type PubSeqAppendOnlyData = SeqAppendOnlyData<PubPermissions>;
pub type PubUnseqAppendOnlyData = UnseqAppendOnlyData<PubPermissions>;
pub type UnpubSeqAppendOnlyData = SeqAppendOnlyData<UnpubPermissions>;
pub type UnpubUnseqAppendOnlyData = UnseqAppendOnlyData<UnpubPermissions>;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum User {
    Anyone,
    Key(PublicKey),
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

// Set of data, owners, permissions Indices.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Indices {
    data_index: u64,
    owners_index: u64,
    permissions_index: u64,
}

impl Indices {
    pub fn new(data_index: u64, owners_index: u64, permissions_index: u64) -> Self {
        Indices {
            data_index,
            owners_index,
            permissions_index,
        }
    }

    pub fn data_index(&self) -> u64 {
        self.data_index
    }

    pub fn owners_index(&self) -> u64 {
        self.owners_index
    }

    pub fn permissions_index(&self) -> u64 {
        self.permissions_index
    }
}

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct UnpubPermissionSet {
    read: bool,
    append: bool,
    manage_permissions: bool,
}

impl UnpubPermissionSet {
    pub fn new(read: bool, append: bool, manage_perms: bool) -> Self {
        UnpubPermissionSet {
            read,
            append,
            manage_permissions: manage_perms,
        }
    }

    pub fn set_perms(&mut self, read: bool, append: bool, manage_perms: bool) {
        self.read = read;
        self.append = append;
        self.manage_permissions = manage_perms;
    }

    pub fn is_allowed(self, action: Action) -> bool {
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
    pub fn new(append: bool, manage_perms: bool) -> Self {
        PubPermissionSet {
            append: Some(append),
            manage_permissions: Some(manage_perms),
        }
    }

    pub fn set_perms(&mut self, append: bool, manage_perms: bool) {
        self.append = Some(append);
        self.manage_permissions = Some(manage_perms);
    }

    pub fn is_allowed(self, action: Action) -> Option<bool> {
        match action {
            Action::Read => Some(true), // It's published data, so it's always allowed to read it.
            Action::Append => self.append,
            Action::ManagePermissions => self.manage_permissions,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    PubSeq { name: XorName, tag: u64 },
    PubUnseq { name: XorName, tag: u64 },
    UnpubSeq { name: XorName, tag: u64 },
    UnpubUnseq { name: XorName, tag: u64 },
}

impl Address {
    pub fn new_pub_seq(name: XorName, tag: u64) -> Self {
        Address::PubSeq { name, tag }
    }

    pub fn new_pub_unseq(name: XorName, tag: u64) -> Self {
        Address::PubUnseq { name, tag }
    }

    pub fn new_unpub_seq(name: XorName, tag: u64) -> Self {
        Address::UnpubSeq { name, tag }
    }

    pub fn new_unpub_unseq(name: XorName, tag: u64) -> Self {
        Address::UnpubUnseq { name, tag }
    }

    pub fn name(&self) -> &XorName {
        match self {
            Address::PubSeq { ref name, .. }
            | Address::PubUnseq { ref name, .. }
            | Address::UnpubSeq { ref name, .. }
            | Address::UnpubUnseq { ref name, .. } => name,
        }
    }

    pub fn tag(&self) -> u64 {
        match self {
            Address::PubSeq { tag, .. }
            | Address::PubUnseq { tag, .. }
            | Address::UnpubSeq { tag, .. }
            | Address::UnpubUnseq { tag, .. } => *tag,
        }
    }
}

pub trait Permissions {
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> bool;
    fn data_index(&self) -> u64;
    fn owner_entry_index(&self) -> u64;
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct UnpubPermissions {
    pub permissions: BTreeMap<PublicKey, UnpubPermissionSet>,
    /// The current index of the data when this permission change happened
    pub data_index: u64,
    /// The current index of the owners when this permission change happened
    pub owner_entry_index: u64,
}

impl UnpubPermissions {
    pub fn permissions(&self) -> BTreeMap<PublicKey, UnpubPermissionSet> {
        self.permissions.clone()
    }
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
    pub permissions: BTreeMap<User, PubPermissionSet>,
    /// The current index of the data when this permission change happened
    pub data_index: u64,
    /// The current index of the owners when this permission change happened
    pub owner_entry_index: u64,
}

impl PubPermissions {
    fn check_anyone_permissions(&self, action: Action) -> bool {
        match self.permissions.get(&User::Anyone) {
            None => false,
            Some(perms) => perms.is_allowed(action).unwrap_or(false),
        }
    }

    pub fn permissions(&self) -> &BTreeMap<User, PubPermissionSet> {
        &self.permissions
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
pub struct Owner {
    pub public_key: PublicKey,
    /// The current index of the data when this ownership change happened
    pub data_index: u64,
    /// The current index of the permissions when this ownership change happened
    pub permissions_index: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
struct AppendOnly<P: Permissions> {
    address: Address,
    data: Vec<(Vec<u8>, Vec<u8>)>,
    permissions: Vec<P>,
    // This is the history of owners, with each entry representing an owner.  Each single owner
    // could represent an individual user, or a group of users, depending on the `PublicKey` type.
    owners: Vec<Owner>,
}

/// Common methods for all `AppendOnlyData` flavours.
pub trait AppendOnlyData<P> {
    // /// Get a list of permissions for the provided user from the last entry in the permissions list.
    // fn user_permissions(&self, user: &User) -> Result<&PubPermissionSet>;

    /// Return a value for the given key (if it is present).
    fn get(&self, key: &[u8]) -> Option<&Vec<u8>>;

    /// Return the last entry in the Data (if it is present).
    fn last(&self) -> Option<(Vec<u8>, Vec<u8>)>;

    /// Get a list of keys and values with the given indices.
    fn in_range(&self, start: Index, end: Index) -> Option<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Return all entries.
    fn entries(&self) -> &Vec<(Vec<u8>, Vec<u8>)>;

    /// Return the address of this AppendOnlyData.
    fn address(&self) -> &Address;

    /// Return the name of this AppendOnlyData.
    fn name(&self) -> &XorName;

    /// Return the type tag of this AppendOnlyData.
    fn tag(&self) -> u64;

    /// Return the last entry index.
    fn entry_index(&self) -> u64;

    /// Return the last owners index.
    fn owners_index(&self) -> u64;

    /// Return the last permissions index.
    fn permissions_index(&self) -> u64;

    /// Get a complete list of permissions from the entry in the permissions list at the specified
    /// index.
    fn permissions_range(&self, start: Index, end: Index) -> Option<&[P]>;

    /// Add a new permissions entry.
    /// The `Permissions` struct should contain valid indices.
    fn append_permissions(&mut self, permissions: P) -> Result<()>;

    /// Fetch perms at index.
    fn fetch_permissions_at_index(&self, perm_index: u64) -> Option<&P>;

    /// Fetch owners at index.
    fn fetch_owner_at_index(&self, owners_index: u64) -> Option<&Owner>;

    /// Get a complete list of owners from the entry in the permissions list at the specified index.
    fn owners_range(&self, start: Index, end: Index) -> Option<&[Owner]>;

    /// Add a new owner entry.
    fn append_owner(&mut self, owner: Owner) -> Result<()>;

    /// Verifies permission for Non-Owners.
    fn check_permissions_for_key(
        &self,
        requester: PublicKey,
        permissions: &P,
        request: Request,
    ) -> Result<()>;
}

/// Common methods for published and unpublished unsequenced `AppendOnlyData`.
pub trait UnseqAppendOnly {
    /// Append new entries.
    fn append(&mut self, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<()>;
}

/// Common methods for published and unpublished sequenced `AppendOnlyData`.
pub trait SeqAppendOnly {
    /// Append new entries.
    ///
    /// If the specified `last_entries_index` does not match the last recorded entries index, an
    /// error will be returned.
    fn append(&mut self, entries: &[(Vec<u8>, Vec<u8>)], last_entries_index: u64) -> Result<()>;
}

macro_rules! impl_appendable_data {
    ($flavour:ident) => {
        #[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
        pub struct $flavour<P>
        where
            P: Permissions + std::hash::Hash + Clone,
        {
            inner: AppendOnly<P>,
        }

        impl<P> $flavour<P>
        where
            P: Permissions + std::hash::Hash + Clone,
        {
            pub fn shell(&self, index: u64) -> Result<Self> {
                if index > self.entry_index() {
                    return Err(Error::NoSuchEntry);
                }

                let permissions = self
                    .inner
                    .permissions
                    .iter()
                    .filter(|perm| perm.data_index() <= index)
                    .cloned()
                    .collect();

                let owners = self
                    .inner
                    .owners
                    .iter()
                    .filter(|owner| owner.data_index <= index)
                    .cloned()
                    .collect();

                Ok(Self {
                    inner: AppendOnly {
                        address: self.inner.address,
                        data: Vec::new(),
                        permissions,
                        owners,
                    },
                })
            }

            pub fn check_permission(&self, request: Request, requester: PublicKey) -> Result<()> {
                if unwrap!(self.inner.owners.last()).public_key == requester {
                    Ok(())
                } else {
                    self.check_permissions_for_key(
                        requester,
                        unwrap!(self.inner.permissions.last()),
                        request,
                    )
                }
            }
        }

        impl<P> AppendOnlyData<P> for $flavour<P>
        where
            P: Permissions + std::hash::Hash + Clone,
        {
            fn address(&self) -> &Address {
                &self.inner.address
            }

            fn name(&self) -> &XorName {
                self.inner.address.name()
            }

            fn tag(&self) -> u64 {
                self.inner.address.tag()
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

            fn check_permissions_for_key(
                &self,
                requester: PublicKey,
                permissions: &P,
                request: Request,
            ) -> Result<()> {
                match request {
                    Request::GetAData(..)
                    | Request::GetADataShell { .. }
                    | Request::GetADataRange { .. }
                    | Request::GetADataIndices(..)
                    | Request::GetADataLastEntry(..)
                    | Request::GetADataPermissions { .. }
                    | Request::GetPubADataUserPermissions { .. }
                    | Request::GetUnpubADataUserPermissions { .. }
                    | Request::GetADataOwners { .. } => {
                        if permissions.is_action_allowed(requester, Action::Read) {
                            Ok(())
                        } else {
                            Err(Error::AccessDenied)
                        }
                    }
                    Request::AddPubADataPermissions { .. }
                    | Request::AddUnpubADataPermissions { .. }
                    | Request::SetADataOwner { .. } => {
                        if permissions.is_action_allowed(requester, Action::ManagePermissions) {
                            Ok(())
                        } else {
                            Err(Error::AccessDenied)
                        }
                    }

                    // Mutation permissions are checked later
                    Request::AppendSeq { .. } | Request::AppendUnseq { .. } => Ok(()),

                    Request::DeleteAData { .. } => Err(Error::AccessDenied),

                    _ => Err(Error::InvalidOperation),
                }
            }

            fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
                self.inner
                    .data
                    .iter()
                    .find_map(|(k, v)| if k.as_slice() == key { Some(v) } else { None })
            }

            fn last(&self) -> Option<(Vec<u8>, Vec<u8>)> {
                match self.inner.data.last() {
                    Some(tup) => Some(tup.clone()),
                    None => None,
                }
            }

            fn fetch_permissions_at_index(&self, perm_index: u64) -> Option<&P> {
                self.inner.permissions.get(perm_index as usize)
            }

            fn fetch_owner_at_index(&self, owners_index: u64) -> Option<&Owner> {
                self.inner.owners.get(owners_index as usize)
            }

            fn in_range(&self, start: Index, end: Index) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
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
                    return Some(Vec::new());
                }

                Some(self.inner.data[idx_start..idx_end].to_vec())
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

            fn owners_range(&self, start: Index, end: Index) -> Option<&[Owner]> {
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

            fn append_permissions(&mut self, permissions: P) -> Result<()> {
                if permissions.data_index() != self.entry_index() {
                    return Err(Error::InvalidSuccessor(self.entry_index()));
                }
                if permissions.owner_entry_index() != self.owners_index() {
                    return Err(Error::InvalidOwnersSuccessor(self.owners_index()));
                }
                self.inner.permissions.push(permissions);
                Ok(())
            }

            fn append_owner(&mut self, owner: Owner) -> Result<()> {
                if owner.data_index != self.entry_index() {
                    return Err(Error::InvalidSuccessor(self.entry_index()));
                }
                if owner.permissions_index != self.permissions_index() {
                    return Err(Error::InvalidPermissionsSuccessor(self.permissions_index()));
                }
                self.inner.owners.push(owner);
                Ok(())
            }
        }
    };
}

impl_appendable_data!(SeqAppendOnlyData);
impl_appendable_data!(UnseqAppendOnlyData);

impl SeqAppendOnlyData<PubPermissions> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            inner: AppendOnly {
                address: Address::new_pub_seq(name, tag),
                data: Vec::new(),
                permissions: Vec::new(),
                owners: Vec::new(),
            },
        }
    }
}

impl UnseqAppendOnlyData<PubPermissions> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            inner: AppendOnly {
                address: Address::new_pub_unseq(name, tag),
                data: Vec::new(),
                permissions: Vec::new(),
                owners: Vec::new(),
            },
        }
    }
}

impl SeqAppendOnlyData<UnpubPermissions> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            inner: AppendOnly {
                address: Address::new_unpub_seq(name, tag),
                data: Vec::new(),
                permissions: Vec::new(),
                owners: Vec::new(),
            },
        }
    }
}

impl UnseqAppendOnlyData<UnpubPermissions> {
    pub fn new(name: XorName, tag: u64) -> Self {
        Self {
            inner: AppendOnly {
                address: Address::new_unpub_unseq(name, tag),
                data: Vec::new(),
                permissions: Vec::new(),
                owners: Vec::new(),
            },
        }
    }
}

impl<P> SeqAppendOnly for SeqAppendOnlyData<P>
where
    P: Permissions + std::hash::Hash + Clone,
{
    fn append(&mut self, entries: &[(Vec<u8>, Vec<u8>)], last_entries_index: u64) -> Result<()> {
        if last_entries_index != self.inner.data.len() as u64 {
            return Err(Error::InvalidSuccessor(self.inner.data.len() as u64));
        }
        self.inner.data.extend(entries.iter().cloned());
        Ok(())
    }
}

impl<P> UnseqAppendOnly for UnseqAppendOnlyData<P>
where
    P: Permissions + std::hash::Hash + Clone,
{
    fn append(&mut self, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        self.inner.data.extend(entries.iter().cloned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use threshold_crypto::SecretKey;
    use unwrap::unwrap;

    #[test]
    fn append_permissions() {
        let mut data = SeqAppendOnlyData::<UnpubPermissions>::new(XorName([1; 32]), 10000);

        // Append the first permission set with correct indices - should pass.
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

        // Append another permissions entry with incorrect indices - should fail.
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
        let owner_pk = PublicKey::Bls(SecretKey::random().public_key());

        let mut data = SeqAppendOnlyData::<UnpubPermissions>::new(XorName([1; 32]), 10000);

        // Append the first owner with correct indices - should pass.
        let res = data.append_owner(Owner {
            public_key: owner_pk,
            data_index: 0,
            permissions_index: 0,
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

        // Append another owners entry with incorrect indices - should fail.
        let res = data.append_owner(Owner {
            public_key: owner_pk,
            data_index: 64,
            permissions_index: 0,
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

    #[test]
    fn assert_shell() {
        let owner_pk = PublicKey::Bls(SecretKey::random().public_key());
        let owner_pk1 = PublicKey::Bls(SecretKey::random().public_key());

        let mut data = SeqAppendOnlyData::<UnpubPermissions>::new(XorName([1; 32]), 10000);

        let _ = data.append_owner(Owner {
            public_key: owner_pk,
            data_index: 0,
            permissions_index: 0,
        });

        let _ = data.append_owner(Owner {
            public_key: owner_pk1,
            data_index: 0,
            permissions_index: 0,
        });

        assert_eq!(data.owners_index(), unwrap!(data.shell(0)).owners_index());
    }
}
