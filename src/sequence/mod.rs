// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod metadata;
mod seq_crdt;

use crate::{Error, PublicKey, Result, XorName};
pub use metadata::{
    Action, Address, Entries, Entry, Index, Kind, Owner, Perm, Permissions, Policy,
    PrivPermissions, PrivPolicy, PubPermissions, PubPolicy, User,
};
use seq_crdt::{CrdtOperation, Op, SequenceCrdt};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
    hash::Hash,
};

// Type of data used for the 'Actor' in CRDT vector clocks
type ActorType = PublicKey;

/// Mutation operation to apply to Sequence.
/// This is used for all kind of operations made on the Sequence,
/// i.e. not only on the data but also on the policy.
pub type MutationOperation<T> = CrdtOperation<ActorType, T>;

/// Public Sequence.
pub type PubSeqData = SequenceCrdt<ActorType, PubPolicy>;
/// Private Sequence.
pub type PrivSeqData = SequenceCrdt<ActorType, PrivPolicy>;

impl Debug for PubSeqData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PubSequence {:?}", self.address().name())
    }
}

impl Debug for PrivSeqData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivSequence {:?}", self.address().name())
    }
}

/// Object storing a Sequence variant.
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    /// Public Sequence Data.
    Public(PubSeqData),
    /// Private Sequence Data.
    Private(PrivSeqData),
}

impl Data {
    /// Constructs a new Public Sequence Data.
    pub fn new_pub(actor: ActorType, name: XorName, tag: u64) -> Self {
        Self::Public(PubSeqData::new(actor, Address::Public { name, tag }))
    }

    /// Constructs a new Private Sequence Data.
    pub fn new_priv(actor: ActorType, name: XorName, tag: u64) -> Self {
        Self::Private(PrivSeqData::new(actor, Address::Private { name, tag }))
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        match self {
            Data::Public(data) => data.address(),
            Data::Private(data) => data.address(),
        }
    }

    /// Returns the kind.
    pub fn kind(&self) -> Kind {
        self.address().kind()
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        self.address().name()
    }

    /// Returns the tag.
    pub fn tag(&self) -> u64 {
        self.address().tag()
    }

    /// Returns `true` if public.
    pub fn is_pub(&self) -> bool {
        self.kind().is_pub()
    }

    /// Returns `true` if private.
    pub fn is_priv(&self) -> bool {
        self.kind().is_priv()
    }

    /// Checks permissions for given `action` for the provided user.
    ///
    /// Returns:
    /// `Ok(())` if the permissions are valid,
    /// `Err::InvalidOwners` if the last owner is invalid,
    /// `Err::AccessDenied` if the action is not allowed.
    pub fn check_permission(&self, action: Action, requester: PublicKey) -> Result<()> {
        macro_rules! check_perm {
            ($data: ident, $requester: ident, $action: ident) => {
                $data.check_is_last_owner($requester).or_else(|_| {
                    $data
                        .policy(Index::FromEnd(1))
                        .ok_or(Error::AccessDenied)?
                        .is_action_allowed($requester, $action)
                })
            };
        }

        match self {
            Data::Public(data) => {
                if action == Action::Read {
                    return Ok(());
                }
                check_perm!(data, requester, action)
            }
            Data::Private(data) => check_perm!(data, requester, action),
        }
    }

    /// Returns the last entry index.
    pub fn entries_index(&self) -> u64 {
        match self {
            Data::Public(data) => data.entries_index(),
            Data::Private(data) => data.entries_index(),
        }
    }

    /// Returns the last permissions index.
    pub fn policy_index(&self) -> u64 {
        match self {
            Data::Public(data) => data.policy_index(),
            Data::Private(data) => data.policy_index(),
        }
    }

    /// Returns the last owners index.
    pub fn owners_index(&self) -> u64 {
        match self {
            Data::Public(data) => data.owners_index(),
            Data::Private(data) => data.owners_index(),
        }
    }

    /// Gets a list of items which are within the given indices.
    pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
        match self {
            Data::Public(data) => data.in_range(start, end),
            Data::Private(data) => data.in_range(start, end),
        }
    }

    /// Returns a value at 'index', if present.
    pub fn get(&self, index: Index) -> Option<&Vec<u8>> {
        match self {
            Data::Public(data) => data.get(index),
            Data::Private(data) => data.get(index),
        }
    }

    /// Returns the last entry, if present.
    pub fn last_entry(&self) -> Option<&Entry> {
        match self {
            Data::Public(data) => data.last_entry(),
            Data::Private(data) => data.last_entry(),
        }
    }

    /// Fetches owner fo history at index.
    pub fn owner(&self, owners_index: impl Into<Index>) -> Option<&Owner> {
        match self {
            Data::Public(data) => data.owner(owners_index),
            Data::Private(data) => data.owner(owners_index),
        }
    }

    /// Appends new entry.
    pub fn append(&mut self, entry: Entry) -> MutationOperation<Entry> {
        match self {
            Data::Public(data) => data.append(entry),
            Data::Private(data) => data.append(entry),
        }
    }

    /// Apply a data CRDT operation.
    pub fn apply_data_op(&mut self, op: MutationOperation<Entry>) {
        match self {
            Data::Public(data) => data.apply_data_op(op),
            Data::Private(data) => data.apply_data_op(op),
        };
    }

    /// Sets the new policy for Public Sequence.
    pub fn set_pub_policy(
        &mut self,
        permissions: BTreeMap<User, PubPermissions>,
    ) -> Result<MutationOperation<PubPolicy>> {
        match self {
            Data::Public(data) => Ok(data.set_policy(PubPolicy {
                entries_index: data.entries_index(),
                owners_index: data.owners_index(),
                permissions,
            })),
            Data::Private(_) => Err(Error::InvalidOperation),
        }
    }

    /// Sets the new policy for Private Sequence.
    pub fn set_priv_policy(
        &mut self,
        permissions: BTreeMap<PublicKey, PrivPermissions>,
    ) -> Result<MutationOperation<PrivPolicy>> {
        match self {
            Data::Private(data) => Ok(data.set_policy(PrivPolicy {
                entries_index: data.entries_index(),
                owners_index: data.owners_index(),
                permissions,
            })),
            Data::Public(_) => Err(Error::InvalidOperation),
        }
    }

    /// Apply Public Policy CRDT operation.
    pub fn apply_crdt_pub_policy_op(&mut self, op: MutationOperation<PubPolicy>) -> Result<()> {
        match (self, &op.crdt_op) {
            (Data::Public(data), Op::Insert { .. }) => {
                data.apply_policy_op(op);
                Ok(())
            }
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Apply Private Policy CRDT operation.
    pub fn apply_crdt_priv_policy_op(&mut self, op: MutationOperation<PrivPolicy>) -> Result<()> {
        match self {
            Data::Private(data) => {
                data.apply_policy_op(op);
                Ok(())
            }
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Sets the new owner.
    pub fn set_owner(&mut self, owner: PublicKey) -> MutationOperation<Owner> {
        match self {
            Data::Public(data) => data.set_owner(owner),
            Data::Private(data) => data.set_owner(owner),
        }
    }

    /// Apply Owner CRDT operation.
    pub fn apply_crdt_owner_op(&mut self, op: MutationOperation<Owner>) {
        match self {
            Data::Public(data) => data.apply_crdt_owner_op(op),
            Data::Private(data) => data.apply_crdt_owner_op(op),
        };
    }

    /// Checks if the requester is the last owner.
    ///
    /// Returns:
    /// `Ok(())` if the requester is the owner,
    /// `Err::InvalidOwners` if the last owner is invalid,
    /// `Err::AccessDenied` if the requester is not the owner.
    pub fn check_is_last_owner(&self, requester: PublicKey) -> Result<()> {
        match self {
            Data::Public(data) => data.check_is_last_owner(requester),
            Data::Private(data) => data.check_is_last_owner(requester),
        }
    }

    /// Returns user permissions, if applicable.
    pub fn permissions(&self, user: User, version: impl Into<Index>) -> Result<Permissions> {
        let user_perm = match self {
            Data::Public(data) => data
                .policy(version)
                .ok_or(Error::NoSuchEntry)?
                .permissions(user)
                .ok_or(Error::NoSuchEntry)?,
            Data::Private(data) => data
                .policy(version)
                .ok_or(Error::NoSuchEntry)?
                .permissions(user)
                .ok_or(Error::NoSuchEntry)?,
        };

        Ok(user_perm)
    }

    /// Returns public policy, if applicable.
    pub fn pub_policy(&self, version: impl Into<Index>) -> Result<&PubPolicy> {
        let perms = match self {
            Data::Public(data) => data.policy(version),
            Data::Private(_) => return Err(Error::InvalidOperation),
        };
        perms.ok_or(Error::NoSuchEntry)
    }

    /// Returns private policy, if applicable.
    pub fn priv_policy(&self, version: impl Into<Index>) -> Result<&PrivPolicy> {
        let perms = match self {
            Data::Private(data) => data.policy(version),
            Data::Public(_) => return Err(Error::InvalidOperation),
        };
        perms.ok_or(Error::NoSuchEntry)
    }
}

impl From<PubSeqData> for Data {
    fn from(data: PubSeqData) -> Self {
        Data::Public(data)
    }
}

impl From<PrivSeqData> for Data {
    fn from(data: PrivSeqData) -> Self {
        Data::Private(data)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Error, PublicKey, Result, SData, SDataAddress, SDataIndex, SDataKind, SDataPermissions,
        SDataPrivPermissions, SDataPubPermissions, SDataUser, XorName,
    };
    use std::collections::BTreeMap;
    use threshold_crypto::SecretKey;

    fn gen_public_key() -> PublicKey {
        PublicKey::Bls(SecretKey::random().public_key())
    }

    #[test]
    fn sequence_create_public() {
        let actor = gen_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_000;
        let sdata = SData::new_pub(actor, sdata_name, sdata_tag);
        assert_eq!(sdata.kind(), SDataKind::Public);
        assert_eq!(*sdata.name(), sdata_name);
        assert_eq!(sdata.tag(), sdata_tag);
        assert!(sdata.is_pub());
        assert!(!sdata.is_priv());

        let sdata_address = SDataAddress::from_kind(SDataKind::Public, sdata_name, sdata_tag);
        assert_eq!(*sdata.address(), sdata_address);
    }

    #[test]
    fn sequence_create_private() {
        let actor = gen_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_000;
        let sdata = SData::new_priv(actor, sdata_name, sdata_tag);
        assert_eq!(sdata.kind(), SDataKind::Private);
        assert_eq!(*sdata.name(), sdata_name);
        assert_eq!(sdata.tag(), sdata_tag);
        assert!(!sdata.is_pub());
        assert!(sdata.is_priv());

        let sdata_address = SDataAddress::from_kind(SDataKind::Private, sdata_name, sdata_tag);
        assert_eq!(*sdata.address(), sdata_address);
    }

    #[test]
    fn sequence_append_entry_and_apply() {
        let actor = gen_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_000;
        let mut replica1 = SData::new_pub(actor, sdata_name, sdata_tag);
        let mut replica2 = SData::new_pub(actor, sdata_name, sdata_tag);

        let entry1 = b"value0".to_vec();
        let entry2 = b"value1".to_vec();

        let op1 = replica1.append(entry1.clone());
        let op2 = replica1.append(entry2.clone());

        // we apply the operations in different order, to verify that doesn't affect the result
        replica2.apply_data_op(op2);
        replica2.apply_data_op(op1);

        assert_eq!(replica1.entries_index(), 2);
        assert_eq!(replica2.entries_index(), 2);

        let index_0 = SDataIndex::FromStart(0);
        let first_entry = replica1.get(index_0);
        assert_eq!(first_entry, Some(&entry1));
        assert_eq!(first_entry, replica2.get(index_0));

        let index_1 = SDataIndex::FromStart(1);
        let second_entry = replica1.get(index_1);
        assert_eq!(second_entry, Some(&entry2));
        assert_eq!(second_entry, replica2.get(index_1));

        let last_entry = replica1.last_entry();
        assert_eq!(last_entry, Some(&entry2));
        assert_eq!(last_entry, replica2.last_entry());
    }

    #[test]
    fn sequence_public_append_perms_and_apply() -> Result<()> {
        let actor = gen_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_000;
        let mut replica1 = SData::new_pub(actor, sdata_name, sdata_tag);
        let mut replica2 = SData::new_pub(actor, sdata_name, sdata_tag);

        let mut perms1 = BTreeMap::default();
        let user_perms1 = SDataPubPermissions::new(true, false);
        let _ = perms1.insert(SDataUser::Anyone, user_perms1);

        let mut perms2 = BTreeMap::default();
        let user_perms2 = SDataPubPermissions::new(false, true);
        let _ = perms2.insert(SDataUser::Key(actor), user_perms2);

        let op1 = replica1.set_pub_policy(perms1.clone())?;
        let op2 = replica1.set_pub_policy(perms2.clone())?;

        // we apply the operations in different order, to verify that doesn't affect the result
        replica2.apply_crdt_pub_policy_op(op2)?;
        replica2.apply_crdt_pub_policy_op(op1)?;

        assert_eq!(replica1.policy_index(), 2);
        assert_eq!(replica2.policy_index(), 2);

        let index_0 = SDataIndex::FromStart(0);
        let first_entry = replica1.pub_policy(index_0)?;
        assert_eq!(first_entry.permissions, perms1);
        assert_eq!(first_entry.entries_index, 0);
        assert_eq!(first_entry.owners_index, 0);
        assert_eq!(first_entry, replica2.pub_policy(index_0)?);
        assert_eq!(
            SDataPermissions::Pub(user_perms1),
            replica1.permissions(SDataUser::Anyone, index_0)?
        );

        let index_1 = SDataIndex::FromStart(1);
        let second_entry = replica1.pub_policy(index_1)?;
        assert_eq!(second_entry.permissions, perms2);
        assert_eq!(second_entry.entries_index, 0);
        assert_eq!(second_entry.owners_index, 0);
        assert_eq!(second_entry, replica2.pub_policy(index_1)?);
        assert_eq!(
            SDataPermissions::Pub(user_perms2),
            replica1.permissions(SDataUser::Key(actor), index_1)?
        );

        Ok(())
    }

    #[test]
    fn sequence_private_append_perms_and_apply() -> Result<()> {
        let actor1 = gen_public_key();
        let actor2 = gen_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_000;
        let mut replica1 = SData::new_priv(actor1, sdata_name, sdata_tag);
        let mut replica2 = SData::new_priv(actor2, sdata_name, sdata_tag);

        let mut perms1 = BTreeMap::default();
        let user_perms1 = SDataPrivPermissions::new(true, false, true);
        let _ = perms1.insert(actor1, user_perms1);

        let mut perms2 = BTreeMap::default();
        let user_perms2 = SDataPrivPermissions::new(false, true, false);
        let _ = perms2.insert(actor2, user_perms2);

        let op1 = replica1.set_priv_policy(perms1.clone())?;
        let op2 = replica1.set_priv_policy(perms2.clone())?;

        // we apply the operations in different order, to verify that doesn't affect the result
        replica2.apply_crdt_priv_policy_op(op2)?;
        replica2.apply_crdt_priv_policy_op(op1)?;

        assert_eq!(replica1.policy_index(), 2);
        assert_eq!(replica2.policy_index(), 2);

        let index_0 = SDataIndex::FromStart(0);
        let first_entry = replica1.priv_policy(index_0)?;
        assert_eq!(first_entry.permissions, perms1);
        assert_eq!(first_entry.entries_index, 0);
        assert_eq!(first_entry.owners_index, 0);
        assert_eq!(first_entry, replica2.priv_policy(index_0)?);
        assert_eq!(
            SDataPermissions::Priv(user_perms1),
            replica1.permissions(SDataUser::Key(actor1), index_0)?
        );

        let index_1 = SDataIndex::FromStart(1);
        let second_entry = replica1.priv_policy(index_1)?;
        assert_eq!(second_entry.permissions, perms2);
        assert_eq!(second_entry.entries_index, 0);
        assert_eq!(second_entry.owners_index, 0);
        assert_eq!(second_entry, replica2.priv_policy(index_1)?);
        assert_eq!(
            SDataPermissions::Priv(user_perms2),
            replica1.permissions(SDataUser::Key(actor2), index_1)?
        );

        Ok(())
    }

    #[test]
    fn sequence_set_owner_and_apply() -> Result<()> {
        let actor = gen_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_000;
        let mut replica1 = SData::new_pub(actor, sdata_name, sdata_tag);
        let mut replica2 = SData::new_pub(actor, sdata_name, sdata_tag);

        let owner1 = gen_public_key();
        let owner2 = gen_public_key();
        let op1 = replica1.set_owner(owner1);
        let op2 = replica1.set_owner(owner2);

        // we apply the operations in different order, to verify that doesn't affect the result
        replica2.apply_crdt_owner_op(op2);
        replica2.apply_crdt_owner_op(op1);

        assert_eq!(replica1.owners_index(), 2);
        assert_eq!(replica2.owners_index(), 2);

        let index_0 = SDataIndex::FromStart(0);
        let first_owner = replica1.owner(index_0).ok_or(Error::InvalidOwners)?;
        assert_eq!(first_owner.public_key, owner1);
        assert_eq!(first_owner.entries_index, 0);
        assert_eq!(first_owner.policy_index, 0);
        assert_eq!(
            first_owner,
            replica2.owner(index_0).ok_or(Error::InvalidOwners)?
        );

        let index_1 = SDataIndex::FromStart(1);
        let second_owner = replica1.owner(index_1).ok_or(Error::InvalidOwners)?;
        assert_eq!(second_owner.public_key, owner2);
        assert_eq!(second_owner.entries_index, 0);
        assert_eq!(second_owner.policy_index, 0);
        assert_eq!(
            second_owner,
            replica2.owner(index_1).ok_or(Error::InvalidOwners)?
        );

        replica1.check_is_last_owner(owner2)?;
        replica2.check_is_last_owner(owner2)?;

        Ok(())
    }

    #[test]
    fn sequence_concurrent_policy_and_data_ops() -> Result<()> {
        let actor1 = gen_public_key();
        let actor2 = gen_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_000u64;

        // Instantiate the same Sequence on two replicas with two diff actors
        let mut replica1 = SData::new_pub(actor1, sdata_name, sdata_tag);
        let mut replica2 = SData::new_pub(actor2, sdata_name, sdata_tag);

        // Set Actor1 as the owner in both replicas
        let _ = replica1.set_owner(actor1);
        let _ = replica2.set_owner(actor1);

        // Grant authorisation for Append to Actor2 in both replicas
        let mut perms = BTreeMap::default();
        let user_perms = SDataPubPermissions::new(/*append=*/ true, /*admin=*/ false);
        let _ = perms.insert(SDataUser::Key(actor2), user_perms);

        let _ = replica1.set_pub_policy(perms.clone())?;
        let _ = replica2.set_pub_policy(perms)?;
        // Let's assert initial state on both replicas
        assert_eq!(replica1.entries_index(), 0);
        assert_eq!(replica1.policy_index(), 1);
        assert_eq!(replica2.entries_index(), 0);
        assert_eq!(replica2.policy_index(), 1);

        // We revoke authorisation for Actor2 locally on replica1
        let perms_empty = BTreeMap::default();
        let _revoke_op = replica1.set_pub_policy(perms_empty)?;
        // New Policy should have been set on replica1
        assert_eq!(replica1.entries_index(), 0);
        assert_eq!(replica1.policy_index(), 2);

        // Concurrently append an item with Actor2 on replica2
        let item = b"item0";
        let append_op = replica2.append(item.to_vec());
        // Item should have been temporarilly appended on replica2
        assert_eq!(replica2.entries_index(), 1);
        assert_eq!(replica2.policy_index(), 1);

        // Append operation is broadcasted and applied on replica1
        // which shall be ignored as per current policy
        replica1.apply_data_op(append_op);
        /*
                // Now revoke operation is broadcasted and applied on replica2
                replica2.apply_crdt_pub_policy_op(revoke_op)?;
                // Let's assert append op was undone on replica2 due to new and retroactive policy
                assert_eq!(replica2.entries_index(), 0);
                assert_eq!(replica2.policy_index(), 2);
        */
        Ok(())
    }

    #[test]
    fn sequence_causality_between_data_and_policy_ops() -> Result<()> {
        let actor1 = gen_public_key();
        let actor2 = gen_public_key();
        let actor3 = gen_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_001u64;

        // Instantiate the same Sequence on three replicas with three diff actors
        let mut replica1 = SData::new_pub(actor1, sdata_name, sdata_tag);
        let mut replica2 = SData::new_pub(actor2, sdata_name, sdata_tag);
        let mut replica3 = SData::new_pub(actor3, sdata_name, sdata_tag);

        // Set Actor1 as the owner in all replicas
        let user1 = gen_public_key();
        let user3 = gen_public_key();
        let _ = replica1.set_owner(user1);
        let _ = replica2.set_owner(user1);
        let _ = replica3.set_owner(user1);

        // Grant authorisation for Append to Actor3 in replica1 and apply to replica3 too
        let mut perms = BTreeMap::default();
        let user_perms = SDataPubPermissions::new(/*append=*/ true, /*admin=*/ false);
        let _ = perms.insert(SDataUser::Key(user3), user_perms);

        let grant_op = replica1.set_pub_policy(perms)?;
        replica3.apply_crdt_pub_policy_op(grant_op.clone())?;

        // Let's assert the state on three replicas
        assert_eq!(replica1.entries_index(), 0);
        assert_eq!(replica1.policy_index(), 1);
        assert_eq!(replica2.entries_index(), 0);
        assert_eq!(replica2.policy_index(), 0);
        assert_eq!(replica3.entries_index(), 0);
        assert_eq!(replica3.policy_index(), 1);

        // We append an item with Actor3 on replica3
        let item = b"item0";
        let append_op = replica3.append(item.to_vec());
        assert_eq!(replica3.entries_index(), 1);

        // Append operation is broadcasted and applied on replica1
        replica1.apply_data_op(append_op.clone());
        assert_eq!(replica1.entries_index(), 1);

        // And now append op is broadcasted and applied on replica2
        replica2.apply_data_op(append_op.clone());
        // Item should have been queued on replica2 as it's not causally ready
        assert_eq!(replica2.entries_index(), 0);

        // Now grant operation is broadcasted and applied on replica2
        replica2.apply_crdt_pub_policy_op(grant_op)?;
        assert_eq!(replica2.policy_index(), 1);

        // Let's assert append op was now applied on replica2 due
        // to now being causally ready with the new policy
        assert_eq!(replica2.entries_index(), 1);

        Ok(())
    }
}
