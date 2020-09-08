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

use crate::{Error, PublicKey, Result};
pub use metadata::{
    Action, Address, Entries, Entry, Index, Kind, Perm, Permissions, Policy, PrivatePermissions,
    PrivatePolicy, PublicPermissions, PublicPolicy, User,
};
use seq_crdt::{CrdtDataOperation, CrdtPolicyOperation, Op, SequenceCrdt};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
    hash::Hash,
};
use xor_name::XorName;
// Type of data used for the 'Actor' in CRDT vector clocks
type ActorType = PublicKey;

/// Data mutation operation to apply to Sequence.
pub type DataWriteOp<T> = CrdtDataOperation<ActorType, T>;

/// Policy mutation operation to apply to Sequence.
pub type PolicyWriteOp<T> = CrdtPolicyOperation<ActorType, T>;

/// Public Sequence.
pub type PublicSeqData = SequenceCrdt<ActorType, PublicPolicy>;
/// Private Sequence.
pub type PrivateSeqData = SequenceCrdt<ActorType, PrivatePolicy>;

impl Debug for PublicSeqData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PubSequence {:?}", self.address().name())
    }
}

impl Debug for PrivateSeqData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivSequence {:?}", self.address().name())
    }
}

/// Write operation to apply to Sequence.
/// This is used for all kind of CRDT operations made on the Sequence,
/// i.e. not only on the data but also on the permissions and owner info.
// #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
// pub struct WriteOp<T> {
//     /// Address of a Sequence object on the network.
//     pub address: Address,
//     /// The operation to apply.
//     pub crdt_op: Op<T, ActorType>,
// }

/// Object storing a Sequence variant.
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    /// Public Sequence Data.
    Public(PublicSeqData),
    /// Private Sequence Data.
    Private(PrivateSeqData),
}

impl Data {
    /// Constructs a new Public Sequence Data.
    pub fn new_public(actor: ActorType, name: XorName, tag: u64) -> Self {
        Self::Public(PublicSeqData::new(actor, Address::Public { name, tag }))
    }

    /// Constructs a new Private Sequence Data.
    pub fn new_private(actor: ActorType, name: XorName, tag: u64) -> Self {
        Self::Private(PrivateSeqData::new(actor, Address::Private { name, tag }))
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
    pub fn is_private(&self) -> bool {
        self.kind().is_private()
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
                $data
                    .policy(Index::FromEnd(1))
                    .ok_or(Error::AccessDenied)?
                    .is_action_allowed($requester, $action)
            };
        }

        match self {
            Data::Public(data) => check_perm!(data, requester, action),
            Data::Private(data) => check_perm!(data, requester, action),
        }
    }

    /// Returns the length of the sequence.
    pub fn len(&self) -> u64 {
        match self {
            Data::Public(data) => data.len(),
            Data::Private(data) => data.len(),
        }
    }

    /// Returns true if the sequence is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the version of last Policy.
    pub fn policy_version(&self) -> u64 {
        match self {
            Data::Public(data) => data.policy_index(),
            Data::Private(data) => data.policy_index(),
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

    /// Appends new entry.
    pub fn append(&mut self, entry: Entry) -> Result<DataWriteOp<Entry>> {
        match self {
            Data::Public(data) => data.append(entry),
            Data::Private(data) => data.append(entry),
        }
    }

    /// Apply a data CRDT operation.
    pub fn apply_data_op(&mut self, op: DataWriteOp<Entry>) -> Result<()> {
        match self {
            Data::Public(data) => data.apply_data_op(op),
            Data::Private(data) => data.apply_data_op(op),
        }
    }

    /// Sets the new policy for Public Sequence.
    pub fn set_public_policy(
        &mut self,
        owner: PublicKey,
        permissions: BTreeMap<User, PublicPermissions>,
    ) -> Result<PolicyWriteOp<PublicPolicy>> {
        match self {
            Data::Public(data) => data.set_policy(PublicPolicy { owner, permissions }),
            Data::Private(_) => Err(Error::InvalidOperation),
        }
    }

    /// Sets the new policy for Private Sequence.
    pub fn set_private_policy(
        &mut self,
        owner: PublicKey,
        permissions: BTreeMap<PublicKey, PrivatePermissions>,
    ) -> Result<PolicyWriteOp<PrivatePolicy>> {
        match self {
            Data::Private(data) => data.set_policy(PrivatePolicy { owner, permissions }),
            Data::Public(_) => Err(Error::InvalidOperation),
        }
    }

    /// Apply Public Policy CRDT operation.
    pub fn apply_public_policy_op(&mut self, op: PolicyWriteOp<PublicPolicy>) -> Result<()> {
        match (self, &op.crdt_op) {
            (Data::Public(data), Op::Insert { .. }) => data.apply_policy_op(op),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Apply Private Policy CRDT operation.
    pub fn apply_private_policy_op(&mut self, op: PolicyWriteOp<PrivatePolicy>) -> Result<()> {
        match self {
            Data::Private(data) => data.apply_policy_op(op),
            _ => Err(Error::InvalidOperation),
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
    pub fn public_policy(&self, version: impl Into<Index>) -> Result<&PublicPolicy> {
        let perms = match self {
            Data::Public(data) => data.policy(version),
            Data::Private(_) => return Err(Error::InvalidOperation),
        };
        perms.ok_or(Error::NoSuchEntry)
    }

    /// Returns private policy, if applicable.
    pub fn private_policy(&self, version: impl Into<Index>) -> Result<&PrivatePolicy> {
        let perms = match self {
            Data::Private(data) => data.policy(version),
            Data::Public(_) => return Err(Error::InvalidOperation),
        };
        perms.ok_or(Error::NoSuchEntry)
    }
}

impl From<PublicSeqData> for Data {
    fn from(data: PublicSeqData) -> Self {
        Data::Public(data)
    }
}

impl From<PrivateSeqData> for Data {
    fn from(data: PrivateSeqData) -> Self {
        Data::Private(data)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Error, PublicKey, Result, Sequence, SequenceAddress, SequenceIndex, SequenceKind,
        SequencePermissions, SequencePrivatePermissions, SequencePublicPermissions, SequenceUser,
    };
    use std::collections::BTreeMap;
    use threshold_crypto::SecretKey;
    use xor_name::XorName;

    #[test]
    fn sequence_create_public() {
        let actor = gen_public_key();
        let sequence_name = XorName::random();
        let sequence_tag = 43_000;
        let sequence = Sequence::new_public(actor, sequence_name, sequence_tag);
        assert_eq!(sequence.kind(), SequenceKind::Public);
        assert_eq!(*sequence.name(), sequence_name);
        assert_eq!(sequence.tag(), sequence_tag);
        assert!(sequence.is_pub());
        assert!(!sequence.is_private());

        let sequence_address =
            SequenceAddress::from_kind(SequenceKind::Public, sequence_name, sequence_tag);
        assert_eq!(*sequence.address(), sequence_address);
    }

    #[test]
    fn sequence_create_private() {
        let actor = gen_public_key();
        let sequence_name = XorName::random();
        let sequence_tag = 43_000;
        let sequence = Sequence::new_private(actor, sequence_name, sequence_tag);
        assert_eq!(sequence.kind(), SequenceKind::Private);
        assert_eq!(*sequence.name(), sequence_name);
        assert_eq!(sequence.tag(), sequence_tag);
        assert!(!sequence.is_pub());
        assert!(sequence.is_private());

        let sequence_address =
            SequenceAddress::from_kind(SequenceKind::Private, sequence_name, sequence_tag);
        assert_eq!(*sequence.address(), sequence_address);
    }

    #[test]
    fn sequence_append_entry_and_apply() -> Result<()> {
        let actor = gen_public_key();
        let sequence_name = XorName::random();
        let sequence_tag = 43_000;
        let mut replica1 = Sequence::new_public(actor, sequence_name, sequence_tag);
        let mut replica2 = Sequence::new_public(actor, sequence_name, sequence_tag);

        let mut perms1 = BTreeMap::default();
        let user_perms1 = SequencePublicPermissions::new(true, false);
        let _ = perms1.insert(SequenceUser::Anyone, user_perms1);
        let policy_op = replica1.set_public_policy(actor, perms1)?;
        replica2.apply_public_policy_op(policy_op)?;

        let entry1 = b"value0".to_vec();
        let entry2 = b"value1".to_vec();

        let op1 = replica1.append(entry1.clone())?;
        let op2 = replica1.append(entry2.clone())?;

        // we apply the operations in different order, to verify that doesn't affect the result
        replica2.apply_data_op(op2)?;
        replica2.apply_data_op(op1)?;

        assert_eq!(replica1.len(), 2);
        assert_eq!(replica2.len(), 2);

        let index_0 = SequenceIndex::FromStart(0);
        let first_entry = replica1.get(index_0);
        assert_eq!(first_entry, Some(&entry1));
        assert_eq!(first_entry, replica2.get(index_0));

        let index_1 = SequenceIndex::FromStart(1);
        let second_entry = replica1.get(index_1);
        assert_eq!(second_entry, Some(&entry2));
        assert_eq!(second_entry, replica2.get(index_1));

        let last_entry = replica1.last_entry();
        assert_eq!(last_entry, Some(&entry2));
        assert_eq!(last_entry, replica2.last_entry());

        Ok(())
    }

    #[test]
    fn sequence_public_set_policy_and_apply() -> Result<()> {
        let actor = gen_public_key();
        let sequence_name = XorName::random();
        let sequence_tag = 43_000;
        let mut replica1 = Sequence::new_public(actor, sequence_name, sequence_tag);
        let mut replica2 = Sequence::new_public(actor, sequence_name, sequence_tag);

        let mut perms1 = BTreeMap::default();
        let user_perms1 = SequencePublicPermissions::new(true, false);
        let _ = perms1.insert(SequenceUser::Anyone, user_perms1);

        let mut perms2 = BTreeMap::default();
        let user_perms2 = SequencePublicPermissions::new(false, true);
        let _ = perms2.insert(SequenceUser::Key(actor), user_perms2);

        let op1 = replica1.set_public_policy(actor, perms1.clone())?;
        let op2 = replica1.set_public_policy(actor, perms2.clone())?;

        // if we apply the operations in different order it should fail
        // as op2 is not causally ready in replica2, it depends on op1
        check_not_causally_ready_failure(replica2.apply_public_policy_op(op2.clone()))?;

        // let's apply op1 first then
        replica2.apply_public_policy_op(op1)?;
        replica2.apply_public_policy_op(op2)?;

        assert_eq!(replica1.policy_version(), 2);
        assert_eq!(replica2.policy_version(), 2);

        let index_0 = SequenceIndex::FromStart(0);
        let first_entry = replica1.public_policy(index_0)?;
        assert_eq!(first_entry.permissions, perms1);
        assert_eq!(first_entry.owner, actor);
        assert_eq!(first_entry, replica2.public_policy(index_0)?);
        assert_eq!(
            SequencePermissions::Public(user_perms1),
            replica1.permissions(SequenceUser::Anyone, index_0)?
        );

        let index_1 = SequenceIndex::FromStart(1);
        let second_entry = replica1.public_policy(index_1)?;
        assert_eq!(second_entry.permissions, perms2);
        assert_eq!(second_entry.owner, actor);
        assert_eq!(second_entry, replica2.public_policy(index_1)?);
        assert_eq!(
            SequencePermissions::Public(user_perms2),
            replica1.permissions(SequenceUser::Key(actor), index_1)?
        );

        Ok(())
    }

    #[test]
    fn sequence_private_set_policy_and_apply() -> Result<()> {
        let actor1 = gen_public_key();
        let actor2 = gen_public_key();
        let sequence_name = XorName::random();
        let sequence_tag = 43_000;
        let mut replica1 = Sequence::new_private(actor1, sequence_name, sequence_tag);
        let mut replica2 = Sequence::new_private(actor2, sequence_name, sequence_tag);

        let mut perms1 = BTreeMap::default();
        let user_perms1 = SequencePrivatePermissions::new(true, false, true);
        let _ = perms1.insert(actor1, user_perms1);

        let mut perms2 = BTreeMap::default();
        let user_perms2 = SequencePrivatePermissions::new(false, true, false);
        let _ = perms2.insert(actor2, user_perms2);

        let op1 = replica1.set_private_policy(actor2, perms1.clone())?;
        let op2 = replica1.set_private_policy(actor1, perms2.clone())?;

        // if we apply the operations in different order it should fail
        // as op2 is not causally ready in replica2, it depends on op1
        check_not_causally_ready_failure(replica2.apply_private_policy_op(op2.clone()))?;

        // let's apply op1 first then
        replica2.apply_private_policy_op(op1)?;
        replica2.apply_private_policy_op(op2)?;

        assert_eq!(replica1.policy_version(), 2);
        assert_eq!(replica2.policy_version(), 2);

        let index_0 = SequenceIndex::FromStart(0);
        let first_entry = replica1.private_policy(index_0)?;
        assert_eq!(first_entry.permissions, perms1);
        assert_eq!(first_entry.owner, actor2);
        assert_eq!(first_entry, replica2.private_policy(index_0)?);
        assert_eq!(
            SequencePermissions::Private(user_perms1),
            replica1.permissions(SequenceUser::Key(actor1), index_0)?
        );

        let index_1 = SequenceIndex::FromStart(1);
        let second_entry = replica1.private_policy(index_1)?;
        assert_eq!(second_entry.permissions, perms2);
        assert_eq!(second_entry.owner, actor1);
        assert_eq!(second_entry, replica2.private_policy(index_1)?);
        assert_eq!(
            SequencePermissions::Private(user_perms2),
            replica1.permissions(SequenceUser::Key(actor2), index_1)?
        );

        Ok(())
    }

    #[test]
    fn sequence_concurrent_policy_and_data_ops() -> Result<()> {
        let actor1 = gen_public_key();
        let actor2 = gen_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_000u64;

        // Instantiate the same Sequence on two replicas with two diff actors
        let mut replica1 = Sequence::new_public(actor1, sdata_name, sdata_tag);
        let mut replica2 = Sequence::new_public(actor2, sdata_name, sdata_tag);

        // Set Actor1 as the owner in both replicas and
        // grant authorisation for Append to Actor2 in both replicas
        let mut perms = BTreeMap::default();
        let user_perms =
            SequencePublicPermissions::new(/*append=*/ true, /*admin=*/ false);
        let _ = perms.insert(SequenceUser::Key(actor2), user_perms);
        let grant_op = replica1.set_public_policy(actor1, perms)?;
        replica2.apply_public_policy_op(grant_op)?;

        // And let's append both replicas with one first item
        let item1 = b"item1";
        let append_op1 = replica1.append(item1.to_vec())?;
        replica2.apply_data_op(append_op1)?;

        // Let's assert initial state on both replicas
        assert_eq!(replica1.len(), 1);
        assert_eq!(replica1.policy_version(), 1);
        assert_eq!(replica2.len(), 1);
        assert_eq!(replica2.policy_version(), 1);

        // We revoke authorisation for Actor2 locally on replica1
        let revoke_op = replica1.set_public_policy(actor1, BTreeMap::default())?;
        // New Policy should have been set on replica1
        assert_eq!(replica1.policy_version(), 2);

        // Concurrently append an item with Actor2 on replica2
        let item2 = b"item2";
        let append_op2 = replica2.append(item2.to_vec())?;
        // Item should be appended on replica2
        assert_eq!(replica2.len(), 2);

        // Append operation is broadcasted and applied on replica1 using old Policy
        replica1.apply_data_op(append_op2)?;
        assert_eq!(replica1.len(), 1);

        // Now revoke operation is broadcasted and applied on replica2
        replica2.apply_public_policy_op(revoke_op)?;
        assert_eq!(replica2.policy_version(), 2);
        assert_eq!(replica2.len(), 1);

        // Let's assert that append_op2 created a branch of data on both replicas
        // due to new policy having been applied concurrently, thus only first
        // item shall be returned from main branch of data
        verify_data_convergence(&[&replica1, &replica2], 1);

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
        let mut replica1 = Sequence::new_public(actor1, sdata_name, sdata_tag);
        let mut replica2 = Sequence::new_public(actor2, sdata_name, sdata_tag);
        let mut replica3 = Sequence::new_public(actor3, sdata_name, sdata_tag);

        // Set Actor1 as the owner in all replicas, with empty users permissions yet
        let owner_op = replica1.set_public_policy(actor1, BTreeMap::default())?;
        replica2.apply_public_policy_op(owner_op.clone())?;
        replica3.apply_public_policy_op(owner_op)?;

        // Grant authorisation for Append to Actor3 in replica1 and apply to replica3 too
        let mut perms = BTreeMap::default();
        let user_perms =
            SequencePublicPermissions::new(/*append=*/ true, /*admin=*/ false);
        let _ = perms.insert(SequenceUser::Key(actor3), user_perms);
        let grant_op = replica1.set_public_policy(actor1, perms)?;
        replica3.apply_public_policy_op(grant_op.clone())?;

        // Let's assert the state on three replicas
        assert_eq!(replica1.len(), 0);
        assert_eq!(replica1.policy_version(), 2);
        assert_eq!(replica2.len(), 0);
        assert_eq!(replica2.policy_version(), 1);
        assert_eq!(replica3.len(), 0);
        assert_eq!(replica3.policy_version(), 2);

        // We append an item with Actor3 on replica3
        let item = b"item0";
        let append_op = replica3.append(item.to_vec())?;
        assert_eq!(replica3.len(), 1);

        // Append op is broadcasted and applied on replica1
        replica1.apply_data_op(append_op.clone())?;
        assert_eq!(replica1.len(), 1);

        // And now append op is broadcasted and applied on replica2
        // It should be rejected on replica2 as it's not causally ready
        check_not_causally_ready_failure(replica2.apply_data_op(append_op.clone()))?;
        assert_eq!(replica2.len(), 0);

        // So let's apply grant operation to replica2
        replica2.apply_public_policy_op(grant_op)?;
        assert_eq!(replica2.policy_version(), 2);

        // Retrying to apply append op to replica2 should be successful, due
        // to now being causally ready with the new policy
        replica2.apply_data_op(append_op)?;
        verify_data_convergence(&[&replica1, &replica2, &replica3], 1);

        Ok(())
    }

    #[test]
    fn sequence_concurrent_policy_ops() -> Result<()> {
        let actor1 = gen_public_key();
        let actor2 = gen_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_001u64;

        // Instantiate the same Sequence on two replicas with two diff actors
        let mut replica1 = Sequence::new_public(actor1, sdata_name, sdata_tag);
        let mut replica2 = Sequence::new_public(actor2, sdata_name, sdata_tag);

        // Set Actor1 as the owner and Actor2 with append perms in all replicas
        let mut perms = BTreeMap::default();
        let user_perms =
            SequencePublicPermissions::new(/*append=*/ true, /*admin=*/ false);
        let _ = perms.insert(SequenceUser::Key(actor2), user_perms);
        let owner_op = replica1.set_public_policy(actor1, perms.clone())?;
        replica2.apply_public_policy_op(owner_op)?;

        // Append item on replica1, and apply it to replica2
        let item0 = b"item0".to_vec();
        let append_op = replica1.append(item0)?;
        replica2.apply_data_op(append_op)?;

        // Let's assert the state on both replicas
        assert_eq!(replica1.len(), 1);
        assert_eq!(replica1.policy_version(), 1);
        assert_eq!(replica2.len(), 1);
        assert_eq!(replica2.policy_version(), 1);

        // Concurrently set new policy (new owner) on both replicas
        let owner_op_1 = replica1.set_public_policy(actor2, perms.clone())?;
        let owner_op_2 = replica2.set_public_policy(actor2, perms)?;
        // ...and concurrently append a new item on top of their own respective new policies
        let item1_r1 = b"item1_replica1".to_vec();
        let item1_r2 = b"item1_replica2".to_vec();
        let append_op1 = replica1.append(item1_r1)?;
        let append_op2 = replica2.append(item1_r2)?;

        assert_eq!(replica1.len(), 2);
        assert_eq!(replica2.len(), 2);

        // Let's now apply policy the other replica
        replica1.apply_public_policy_op(owner_op_2)?;
        replica2.apply_public_policy_op(owner_op_1)?;

        assert_eq!(replica1.policy_version(), 3);
        assert_eq!(replica2.policy_version(), 3);

        // Let's now apply the append ops on the other replica
        replica1.apply_data_op(append_op2)?;
        replica2.apply_data_op(append_op1)?;

        // Let's assert the state on all replicas to assure convergence
        // One of the items appended concurrently should not belong to
        // the master branch of the data thus we should see only 2 items
        verify_data_convergence(&[&replica1, &replica2], 2);

        Ok(())
    }

    #[test]
    fn sequence_old_data_op() -> Result<()> {
        let actor1 = gen_public_key();
        let actor2 = gen_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_001u64;

        // Instantiate the same Sequence on two replicas with two diff actors
        let mut replica1 = Sequence::new_public(actor1, sdata_name, sdata_tag);
        let mut replica2 = Sequence::new_public(actor2, sdata_name, sdata_tag);

        // Set Actor1 as the owner and Actor2 with append perms in all replicas
        let mut perms = BTreeMap::default();
        let user_perms =
            SequencePublicPermissions::new(/*append=*/ true, /*admin=*/ false);
        let _ = perms.insert(SequenceUser::Key(actor2), user_perms);
        let owner_op = replica1.set_public_policy(actor1, perms)?;
        replica2.apply_public_policy_op(owner_op)?;

        // Append an item on replica1
        let item0 = b"item0".to_vec();
        let append_op = replica1.append(item0)?;

        // A new Policy is set in replica1 and applied to replica2
        let policy_op = replica1.set_public_policy(actor1, BTreeMap::default())?;
        replica2.apply_public_policy_op(policy_op)?;

        // Now the old append op is applied to replica2
        replica2.apply_data_op(append_op)?;

        assert_eq!(replica1.policy_version(), 2);
        assert_eq!(replica2.policy_version(), 2);

        verify_data_convergence(&[&replica1, &replica2], 1);

        Ok(())
    }

    // Helpers for tests

    fn gen_public_key() -> PublicKey {
        PublicKey::Bls(SecretKey::random().public_key())
    }

    // check it fails due to not being causally ready
    fn check_not_causally_ready_failure(result: Result<()>) -> Result<()> {
        match result {
            Err(Error::OpNotCausallyReady) => Ok(()),
            Err(err) => Err(Error::Unexpected(format!(
                "Error returned was the unexpected one: {}",
                err
            ))),
            Ok(()) => Err(Error::Unexpected(
                "Data op applied unexpectedly".to_string(),
            )),
        }
    }

    // verify data convergence on a set of replicas and with the expected length
    fn verify_data_convergence(replicas: &[&Sequence], expected_len: u64) {
        // verify replicas have the expected length
        // also verify replicas failed to get with index beyond reported length
        let index_beyond = SequenceIndex::FromStart(expected_len);
        for r in replicas {
            assert_eq!(r.len(), expected_len);
            assert_eq!(r.get(index_beyond), None);
        }

        // now verify that the items are the same in all replicas
        for i in 0..expected_len {
            let index = SequenceIndex::FromStart(i);
            let r0_entry = replicas[0].get(index);
            for r in replicas {
                assert_eq!(r0_entry, r.get(index));
            }
        }
    }
}
