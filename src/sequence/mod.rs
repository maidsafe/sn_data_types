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
use crdts::lseq::ident::Identifier;
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

macro_rules! check_perm {
    ($policy: ident, $requester: ident, $action: ident) => {
        match $policy {
            None => {
                if $action == Action::Admin {
                    Ok(())
                } else {
                    Err(Error::AccessDenied)
                }
            }
            Some(policy) => policy.is_action_allowed($requester, $action),
        }
    };
}

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
    pub fn policy_version(&self) -> Option<u64> {
        match self {
            Data::Public(data) => data.policy_index(),
            Data::Private(data) => data.policy_index(),
        }
    }

    /// Gets a list of items which are within the given indices.
    pub fn in_range(&self, start: Index, end: Index) -> Result<Option<Entries>> {
        self.check_self_permission(Action::Read)?;

        Ok(match self {
            Data::Public(data) => data.in_range(start, end),
            Data::Private(data) => data.in_range(start, end),
        })
    }

    /// Returns a value at 'index', if present.
    pub fn get(&self, index: Index) -> Result<Option<&Vec<u8>>> {
        self.check_self_permission(Action::Read)?;

        Ok(match self {
            Data::Public(data) => data.get(index),
            Data::Private(data) => data.get(index),
        })
    }

    /// Returns the last entry, if present.
    pub fn last_entry(&self) -> Result<Option<&Entry>> {
        self.check_self_permission(Action::Read)?;

        Ok(match self {
            Data::Public(data) => data.last_entry(),
            Data::Private(data) => data.last_entry(),
        })
    }

    /// Appends new entry.
    pub fn append(&mut self, entry: Entry) -> Result<DataWriteOp<Entry>> {
        self.check_self_permission(Action::Append)?;

        match self {
            Data::Public(data) => data.append(entry),
            Data::Private(data) => data.append(entry),
        }
    }

    /// Apply a data CRDT operation.
    pub fn apply_data_op(&mut self, op: DataWriteOp<Entry>) -> Result<()> {
        self.check_permission(Action::Append, op.crdt_op.dot().actor, Some(&op.ctx))?;

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
        self.check_self_permission(Action::Admin)?;

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
        self.check_self_permission(Action::Admin)?;

        match self {
            Data::Private(data) => data.set_policy(PrivatePolicy { owner, permissions }),
            Data::Public(_) => Err(Error::InvalidOperation),
        }
    }

    /// Apply Public Policy CRDT operation.
    pub fn apply_public_policy_op(&mut self, op: PolicyWriteOp<PublicPolicy>) -> Result<()> {
        // TODO: review if this permissions check is too laxed
        match op.ctx {
            Some((ref policy_id, _)) => {
                self.check_permission(Action::Admin, op.crdt_op.dot().actor, Some(policy_id))?
            }
            None => self.check_permission(Action::Admin, op.crdt_op.dot().actor, None)?,
        }

        match (self, &op.crdt_op) {
            (Data::Public(data), Op::Insert { .. }) => data.apply_policy_op(op),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Apply Private Policy CRDT operation.
    pub fn apply_private_policy_op(&mut self, op: PolicyWriteOp<PrivatePolicy>) -> Result<()> {
        // TODO: review if this permissions check is too laxed
        match op.ctx {
            Some((ref policy_id, _)) => {
                self.check_permission(Action::Admin, op.crdt_op.dot().actor, Some(policy_id))?
            }
            None => self.check_permission(Action::Admin, op.crdt_op.dot().actor, None)?,
        }

        match self {
            Data::Private(data) => data.apply_policy_op(op),
            _ => Err(Error::InvalidOperation),
        }
    }

    /// Returns user permissions, if applicable.
    pub fn permissions(&self, user: User, version: impl Into<Index>) -> Result<Permissions> {
        let user_perm = match self {
            Data::Public(data) => data
                .policy_at(version)
                .ok_or(Error::NoSuchEntry)?
                .permissions(user)
                .ok_or(Error::NoSuchEntry)?,
            Data::Private(data) => data
                .policy_at(version)
                .ok_or(Error::NoSuchEntry)?
                .permissions(user)
                .ok_or(Error::NoSuchEntry)?,
        };

        Ok(user_perm)
    }

    /// Returns public policy, if applicable.
    pub fn public_policy(&self, version: impl Into<Index>) -> Result<&PublicPolicy> {
        let perms = match self {
            Data::Public(data) => data.policy_at(version),
            Data::Private(_) => return Err(Error::InvalidOperation),
        };
        perms.ok_or(Error::NoSuchEntry)
    }

    /// Returns private policy, if applicable.
    pub fn private_policy(&self, version: impl Into<Index>) -> Result<&PrivatePolicy> {
        let perms = match self {
            Data::Private(data) => data.policy_at(version),
            Data::Public(_) => return Err(Error::InvalidOperation),
        };
        perms.ok_or(Error::NoSuchEntry)
    }

    /// Private helper to check permissions for given `action`
    /// for the given requester's public key.
    ///
    /// Returns:
    /// `Ok(())` if the permissions are valid,
    /// `Err::InvalidOwners` if the last owner is invalid,
    /// `Err::AccessDenied` if the action is not allowed.
    fn check_permission(
        &self,
        action: Action,
        requester: PublicKey,
        policy_id: Option<&Identifier<ActorType>>,
    ) -> Result<()> {
        macro_rules! get_policy {
            ($policy_id: ident, $data: ident) => {
                match $policy_id {
                    Some(id) => match $data.policy_by_id(id) {
                        Some(policy) => Ok(Some(policy)),
                        None => Err(Error::OpNotCausallyReady),
                    },
                    None => Ok($data.policy()),
                }
            };
        }

        match self {
            Data::Public(data) => {
                let policy = get_policy!(policy_id, data)?;
                check_perm!(policy, requester, action)
            }
            Data::Private(data) => {
                let policy = get_policy!(policy_id, data)?;
                check_perm!(policy, requester, action)
            }
        }
    }

    fn check_self_permission(&self, action: Action) -> Result<()> {
        match self {
            Data::Public(data) => {
                let policy = data.policy();
                let actor = data.actor;
                check_perm!(policy, actor, action)
            }
            Data::Private(data) => {
                let policy = data.policy();
                let actor = data.actor;
                check_perm!(policy, actor, action)
            }
        }
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
        let actor = generate_public_key();
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
        let actor = generate_public_key();
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
        let actor = generate_public_key();
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
        let first_entry = replica1.get(index_0)?;
        assert_eq!(first_entry, Some(&entry1));
        assert_eq!(first_entry, replica2.get(index_0)?);

        let index_1 = SequenceIndex::FromStart(1);
        let second_entry = replica1.get(index_1)?;
        assert_eq!(second_entry, Some(&entry2));
        assert_eq!(second_entry, replica2.get(index_1)?);

        let last_entry = replica1.last_entry()?;
        assert_eq!(last_entry, Some(&entry2));
        assert_eq!(last_entry, replica2.last_entry()?);

        Ok(())
    }

    #[test]
    fn sequence_public_set_policy_and_apply() -> Result<()> {
        let actor = generate_public_key();
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

        assert_eq!(replica1.policy_version(), Some(1));
        assert_eq!(replica2.policy_version(), Some(1));

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
        let actor1 = generate_public_key();
        let actor2 = generate_public_key();
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

        assert_eq!(replica1.policy_version(), Some(1));
        assert_eq!(replica2.policy_version(), Some(1));

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
    fn sequence_private_set_policy_and_get_read_fails_when_no_perms_for_actor() -> Result<()> {
        let actor1 = generate_public_key();
        let actor2 = generate_public_key();
        let sequence_name = XorName::random();
        let sequence_tag = 43_000;
        let mut replica1 = Sequence::new_private(actor1, sequence_name, sequence_tag);
        let mut replica2 = Sequence::new_private(actor2, sequence_name, sequence_tag);

        let mut perms1 = BTreeMap::default();
        let user_perms1 = SequencePrivatePermissions::new(true, false, true);
        let _ = perms1.insert(actor1, user_perms1);

        let mut perms2 = BTreeMap::default();
        let user_perms2 = SequencePrivatePermissions::new(false, false, false);
        let _ = perms2.insert(actor2, user_perms2);

        let op1 = replica1.set_private_policy(actor2, perms1.clone())?;
        let op2 = replica1.set_private_policy(actor1, perms2.clone())?;

        // let's apply op perms...
        replica2.apply_private_policy_op(op1)?;
        replica2.apply_private_policy_op(op2)?;

        assert_eq!(replica1.policy_version(), Some(1));
        assert_eq!(replica2.policy_version(), Some(1));

        // And let's append to both replicas with one first item
        let item1 = b"item1";
        let append_op1 = replica1.append(item1.to_vec())?;
        replica2.apply_data_op(append_op1)?;

        // lets check replica1 can read that, and replica2 not...
        let _ = match replica1.get(SequenceIndex::FromStart(0))? {
            Some(data) => assert_eq!(data, b"item1"),
            None => {
                return Err(Error::Unexpected(
                    "replica one should be able to read item1 here".to_string(),
                ))
            }
        };

        match replica2.get(SequenceIndex::FromStart(0)) {
            Ok(_) => Err(Error::Unexpected("Should not be able to read".to_string())),
            Err(_) => Ok(()),
        }?;

        Ok(())
    }

    #[test]
    fn sequence_private_set_policy_and_last_entry_read_fails_when_no_perms_for_actor() -> Result<()>
    {
        let actor1 = generate_public_key();
        let actor2 = generate_public_key();
        let sequence_name = XorName::random();
        let sequence_tag = 43_000;
        let mut replica1 = Sequence::new_private(actor1, sequence_name, sequence_tag);
        let mut replica2 = Sequence::new_private(actor2, sequence_name, sequence_tag);

        let mut perms1 = BTreeMap::default();
        let user_perms1 = SequencePrivatePermissions::new(true, false, true);
        let _ = perms1.insert(actor1, user_perms1);

        let mut perms2 = BTreeMap::default();
        let user_perms2 = SequencePrivatePermissions::new(false, false, false);
        let _ = perms2.insert(actor2, user_perms2);

        let op1 = replica1.set_private_policy(actor2, perms1.clone())?;
        let op2 = replica1.set_private_policy(actor1, perms2.clone())?;

        // let's apply op perms...
        replica2.apply_private_policy_op(op1)?;
        replica2.apply_private_policy_op(op2)?;

        assert_eq!(replica1.policy_version(), Some(1));
        assert_eq!(replica2.policy_version(), Some(1));

        // And let's append to both replicas with one first item
        let item1 = b"item1";
        let append_op1 = replica1.append(item1.to_vec())?;
        replica2.apply_data_op(append_op1)?;

        // lets check replica1 can read that, and replica2 not...
        let _ = match replica1.last_entry()? {
            Some(data) => assert_eq!(data, b"item1"),
            None => {
                return Err(Error::Unexpected(
                    "replica one should be able to read item1 here".to_string(),
                ))
            }
        };

        match replica2.last_entry() {
            Ok(_) => Err(Error::Unexpected("Should not be able to read".to_string())),
            Err(_) => Ok(()),
        }?;

        Ok(())
    }

    #[test]
    fn sequence_private_set_policy_and_range_read_fails_when_no_perms_for_actor() -> Result<()> {
        let actor1 = generate_public_key();
        let actor2 = generate_public_key();
        let sequence_name = XorName::random();
        let sequence_tag = 43_000;
        let mut replica1 = Sequence::new_private(actor1, sequence_name, sequence_tag);
        let mut replica2 = Sequence::new_private(actor2, sequence_name, sequence_tag);

        let mut perms1 = BTreeMap::default();
        let user_perms1 = SequencePrivatePermissions::new(true, false, true);
        let _ = perms1.insert(actor1, user_perms1);

        let mut perms2 = BTreeMap::default();
        let user_perms2 = SequencePrivatePermissions::new(false, false, false);
        let _ = perms2.insert(actor2, user_perms2);

        let op1 = replica1.set_private_policy(actor2, perms1.clone())?;
        let op2 = replica1.set_private_policy(actor1, perms2.clone())?;

        // let's apply op perms...
        replica2.apply_private_policy_op(op1)?;
        replica2.apply_private_policy_op(op2)?;

        assert_eq!(replica1.policy_version(), Some(1));
        assert_eq!(replica2.policy_version(), Some(1));

        // And let's append to both replicas with one first item
        let item1 = b"item1";
        let append_op1 = replica1.append(item1.to_vec())?;
        replica2.apply_data_op(append_op1)?;

        // lets check replica1 can read that, and replica2 not...
        let _ = match replica1.in_range(SequenceIndex::FromStart(0), SequenceIndex::FromStart(1))? {
            Some(data) => assert_eq!(data[0], b"item1"),
            None => {
                return Err(Error::Unexpected(
                    "replica one should be able to read item1 here".to_string(),
                ))
            }
        };

        match replica2.in_range(SequenceIndex::FromStart(0), SequenceIndex::FromStart(1)) {
            Ok(_) => Err(Error::Unexpected("Should not be able to read".to_string())),
            Err(_) => Ok(()),
        }?;

        Ok(())
    }

    #[test]
    fn sequence_private_set_policy_and_read_possible_after_update() -> Result<()> {
        let actor1 = generate_public_key();
        let actor2 = generate_public_key();
        let sequence_name = XorName::random();
        let sequence_tag = 43_000;
        let mut replica1 = Sequence::new_private(actor1, sequence_name, sequence_tag);
        let mut replica2 = Sequence::new_private(actor2, sequence_name, sequence_tag);

        let mut perms1 = BTreeMap::default();
        let user_perms1 = SequencePrivatePermissions::new(true, false, true);
        let _ = perms1.insert(actor1, user_perms1);

        let mut perms2 = BTreeMap::default();
        let user_perms2 = SequencePrivatePermissions::new(false, false, false);
        let _ = perms2.insert(actor2, user_perms2);

        let op1 = replica1.set_private_policy(actor2, perms1.clone())?;
        let op2 = replica1.set_private_policy(actor1, perms2.clone())?;

        // let's apply op perms...
        replica2.apply_private_policy_op(op1)?;
        replica2.apply_private_policy_op(op2)?;

        assert_eq!(replica1.policy_version(), Some(1));
        assert_eq!(replica2.policy_version(), Some(1));

        // And let's append to both replicas with one first item
        let item1 = b"item1";
        let append_op1 = replica1.append(item1.to_vec())?;
        replica2.apply_data_op(append_op1)?;

        // lets check replica1 can read that, and replica2 not...
        let _ = match replica1.get(SequenceIndex::FromStart(0))? {
            Some(data) => assert_eq!(data, b"item1"),
            None => {
                return Err(Error::Unexpected(
                    "replica one should be able to read item1 here".to_string(),
                ))
            }
        };

        match replica2.get(SequenceIndex::FromStart(0)) {
            Ok(_) => Err(Error::Unexpected("Should not be able to read".to_string())),
            Err(_) => Ok(()),
        }?;

        // set readable for replica 2 once more
        let mut perms3 = BTreeMap::default();
        let user_perms3 = SequencePrivatePermissions::new(true, false, false);
        let _ = perms3.insert(actor2, user_perms3);

        let updated_perms_op = replica1.set_private_policy(actor1, perms3.clone())?;

        // let's apply op perms...
        replica2.apply_private_policy_op(updated_perms_op)?;

        let _ = replica1.get(SequenceIndex::FromStart(0))?;
        match replica2.get(SequenceIndex::FromStart(0)) {
            Err(_) => Err(Error::Unexpected("Should be able to read now".to_string())),
            Ok(_) => Ok(()),
        }?;

        // finally check the policy ahs been updated
        assert_eq!(replica1.policy_version(), Some(2));
        assert_eq!(replica2.policy_version(), Some(2));

        Ok(())
    }

    #[test]
    fn sequence_concurrent_policy_and_data_ops() -> Result<()> {
        let actor1 = generate_public_key();
        let actor2 = generate_public_key();
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

        // And let's append to both replicas with one first item
        let item1 = b"item1";
        let append_op1 = replica1.append(item1.to_vec())?;
        replica2.apply_data_op(append_op1)?;

        // Let's assert initial state on both replicas
        assert_eq!(replica1.len(), 1);
        assert_eq!(replica1.policy_version(), Some(0));
        assert_eq!(replica2.len(), 1);
        assert_eq!(replica2.policy_version(), Some(0));

        // We revoke authorisation for Actor2 locally on replica1
        let revoke_op = replica1.set_public_policy(actor1, BTreeMap::default())?;
        // New Policy should have been set on replica1
        assert_eq!(replica1.policy_version(), Some(1));

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
        assert_eq!(replica2.policy_version(), Some(1));
        assert_eq!(replica2.len(), 1);

        // Let's assert that append_op2 created a branch of data on both replicas
        // due to new policy having been applied concurrently, thus only first
        // item shall be returned from main branch of data
        verify_data_convergence(&[&replica1, &replica2], 1)?;

        Ok(())
    }

    #[test]
    fn sequence_causality_between_data_and_policy_ops() -> Result<()> {
        let actor1 = generate_public_key();
        let actor2 = generate_public_key();
        let actor3 = generate_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_001u64;

        // Instantiate the same Sequence on three replicas with three diff actors
        let mut replica1 = Sequence::new_public(actor1, sdata_name, sdata_tag);
        let mut replica2 = Sequence::new_public(actor2, sdata_name, sdata_tag);
        let mut replica3 = Sequence::new_public(actor3, sdata_name, sdata_tag);

        // Set Actor1 as the owner in all replicas, with Append perms for Actor3
        let mut perms = BTreeMap::default();
        let user_perms =
            SequencePublicPermissions::new(/*append=*/ true, /*admin=*/ false);
        let _ = perms.insert(SequenceUser::Key(actor3), user_perms);
        let owner_op = replica1.set_public_policy(actor1, perms)?;
        replica2.apply_public_policy_op(owner_op.clone())?;
        replica3.apply_public_policy_op(owner_op)?;

        // Grant authorisation for Append and Admin to Actor3 in replica1,
        // and apply it to replica3 too
        let mut perms = BTreeMap::default();
        let user_perms =
            SequencePublicPermissions::new(/*append=*/ true, /*admin=*/ true);
        let _ = perms.insert(SequenceUser::Key(actor3), user_perms);
        let grant_op = replica1.set_public_policy(actor1, perms)?;
        replica3.apply_public_policy_op(grant_op.clone())?;

        // Let's assert the state on three replicas
        assert_eq!(replica1.len(), 0);
        assert_eq!(replica1.policy_version(), Some(1));
        assert_eq!(replica2.len(), 0);
        assert_eq!(replica2.policy_version(), Some(0));
        assert_eq!(replica3.len(), 0);
        assert_eq!(replica3.policy_version(), Some(1));

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
        assert_eq!(replica2.policy_version(), Some(1));

        // Retrying to apply append op to replica2 should be successful, due
        // to now being causally ready with the new policy
        replica2.apply_data_op(append_op)?;
        verify_data_convergence(&[&replica1, &replica2, &replica3], 1)?;

        Ok(())
    }

    #[test]
    fn sequence_concurrent_policy_ops() -> Result<()> {
        let actor1 = generate_public_key();
        let actor2 = generate_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_001u64;

        // Instantiate the same Sequence on two replicas with two diff actors
        let mut replica1 = Sequence::new_public(actor1, sdata_name, sdata_tag);
        let mut replica2 = Sequence::new_public(actor2, sdata_name, sdata_tag);

        // Set Actor1 as the owner and Actor2 with Append and Admin perms in all replicas
        let mut perms = BTreeMap::default();
        let user_perms =
            SequencePublicPermissions::new(/*append=*/ true, /*admin=*/ true);
        let _ = perms.insert(SequenceUser::Key(actor2), user_perms);
        let owner_op = replica1.set_public_policy(actor1, perms.clone())?;
        replica2.apply_public_policy_op(owner_op)?;

        // Append item on replica1, and apply it to replica2
        let item0 = b"item0".to_vec();
        let append_op = replica1.append(item0)?;
        replica2.apply_data_op(append_op)?;

        // Let's assert the state on both replicas
        assert_eq!(replica1.len(), 1);
        assert_eq!(replica1.policy_version(), Some(0));
        assert_eq!(replica2.len(), 1);
        assert_eq!(replica2.policy_version(), Some(0));

        // Concurrently set new policy (new random owner) with Append and Admin perms
        // for both actors on both replicas
        let _ = perms.insert(SequenceUser::Key(actor1), user_perms);
        let owner_op_1 = replica1.set_public_policy(generate_public_key(), perms.clone())?;
        let owner_op_2 = replica2.set_public_policy(generate_public_key(), perms)?;
        // ...and concurrently append a new item on top of their own respective new policies
        let item1_r1 = b"item1_replica1".to_vec();
        let item1_r2 = b"item1_replica2".to_vec();
        let append_op1 = replica1.append(item1_r1)?;
        let append_op2 = replica2.append(item1_r2)?;

        assert_eq!(replica1.len(), 2);
        assert_eq!(replica2.len(), 2);

        // Let's now apply the policy op to the other replica
        replica1.apply_public_policy_op(owner_op_2)?;
        replica2.apply_public_policy_op(owner_op_1)?;

        assert_eq!(replica1.policy_version(), Some(2));
        assert_eq!(replica2.policy_version(), Some(2));

        // Let's now apply the append ops on the other replica
        replica1.apply_data_op(append_op2)?;
        replica2.apply_data_op(append_op1)?;

        // Let's assert the state on all replicas to assure convergence
        // One of the items appended concurrently should not belong to
        // the master branch of the data thus we should see only 2 items
        verify_data_convergence(&[&replica1, &replica2], 2)?;

        Ok(())
    }

    #[test]
    fn sequence_old_data_op() -> Result<()> {
        let actor1 = generate_public_key();
        let actor2 = generate_public_key();
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

        assert_eq!(replica1.policy_version(), Some(1));
        assert_eq!(replica2.policy_version(), Some(1));

        verify_data_convergence(&[&replica1, &replica2], 1)?;

        Ok(())
    }

    #[test]
    fn sequence_old_policy_op() -> Result<()> {
        // Assuming the following scenario:
        // - replica1 is the owner of the Seq as per first policy (policy1),
        // - replica2 is then owner of the Seq as per second/new policy (policy2)
        // Then replica1 sends a policy op (note it's not the owner anymore)
        // which was generated before applying the policy2 op, thus it can still be applied
        // but as an old policy between policy1 and policy2 in the policies history.
        // ??? TODO: is this the correct/expected behavior???

        let actor1 = generate_public_key();
        let actor2 = generate_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_001u64;

        // Instantiate the same Sequence on two replicas with two diff actors
        let mut replica1 = Sequence::new_public(actor1, sdata_name, sdata_tag);
        let mut replica2 = Sequence::new_public(actor2, sdata_name, sdata_tag);

        // Set Actor1 as the owner in both replicas (policy1)
        let mut perms = BTreeMap::default();
        let user_perms =
            SequencePublicPermissions::new(/*append=*/ true, /*admin=*/ true);
        let _ = perms.insert(SequenceUser::Key(actor2), user_perms);
        let owner_op = replica1.set_public_policy(actor1, perms)?;
        replica2.apply_public_policy_op(owner_op)?;

        // Let's create a second policy op on replica1, but don't apply it to replica2 yet
        let perms = BTreeMap::default();
        let actor3 = generate_public_key();
        let old_owner_op = replica1.set_public_policy(actor3, perms.clone())?;

        // Set Actor2 as the new owner in replica2 (policy2)
        let owner_op = replica2.set_public_policy(actor2, perms.clone())?;

        // Now apply the old policy op to replica2, which should be applied as
        // an old policy even if the current/latest policy doesn't allow actor1 to change policy
        replica2.apply_public_policy_op(old_owner_op)?;

        // and finally apply the latest owner op to replica1
        replica1.apply_public_policy_op(owner_op)?;

        // Let's assert the state on both replicas
        assert_eq!(replica1.policy_version(), Some(2));
        assert_eq!(replica2.policy_version(), Some(2));

        // Let's assert the owners set in policy1 and policy2
        // are actor1 and actor2 respectivelly
        let policy1 = replica1.public_policy(0)?;
        assert_eq!(policy1.owner, actor1);
        assert_eq!(policy1.owner, replica2.public_policy(0)?.owner);

        let policy2 = replica1.public_policy(1)?;
        if policy2.owner == actor3 {
            assert_eq!(policy2.owner, replica2.public_policy(1)?.owner);
            let policy3 = replica1.public_policy(2)?;
            assert_eq!(policy3.owner, actor2);
            assert_eq!(policy3.owner, replica2.public_policy(2)?.owner);
        } else {
            assert_eq!(policy2.owner, actor2);
            assert_eq!(policy2.owner, replica2.public_policy(1)?.owner);

            let policy3 = replica1.public_policy(2)?;
            assert_eq!(policy3.owner, actor3);
            assert_eq!(policy3.owner, replica2.public_policy(2)?.owner);
        }

        Ok(())
    }

    #[test]
    fn sequence_falsified_policy_op() -> Result<()> {
        // TODO: review if this test is correct, i.e. if should fail
        // even if the policy op is not falsified??

        // Assuming the following scenario:
        // - replica1 is the owner of the Seq as per first policy (policy1),
        // - replica2 is then owner of the Seq as per second/new policy (policy2)
        // Then replica1 tries to cheat by sending a policy op (note it
        // is not the owner anymore, thus shouldn't be allowed) by setting
        // the correct context/dependency on policy2, but setting the identifier
        // of the policy to be appended after policy2

        let actor1 = generate_public_key();
        let actor2 = generate_public_key();
        let sdata_name: XorName = rand::random();
        let sdata_tag = 43_001u64;

        // Instantiate the same Sequence on two replicas with two diff actors
        let mut replica1 = Sequence::new_public(actor1, sdata_name, sdata_tag);
        let mut replica2 = Sequence::new_public(actor2, sdata_name, sdata_tag);

        // Set Actor1 as the owner in both replicas (policy1)
        let perms = BTreeMap::default();
        let owner_op = replica1.set_public_policy(actor1, perms.clone())?;
        replica2.apply_public_policy_op(owner_op)?;

        // Let's create a clone of replica1 we'll use later on to falsify a policy op
        let mut temp_replica = replica1.clone();

        // Set Actor2 as the new owner in both replicas (policy2)
        let owner_op = replica1.set_public_policy(actor2, perms.clone())?;
        replica2.apply_public_policy_op(owner_op)?;

        // Let's assert the state on both replicas
        assert_eq!(replica1.policy_version(), Some(1));
        assert_eq!(replica2.policy_version(), Some(1));

        // Now replica1 shouldn't be allowed to set a new policy since
        // it's not the owner anymore, thus we use the cloned replica
        // we created above (where replica1 is still the owner)
        // in order to falsify a new policy operation
        let mut owner_op = temp_replica.set_public_policy(actor1, perms)?;

        // Let's falsify the op by changing the policy CRDT identifier to be the last
        use crdts::lseq::{ident::IdentGen, Op};
        let upper_ident = IdentGen::new(actor1).upper();
        owner_op.crdt_op = match owner_op.crdt_op {
            Op::Insert { dot, val, .. } => Op::Insert {
                id: upper_ident,
                dot,
                val,
            },
            Op::Delete { remote, dot, .. } => Op::Delete {
                remote,
                id: upper_ident,
                dot,
            },
        };
        check_op_not_allowed_failure(replica2.apply_public_policy_op(owner_op))?;

        // Let's assert the state on both replicas
        assert_eq!(replica1.policy_version(), Some(1));
        assert_eq!(replica2.policy_version(), Some(1));

        // Let's assert the owners set in policy1 and policy2
        // are actor1 and actor2 respectivelly
        let cur_policy = replica2.public_policy(0)?;
        assert_eq!(cur_policy.owner, actor1);
        let cur_policy = replica2.public_policy(1)?;
        assert_eq!(cur_policy.owner, actor2);

        Ok(())
    }

    /*
        TODO: missing tests:
        - test read permissions with all read APIs ??
        - test Append and Admin permissions, with public and private Seq
        - test permissions with BLS shared secrets for shared Seq
        - review to confirm if tests for old and falsified policy ops are correct
        - ...if so, and the test with falsified policy op to pass
    */

    // Helpers for tests

    fn generate_public_key() -> PublicKey {
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

    // check it fails due to not having permissions
    fn check_op_not_allowed_failure(result: Result<()>) -> Result<()> {
        match result {
            Err(Error::AccessDenied) => Ok(()),
            Err(err) => Err(Error::Unexpected(format!(
                "Error returned was the unexpected one for a non-allowed op: {}",
                err
            ))),
            Ok(()) => Err(Error::Unexpected(
                "Data op applied unexpectedly, op not allowed was expected".to_string(),
            )),
        }
    }

    // verify data convergence on a set of replicas and with the expected length
    fn verify_data_convergence(replicas: &[&Sequence], expected_len: u64) -> Result<()> {
        // verify replicas have the expected length
        // also verify replicas failed to get with index beyond reported length
        let index_beyond = SequenceIndex::FromStart(expected_len);
        for r in replicas {
            assert_eq!(r.len(), expected_len);
            assert_eq!(r.get(index_beyond)?, None);
        }

        // now verify that the items are the same in all replicas
        for i in 0..expected_len {
            let index = SequenceIndex::FromStart(i);
            let r0_entry = replicas[0].get(index)?;
            for r in replicas {
                assert_eq!(r0_entry, r.get(index)?);
            }
        }

        Ok(())
    }
}
