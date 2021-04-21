// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod metadata;
mod policy;
mod reg_crdt;

use crate::{Error, PublicKey, Result};
pub use metadata::{Action, Address, Entry, Kind};
pub use policy::{
    Permissions, Policy, PrivatePermissions, PrivatePolicy, PublicPermissions, PublicPolicy, User,
};
pub use reg_crdt::EntryHash;
use reg_crdt::{CrdtOperation, RegisterCrdt};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Debug, Formatter},
    hash::Hash,
};
use xor_name::XorName;

/// Register mutation operation to apply to Register.
pub type RegisterOp<T> = CrdtOperation<T>;

impl Debug for RegisterCrdt {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "{} Register {:?}",
            if self.address().is_public() {
                "Public"
            } else {
                "Private"
            },
            self.address().name()
        )
    }
}

/// Object storing the Register
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub struct Register {
    authority: PublicKey,
    crdt: RegisterCrdt,
    policy: Policy,
}

impl Register {
    /// Construct a new Public Register.
    /// The 'authority' is assumed to be the PK which the messages were and will be
    /// signed with.
    /// If a policy is not provided, a default policy will be set where
    /// the 'authority' is the owner along with an empty users permissions set.
    pub fn new_public(
        authority: PublicKey,
        name: XorName,
        tag: u64,
        policy: Option<PublicPolicy>,
    ) -> Self {
        let policy = policy.unwrap_or(PublicPolicy {
            owner: authority,
            permissions: BTreeMap::new(),
        });

        Self {
            authority,
            crdt: RegisterCrdt::new(Address::Public { name, tag }),
            policy: policy.into(),
        }
    }

    /// Construct a new Private Register.
    /// The 'authority' is assumed to be the PK which the messages were and will be
    /// signed with.
    /// If a policy is not provided, a default policy will be set where
    /// the 'authority' is the owner along with an empty users permissions set.
    pub fn new_private(
        authority: PublicKey,
        name: XorName,
        tag: u64,
        policy: Option<PrivatePolicy>,
    ) -> Self {
        let policy = policy.unwrap_or(PrivatePolicy {
            owner: authority,
            permissions: BTreeMap::new(),
        });

        Self {
            authority,
            crdt: RegisterCrdt::new(Address::Private { name, tag }),
            policy: policy.into(),
        }
    }

    /// Return the address.
    pub fn address(&self) -> &Address {
        self.crdt.address()
    }

    /// Return the kind.
    pub fn kind(&self) -> Kind {
        self.address().kind()
    }

    /// Return the name.
    pub fn name(&self) -> &XorName {
        self.address().name()
    }

    /// Return the tag.
    pub fn tag(&self) -> u64 {
        self.address().tag()
    }

    /// Return `true` if public.
    pub fn is_public(&self) -> bool {
        self.kind().is_public()
    }

    /// Return `true` if private.
    pub fn is_private(&self) -> bool {
        self.kind().is_private()
    }

    /// Return the number of items held in the register, optionally
    /// verifying read permissions if a pk is provided
    pub fn size(&self, requester: Option<PublicKey>) -> Result<u64> {
        self.check_permission(Action::Read, requester)?;

        Ok(self.crdt.size())
    }

    /// Return true if the register is empty.
    pub fn is_empty(&self, requester: Option<PublicKey>) -> Result<bool> {
        Ok(self.size(requester)? == 0)
    }

    /// Return a value corresponding to the provided 'hash', if present.
    pub fn get(&self, hash: EntryHash, requester: Option<PublicKey>) -> Result<Option<&Entry>> {
        self.check_permission(Action::Read, requester)?;

        Ok(self.crdt.get(hash))
    }

    /// Read the last entry, or entries when there are branches, if the register is not empty.
    pub fn read(&self, requester: Option<PublicKey>) -> Result<BTreeSet<(EntryHash, Entry)>> {
        self.check_permission(Action::Read, requester)?;

        Ok(self.crdt.read())
    }

    /// Write an entry to the Register, returning the generated unsigned
    /// CRDT operation so the caller can sign and broadcast it to other replicas,
    /// along with the hash of the entry just written.
    pub fn write(
        &mut self,
        entry: Entry,
        parents: BTreeSet<EntryHash>,
    ) -> Result<(EntryHash, RegisterOp<Entry>)> {
        self.check_permission(Action::Write, None)?;

        self.crdt.write(entry, parents, self.authority)
    }

    /// Apply a signed data CRDT operation.
    pub fn apply_op(&mut self, op: RegisterOp<Entry>) -> Result<()> {
        self.check_permission(Action::Write, Some(op.source))?;

        self.crdt.apply_op(op)
    }

    /// Return user permissions, if applicable.
    pub fn permissions(&self, user: User, requester: Option<PublicKey>) -> Result<Permissions> {
        self.check_permission(Action::Read, requester)?;

        self.policy.permissions(user).ok_or(Error::NoSuchEntry)
    }

    /// Return the policy.
    pub fn policy(&self, requester: Option<PublicKey>) -> Result<&Policy> {
        self.check_permission(Action::Read, requester)?;

        Ok(&self.policy)
    }

    /// Helper to check permissions for given `action`
    /// for the given requester's public key.
    ///
    /// Returns:
    /// `Ok(())` if the permissions are valid,
    /// `Err::AccessDenied` if the action is not allowed.
    pub fn check_permission(&self, action: Action, requester: Option<PublicKey>) -> Result<()> {
        let requester = requester.unwrap_or(self.authority);
        self.policy.is_action_allowed(requester, action)
    }

    /// Return the owner of the data.
    pub fn owner(&self) -> PublicKey {
        *self.policy.owner()
    }

    /// Return the PK which the messages are expected to be signed with by this replica.
    pub fn replica_authority(&self) -> PublicKey {
        self.authority
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        register::{
            Address, Entry, EntryHash, Kind, Permissions, PrivatePermissions, PrivatePolicy,
            PublicPermissions, PublicPolicy, Register, RegisterOp, User,
        },
        utils, Error, Keypair, Result,
    };
    use anyhow::anyhow;
    use proptest::prelude::*;
    use rand::{rngs::OsRng, seq::SliceRandom, thread_rng};
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    };
    use xor_name::XorName;

    #[test]
    fn register_create_public() {
        let register_name = XorName::random();
        let register_tag = 43_000;
        let (authority_keypair, register) =
            &gen_pub_reg_replicas(None, register_name, register_tag, None, 1)[0];

        assert_eq!(register.kind(), Kind::Public);
        assert_eq!(*register.name(), register_name);
        assert_eq!(register.tag(), register_tag);
        assert!(register.is_public());
        assert!(!register.is_private());

        let authority_pk = authority_keypair.public_key();
        assert_eq!(register.owner(), authority_pk);
        assert_eq!(register.replica_authority(), authority_pk);

        let register_address = Address::from_kind(Kind::Public, register_name, register_tag);
        assert_eq!(*register.address(), register_address);
    }

    #[test]
    fn register_create_private() {
        let register_name = XorName::random();
        let register_tag = 43_000;
        let (authority_keypair, register) =
            &gen_priv_reg_replicas(None, register_name, register_tag, None, 1)[0];

        assert_eq!(register.kind(), Kind::Private);
        assert_eq!(*register.name(), register_name);
        assert_eq!(register.tag(), register_tag);
        assert!(!register.is_public());
        assert!(register.is_private());

        let authority_pk = authority_keypair.public_key();
        assert_eq!(register.owner(), authority_pk);
        assert_eq!(register.replica_authority(), authority_pk);

        let register_address = Address::from_kind(Kind::Private, register_name, register_tag);
        assert_eq!(*register.address(), register_address);
    }

    #[test]
    fn register_concurrent_write_ops() -> Result<()> {
        let authority_keypair1 = Keypair::new_ed25519(&mut OsRng);
        let authority1 = authority_keypair1.public_key();
        let authority_keypair2 = Keypair::new_ed25519(&mut OsRng);
        let authority2 = authority_keypair2.public_key();

        let register_name: XorName = rand::random();
        let register_tag = 43_000u64;

        // We'll have 'authority1' as the owner in both replicas and
        // grant permissions for Write to 'authority2' in both replicas too
        let mut perms = BTreeMap::default();
        let user_perms = PublicPermissions::new(true);
        let _ = perms.insert(User::Key(authority2), user_perms);

        // Instantiate the same Register on two replicas with the two diff authorities
        let mut replica1 = Register::new_public(
            authority1,
            register_name,
            register_tag,
            Some(PublicPolicy {
                owner: authority1,
                permissions: perms.clone(),
            }),
        );
        let mut replica2 = Register::new_public(
            authority2,
            register_name,
            register_tag,
            Some(PublicPolicy {
                owner: authority1,
                permissions: perms,
            }),
        );

        // And let's write an item to replica1 with autority1
        let item1 = b"item1";
        let (_, op1) = replica1.write(item1.to_vec(), BTreeSet::new())?;
        let signed_write_op1 = sign_register_op(op1, &authority_keypair1)?;

        // Let's assert current state on both replicas
        assert_eq!(replica1.size(None)?, 1);
        assert_eq!(replica2.size(None)?, 0);

        // Concurrently write another item with authority2 on replica2
        let item2 = b"item2";
        let (_, op2) = replica2.write(item2.to_vec(), BTreeSet::new())?;
        let signed_write_op2 = sign_register_op(op2, &authority_keypair2)?;

        // Item should be writeed on replica2
        assert_eq!(replica2.size(None)?, 1);

        // Write operations are now broadcasted and applied to both replicas
        replica1.apply_op(signed_write_op2)?;
        replica2.apply_op(signed_write_op1)?;

        // Let's assert data convergence on both replicas
        verify_data_convergence(vec![replica1, replica2], 2)?;

        Ok(())
    }

    #[test]
    fn register_get_by_hash() -> anyhow::Result<()> {
        let (_, register) = &mut create_public_reg_replicas(1)[0];

        let entry1 = b"value0".to_vec();
        let entry2 = b"value1".to_vec();
        let entry3 = b"value2".to_vec();

        let (entry1_hash, _) = register.write(entry1.to_vec(), BTreeSet::new())?;

        // this creates a fork since entry1 is not set as parent of entry2
        let (entry2_hash, _) = register.write(entry2.clone(), BTreeSet::new())?;

        // we'll write entry2 but having the entry1 and entry2 as parents,
        // i.e. solving the fork created by them
        let parents = vec![entry1_hash, entry2_hash].into_iter().collect();

        let (entry3_hash, _) = register.write(entry3.clone(), parents)?;

        assert_eq!(register.size(None)?, 3);

        let first_entry = register.get(entry1_hash, None)?;
        assert_eq!(first_entry, Some(&entry1));

        let second_entry = register.get(entry2_hash, None)?;
        assert_eq!(second_entry, Some(&entry2));

        let third_entry = register.get(entry3_hash, None)?;
        assert_eq!(third_entry, Some(&entry3));

        let non_existing_hash = EntryHash::default();
        let entry_not_found = register.get(non_existing_hash, None)?;
        assert!(entry_not_found.is_none());

        Ok(())
    }

    #[test]
    fn register_query_public_policy() -> anyhow::Result<()> {
        let register_name = XorName::random();
        let register_tag = 43_666;

        // one replica will allow write ops to anyone
        let authority_keypair1 = Keypair::new_ed25519(&mut OsRng);
        let owner1 = authority_keypair1.public_key();
        let mut perms1 = BTreeMap::default();
        let _ = perms1.insert(User::Anyone, PublicPermissions::new(true));
        let replica1 = create_public_reg_replica_with(
            register_name,
            register_tag,
            Some(authority_keypair1),
            Some(PublicPolicy {
                owner: owner1,
                permissions: perms1,
            }),
        );

        // the other replica will allow write ops to 'owner1' and 'authority2' only
        let authority_keypair2 = Keypair::new_ed25519(&mut OsRng);
        let authority2 = authority_keypair2.public_key();
        let mut perms2 = BTreeMap::default();
        let _ = perms2.insert(User::Key(owner1), PublicPermissions::new(true));
        let replica2 = create_public_reg_replica_with(
            register_name,
            register_tag,
            Some(authority_keypair2),
            Some(PublicPolicy {
                owner: authority2,
                permissions: perms2,
            }),
        );

        assert_eq!(replica1.owner(), owner1);
        assert_eq!(replica1.replica_authority(), owner1);
        assert_eq!(
            replica1.policy(None)?.permissions(User::Anyone),
            Some(Permissions::Public(PublicPermissions::new(true))),
        );
        assert_eq!(
            replica1.permissions(User::Anyone, None)?,
            Permissions::Public(PublicPermissions::new(true)),
        );

        assert_eq!(replica2.owner(), authority2);
        assert_eq!(replica2.replica_authority(), authority2);
        assert_eq!(
            replica2.policy(None)?.permissions(User::Key(owner1)),
            Some(Permissions::Public(PublicPermissions::new(true))),
        );
        assert_eq!(
            replica2.permissions(User::Key(owner1), None)?,
            Permissions::Public(PublicPermissions::new(true)),
        );

        Ok(())
    }

    #[test]
    fn register_query_private_policy() -> anyhow::Result<()> {
        let register_name = XorName::random();
        let register_tag = 43_666;

        let authority_keypair1 = Keypair::new_ed25519(&mut OsRng);
        let authority1 = authority_keypair1.public_key();
        let authority_keypair2 = Keypair::new_ed25519(&mut OsRng);
        let authority2 = authority_keypair2.public_key();

        let mut perms1 = BTreeMap::default();
        let user_perms1 = PrivatePermissions::new(/*read*/ true, /*write*/ false);
        let _ = perms1.insert(authority1, user_perms1);

        let mut perms2 = BTreeMap::default();
        let user_perms2 = PrivatePermissions::new(/*read*/ true, /*write*/ true);
        let _ = perms2.insert(authority2, user_perms2);
        let user_perms2 = PrivatePermissions::new(/*read*/ false, /*write*/ true);
        let _ = perms2.insert(authority1, user_perms2);

        let replica1 = create_private_reg_replica_with(
            register_name,
            register_tag,
            Some(authority_keypair1),
            Some(PrivatePolicy {
                owner: authority1,
                permissions: perms1,
            }),
        );

        let replica2 = create_private_reg_replica_with(
            register_name,
            register_tag,
            Some(authority_keypair2),
            Some(PrivatePolicy {
                owner: authority2,
                permissions: perms2,
            }),
        );

        assert_eq!(replica1.owner(), authority1);
        assert_eq!(replica1.replica_authority(), authority1);
        assert_eq!(
            replica1
                .policy(Some(authority1))?
                .permissions(User::Key(authority1)),
            Some(Permissions::Private(PrivatePermissions::new(true, false))),
        );
        assert_eq!(
            replica1.permissions(User::Key(authority1), Some(authority1))?,
            Permissions::Private(PrivatePermissions::new(true, false)),
        );

        assert_eq!(replica2.owner(), authority2);
        assert_eq!(replica2.replica_authority(), authority2);
        assert_eq!(
            replica2
                .policy(Some(authority2))?
                .permissions(User::Key(authority2)),
            Some(Permissions::Private(PrivatePermissions::new(true, true))),
        );
        assert_eq!(
            replica2.permissions(User::Key(authority2), Some(authority2))?,
            Permissions::Private(PrivatePermissions::new(true, true)),
        );
        assert_eq!(
            replica2.permissions(User::Key(authority1), None)?,
            Permissions::Private(PrivatePermissions::new(false, true)),
        );

        Ok(())
    }

    #[test]
    fn register_public_write_fails_when_no_perms_for_authority() -> anyhow::Result<()> {
        let register_name = XorName::random();
        let register_tag = 43_666;

        // one replica will allow write ops to anyone
        let authority_keypair1 = Keypair::new_ed25519(&mut OsRng);
        let owner1 = authority_keypair1.public_key();
        let mut perms1 = BTreeMap::default();
        let _ = perms1.insert(User::Anyone, PublicPermissions::new(true));
        let mut replica1 = create_public_reg_replica_with(
            register_name,
            register_tag,
            Some(authority_keypair1.clone()),
            Some(PublicPolicy {
                owner: owner1,
                permissions: perms1,
            }),
        );

        // the other replica will *not* allow write ops to 'owner1'
        let authority_keypair2 = Keypair::new_ed25519(&mut OsRng);
        let authority2 = authority_keypair2.public_key();
        let mut perms2 = BTreeMap::default();
        let _ = perms2.insert(User::Key(owner1), PublicPermissions::new(false));
        let mut replica2 = create_public_reg_replica_with(
            register_name,
            register_tag,
            Some(authority_keypair2.clone()),
            Some(PublicPolicy {
                owner: authority2,
                permissions: perms2,
            }),
        );

        // let's write to both replicas with one first item
        let item1 = b"item1";
        let item2 = b"item2";
        let (_, op1) = replica1.write(item1.to_vec(), BTreeSet::new())?;
        let write_op1 = sign_register_op(op1, &authority_keypair1)?;
        check_op_not_allowed_failure(replica2.apply_op(write_op1))?;

        let (_, op2) = replica2.write(item2.to_vec(), BTreeSet::new())?;
        let write_op2 = sign_register_op(op2, &authority_keypair2)?;
        replica1.apply_op(write_op2)?;

        assert_eq!(replica1.size(None)?, 2);
        assert_eq!(replica2.size(None)?, 1);

        Ok(())
    }

    #[test]
    fn register_private_write_fails_when_no_perms_for_authority() -> anyhow::Result<()> {
        let register_name = XorName::random();
        let register_tag = 43_666;
        let authority_keypair1 = Keypair::new_ed25519(&mut OsRng);
        let authority1 = authority_keypair1.public_key();
        let authority_keypair2 = Keypair::new_ed25519(&mut OsRng);
        let authority2 = authority_keypair2.public_key();

        let mut perms1 = BTreeMap::default();
        let user_perms1 = PrivatePermissions::new(/*read*/ false, /*write*/ true);
        let _ = perms1.insert(authority2, user_perms1);

        let mut perms2 = BTreeMap::default();
        let user_perms2 = PrivatePermissions::new(/*read*/ true, /*write*/ false);
        let _ = perms2.insert(authority1, user_perms2);

        let mut replica1 = create_private_reg_replica_with(
            register_name,
            register_tag,
            Some(authority_keypair1.clone()),
            Some(PrivatePolicy {
                owner: authority1,
                permissions: perms1,
            }),
        );

        let mut replica2 = create_private_reg_replica_with(
            register_name,
            register_tag,
            Some(authority_keypair2.clone()),
            Some(PrivatePolicy {
                owner: authority2,
                permissions: perms2,
            }),
        );

        // let's try to write to both registers
        let item1 = b"item1";
        let item2 = b"item2";

        let (entry1_hash, op1) = replica1.write(item1.to_vec(), BTreeSet::new())?;
        let write_op1 = sign_register_op(op1, &authority_keypair1)?;
        check_op_not_allowed_failure(replica2.apply_op(write_op1))?;

        let (entry2_hash, op2) = replica2.write(item2.to_vec(), BTreeSet::new())?;
        let write_op2 = sign_register_op(op2, &authority_keypair2)?;
        replica1.apply_op(write_op2)?;

        assert_eq!(replica1.size(None)?, 2);
        assert_eq!(replica2.size(None)?, 1);

        // Let's do some read permissions check now...

        // let's check authority1 can read from replica1 and replica2
        let data = replica1.get(entry1_hash, Some(authority1))?;
        let last = replica1.read(Some(authority1))?;
        assert_eq!(data, Some(&item1.to_vec()));
        assert_eq!(
            last,
            vec![(entry1_hash, item1.to_vec()), (entry2_hash, item2.to_vec())]
                .into_iter()
                .collect()
        );

        let data = replica2.get(entry2_hash, Some(authority1))?;
        let last = replica2.read(Some(authority1))?;
        assert_eq!(data, Some(&item2.to_vec()));
        assert_eq!(
            last,
            vec![(entry2_hash, item2.to_vec())].into_iter().collect()
        );

        // authority2 cannot read from replica1
        check_op_not_allowed_failure(replica1.get(entry1_hash, Some(authority2)))?;
        check_op_not_allowed_failure(replica1.read(Some(authority2)))?;

        // but authority2 can read from replica2
        let data = replica2.get(entry2_hash, Some(authority2))?;
        let last = replica2.read(Some(authority2))?;
        assert_eq!(data, Some(&item2.to_vec()));
        assert_eq!(
            last,
            vec![(entry2_hash, item2.to_vec())].into_iter().collect()
        );

        Ok(())
    }

    // Helpers for tests

    fn sign_register_op(mut op: RegisterOp<Entry>, keypair: &Keypair) -> Result<RegisterOp<Entry>> {
        let bytes = utils::serialise(&op.crdt_op)?;
        let signature = keypair.sign(&bytes);
        op.signature = Some(signature);
        Ok(op)
    }

    fn gen_pub_reg_replicas(
        authority_keypair: Option<Keypair>,
        name: XorName,
        tag: u64,
        policy: Option<PublicPolicy>,
        count: usize,
    ) -> Vec<(Keypair, Register)> {
        let replicas: Vec<(Keypair, Register)> = (0..count)
            .map(|_| {
                let authority_keypair = authority_keypair
                    .clone()
                    .unwrap_or_else(|| Keypair::new_ed25519(&mut OsRng));
                let authority = authority_keypair.public_key();
                let register = Register::new_public(authority, name, tag, policy.clone());
                (authority_keypair, register)
            })
            .collect();

        assert_eq!(replicas.len(), count);
        replicas
    }

    fn gen_priv_reg_replicas(
        authority_keypair: Option<Keypair>,
        name: XorName,
        tag: u64,
        policy: Option<PrivatePolicy>,
        count: usize,
    ) -> Vec<(Keypair, Register)> {
        let replicas: Vec<(Keypair, Register)> = (0..count)
            .map(|_| {
                let authority_keypair = authority_keypair
                    .clone()
                    .unwrap_or_else(|| Keypair::new_ed25519(&mut OsRng));
                let authority = authority_keypair.public_key();
                let register = Register::new_private(authority, name, tag, policy.clone());
                (authority_keypair, register)
            })
            .collect();

        assert_eq!(replicas.len(), count);
        replicas
    }

    fn create_public_reg_replicas(count: usize) -> Vec<(Keypair, Register)> {
        let register_name = XorName::random();
        let register_tag = 43_000;

        gen_pub_reg_replicas(None, register_name, register_tag, None, count)
    }

    fn create_public_reg_replica_with(
        name: XorName,
        tag: u64,
        authority_keypair: Option<Keypair>,
        policy: Option<PublicPolicy>,
    ) -> Register {
        let replicas = gen_pub_reg_replicas(authority_keypair, name, tag, policy, 1);
        replicas[0].1.clone()
    }

    fn create_private_reg_replica_with(
        name: XorName,
        tag: u64,
        authority_keypair: Option<Keypair>,
        policy: Option<PrivatePolicy>,
    ) -> Register {
        let replicas = gen_priv_reg_replicas(authority_keypair, name, tag, policy, 1);
        replicas[0].1.clone()
    }

    // check it fails due to not having permissions
    fn check_op_not_allowed_failure<T>(result: Result<T>) -> anyhow::Result<()> {
        match result {
            Err(Error::AccessDenied(_)) => Ok(()),
            Err(err) => Err(anyhow!(
                "Error returned was the unexpected one for a non-allowed op: {}",
                err
            )),
            Ok(_) => Err(anyhow!(
                "Register operation succeded unexpectedly, an AccessDenied error was expected"
                    .to_string(),
            )),
        }
    }

    // verify data convergence on a set of replicas and with the expected length
    fn verify_data_convergence(replicas: Vec<Register>, expected_size: u64) -> Result<()> {
        // verify all replicas have the same and expected size
        for r in &replicas {
            assert_eq!(r.size(None)?, expected_size);
        }

        // now verify that the items are the same in all replicas
        let r0 = &replicas[0];
        for r in replicas.iter() {
            assert_eq!(r.crdt, r0.crdt);
        }

        Ok(())
    }

    // Generate a vec of Register replicas of some length, with corresponding vec of keypairs for signing, and the overall owner of the register
    fn generate_replicas(
        max_quantity: usize,
    ) -> impl Strategy<Value = Result<(Vec<Register>, Arc<Keypair>)>> {
        let xorname = XorName::random();
        let tag = 45_000u64;

        let owner_keypair = Arc::new(Keypair::new_ed25519(&mut OsRng));
        let owner = owner_keypair.public_key();
        let policy = PublicPolicy {
            owner,
            permissions: BTreeMap::default(),
        };

        (1..max_quantity + 1).prop_map(move |quantity| {
            let mut replicas = Vec::with_capacity(quantity);
            for _ in 0..quantity {
                let replica = Register::new_public(owner, xorname, tag, Some(policy.clone()));

                replicas.push(replica);
            }

            Ok((replicas, owner_keypair.clone()))
        })
    }

    // Generate a Register entry
    fn generate_reg_entry() -> impl Strategy<Value = Vec<u8>> {
        "\\PC*".prop_map(|s| s.into_bytes())
    }

    // Generate a vec of Register entries
    fn generate_dataset(max_quantity: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
        prop::collection::vec(generate_reg_entry(), 1..max_quantity + 1)
    }

    // Generates a vec of Register entries each with a value suggesting
    // the delivery chance of the op that gets created with the entry
    fn generate_dataset_and_probability(
        max_quantity: usize,
    ) -> impl Strategy<Value = Vec<(Vec<u8>, u8)>> {
        prop::collection::vec((generate_reg_entry(), any::<u8>()), 1..max_quantity + 1)
    }

    proptest! {
        #[test]
        fn proptest_reg_doesnt_crash_with_random_data(
            data in generate_reg_entry()
        ) {
            // Instantiate the same Register on two replicas
            let register_name = XorName::random();
            let register_tag = 45_000u64;
            let owner_keypair = Keypair::new_ed25519(&mut OsRng);
            let policy = PublicPolicy {
                owner: owner_keypair.public_key(),
                permissions: BTreeMap::default(),
            };

            let mut replicas = gen_pub_reg_replicas(
                Some(owner_keypair.clone()),
                register_name,
                register_tag,
                Some(policy),
                2);
            let (_, mut replica1) = replicas.remove(0);
            let (_, mut replica2) = replicas.remove(0);

            // Write an item on replicas
            let (_, op) = replica1.write(data, BTreeSet::new())?;
            let write_op = sign_register_op(op, &owner_keypair)?;
            replica2.apply_op(write_op)?;

            verify_data_convergence(vec![replica1, replica2], 1)?;
        }

        #[test]
        fn proptest_reg_converge_with_many_random_data(
            dataset in generate_dataset(1000)
        ) {
            // Instantiate the same Register on two replicas
            let register_name = XorName::random();
            let register_tag = 43_001u64;
            let owner_keypair = Keypair::new_ed25519(&mut OsRng);
            let policy = PublicPolicy {
                owner: owner_keypair.public_key(),
                permissions: BTreeMap::default(),
            };

            // Instantiate the same Register on two replicas
            let mut replicas = gen_pub_reg_replicas(
                Some(owner_keypair.clone()),
                register_name,
                register_tag,
                Some(policy),
                2);
            let (_, mut replica1) = replicas.remove(0);
            let (_, mut replica2) = replicas.remove(0);

            let dataset_length = dataset.len() as u64;

            // insert our data at replicas
            let mut parents = BTreeSet::new();
            for data in dataset {
                // Write an item on replica1
                let (hash, op) = replica1.write(data, parents.clone())?;
                let write_op = sign_register_op(op, &owner_keypair)?;
                // now apply that op to replica 2
                replica2.apply_op(write_op)?;
                parents = vec![hash].into_iter().collect();
            }

            verify_data_convergence(vec![replica1, replica2], dataset_length)?;
        }

        #[test]
        fn proptest_reg_converge_with_many_random_data_random_entry_parents(
            dataset in generate_dataset(1000)
        ) {
            // Instantiate the same Register on two replicas
            let register_name = XorName::random();
            let register_tag = 43_002u64;
            let owner_keypair = Keypair::new_ed25519(&mut OsRng);
            let policy = PublicPolicy {
                owner: owner_keypair.public_key(),
                permissions: BTreeMap::default(),
            };

            // Instantiate the same Register on two replicas
            let mut replicas = gen_pub_reg_replicas(
                Some(owner_keypair.clone()),
                register_name,
                register_tag,
                Some(policy),
                2);
            let (_, mut replica1) = replicas.remove(0);
            let (_, mut replica2) = replicas.remove(0);

            let dataset_length = dataset.len() as u64;

            // insert our data at replicas
            let mut list_of_hashes = Vec::new();
            let mut rng = thread_rng();
            for data in dataset {
                // choose a random set of parents
                let num_of_parents: usize = rng.gen();
                let parents: BTreeSet<_> = list_of_hashes.choose_multiple(&mut OsRng, num_of_parents).cloned().collect();

                // Write an item on replica1 using the randomly generated set of parents
                let (hash, op) = replica1.write(data, parents)?;
                let write_op = sign_register_op(op, &owner_keypair)?;

                // now apply that op to replica 2
                replica2.apply_op(write_op)?;
                list_of_hashes.push(hash);
            }

            verify_data_convergence(vec![replica1, replica2], dataset_length)?;
        }

        #[test]
        fn proptest_reg_converge_with_many_random_data_across_arbitrary_number_of_replicas(
            dataset in generate_dataset(500),
            res in generate_replicas(50)
        ) {
            let (mut replicas, owner_keypair) = res?;
            let dataset_length = dataset.len() as u64;

            // insert our data at replicas
            let mut parents = BTreeSet::new();
            for data in dataset {
                // first generate an op from one replica...
                let (hash, op)= replicas[0].write(data, parents)?;
                let signed_op = sign_register_op(op, &owner_keypair)?;

                // then apply this to all replicas
                for replica in &mut replicas {
                    replica.apply_op(signed_op.clone())?;
                }
                parents = vec![hash].into_iter().collect();
            }

            verify_data_convergence(replicas, dataset_length)?;

        }

        #[test]
        fn proptest_converge_with_shuffled_op_set_across_arbitrary_number_of_replicas(
            dataset in generate_dataset(100),
            res in generate_replicas(500)
        ) {
            let (mut replicas, owner_keypair) = res?;
            let dataset_length = dataset.len() as u64;

            // generate an ops set from one replica
            let mut ops = vec![];

            let mut parents = BTreeSet::new();
            for data in dataset {
                let (hash, op) = replicas[0].write(data, parents)?;
                let signed_op = sign_register_op(op, &owner_keypair)?;
                ops.push(signed_op);
                parents = vec![hash].into_iter().collect();
            }

            // now we randomly shuffle ops and apply at each replica
            for replica in &mut replicas {
                let mut ops = ops.clone();
                ops.shuffle(&mut OsRng);

                for op in ops {
                    replica.apply_op(op)?;
                }
            }

            verify_data_convergence(replicas, dataset_length)?;
        }

        #[test]
        fn proptest_converge_with_shuffled_ops_from_many_replicas_across_arbitrary_number_of_replicas(
            dataset in generate_dataset(1000),
            res in generate_replicas(100)
        ) {
            let (mut replicas, owner_keypair) = res?;
            let dataset_length = dataset.len() as u64;

            // generate an ops set using random replica for each data
            let mut ops = vec![];
            let mut parents = BTreeSet::new();
            for data in dataset {
                if let Some(replica) = replicas.choose_mut(&mut OsRng)
                {
                    let (hash, op) = replica.write(data, parents)?;
                    let signed_op = sign_register_op(op, &owner_keypair)?;
                    ops.push(signed_op);
                    parents = vec![hash].into_iter().collect();
                }
            }

            let opslen = ops.len() as u64;
            prop_assert_eq!(dataset_length, opslen);

            // now we randomly shuffle ops and apply at each replica
            for replica in &mut replicas {
                let mut ops = ops.clone();
                ops.shuffle(&mut OsRng);

                for op in ops {
                    replica.apply_op(op)?;
                }
            }

            verify_data_convergence(replicas, dataset_length)?;
        }

        #[test]
        fn proptest_dropped_data_can_be_reapplied_and_we_converge(
            dataset in generate_dataset_and_probability(1000),
        ) {
            // Instantiate the same Register on two replicas
            let register_name = XorName::random();
            let register_tag = 43_001u64;
            let owner_keypair = Keypair::new_ed25519(&mut OsRng);
            let policy = PublicPolicy {
                owner: owner_keypair.public_key(),
                permissions: BTreeMap::default(),
            };

            // Instantiate the same Register on two replicas
            let mut replicas = gen_pub_reg_replicas(
                Some(owner_keypair.clone()),
                register_name,
                register_tag,
                Some(policy),
                2);
            let (_, mut replica1) = replicas.remove(0);
            let (_, mut replica2) = replicas.remove(0);

            let dataset_length = dataset.len() as u64;

            let mut ops = vec![];
            let mut parents = BTreeSet::new();
            for (data, delivery_chance) in dataset {
                let (hash, op)= replica1.write(data, parents)?;
                let signed_op = sign_register_op(op, &owner_keypair)?;

                ops.push((signed_op, delivery_chance));
                parents = vec![hash].into_iter().collect();
            }

            for (op, delivery_chance) in ops.clone() {
                if delivery_chance < u8::MAX / 3 {
                    replica2.apply_op(op)?;
                }
            }

            // here we statistically should have dropped some messages
            if dataset_length > 50 {
                assert_ne!(replica2.size(None), replica1.size(None));
            }

            // reapply all ops
            for (op, _) in ops {
                replica2.apply_op(op)?;
            }

            // now we converge
            verify_data_convergence(vec![replica1, replica2], dataset_length)?;
        }

        #[test]
        fn proptest_converge_with_shuffled_ops_from_many_while_dropping_some_at_random(
            dataset in generate_dataset_and_probability(1000),
            res in generate_replicas(100),
        ) {
            let (mut replicas, owner_keypair) = res?;
            let dataset_length = dataset.len() as u64;

            // generate an ops set using random replica for each data
            let mut ops = vec![];
            let mut parents = BTreeSet::new();
            for (data, delivery_chance) in dataset {
                // a random index within the replicas range
                let index: usize = OsRng.gen_range(0, replicas.len());
                let replica = &mut replicas[index];

                let (hash, op)=replica.write(data, parents)?;
                let signed_op = sign_register_op(op, &owner_keypair)?;
                ops.push((signed_op, delivery_chance));
                parents = vec![hash].into_iter().collect();
            }

            let opslen = ops.len() as u64;
            prop_assert_eq!(dataset_length, opslen);

            // now we randomly shuffle ops and apply at each replica
            for replica in &mut replicas {
                let mut ops = ops.clone();
                ops.shuffle(&mut OsRng);

                for (op, delivery_chance) in ops.clone() {
                    if delivery_chance > u8::MAX / 3 {
                        replica.apply_op(op)?;
                    }
                }

                // reapply all ops, simulating lazy messaging filling in the gaps
                for (op, _) in ops {
                    replica.apply_op(op)?;
                }
            }

            verify_data_convergence(replicas, dataset_length)?;
        }

        #[test]
        fn proptest_converge_with_shuffled_ops_including_bad_ops_which_error_and_are_not_applied(
            dataset in generate_dataset(10),
            bogus_dataset in generate_dataset(10), // should be same number as dataset
            gen_replicas_result in generate_replicas(10),

        ) {
            let (mut replicas, owner_keypair) = gen_replicas_result?;
            let dataset_length = dataset.len();
            let bogus_dataset_length = bogus_dataset.len();
            let number_replicas = replicas.len();

            // generate the real ops set using random replica for each data
            let mut ops = vec![];
            let mut parents = BTreeSet::new();
            for data in dataset {
                if let Some(replica) = replicas.choose_mut(&mut OsRng)
                {
                    let (hash, op)=replica.write(data, parents)?;
                    let signed_op = sign_register_op(op, &owner_keypair)?;
                    ops.push(signed_op);
                    parents = vec![hash].into_iter().collect();
                }
            }

            // set up a replica that has nothing to do with the rest, random xor... different owner...
            let xorname = XorName::random();
            let tag = 45_000u64;
            let random_owner_keypair = Keypair::new_ed25519(&mut OsRng);
            let mut bogus_replica = Register::new_public(random_owner_keypair.public_key(), xorname, tag, None);

            // add bogus ops from bogus replica + bogus data
            let mut parents = BTreeSet::new();
            for data in bogus_dataset {
                let (hash, op)=bogus_replica.write(data, parents)?;
                let bogus_op = sign_register_op(op, &random_owner_keypair)?;
                bogus_replica.apply_op(bogus_op.clone())?;
                ops.push(bogus_op);
                parents = vec![hash].into_iter().collect();
            }

            let opslen = ops.len();
            prop_assert_eq!(dataset_length + bogus_dataset_length, opslen);

            let mut err_count = vec![];
            // now we randomly shuffle ops and apply at each replica
            for replica in &mut replicas {
                let mut ops = ops.clone();
                ops.shuffle(&mut OsRng);

                for op in ops {
                    match replica.apply_op(op) {
                        Ok(_) => {},
                        // record all errors to check this matches bogus data
                        Err(error) => {err_count.push(error)},
                    }
                }
            }

            // check we get an error per bogus datum per replica
            assert_eq!(err_count.len(), bogus_dataset_length * number_replicas);

            verify_data_convergence(replicas, dataset_length as u64)?;
        }

    }
}
