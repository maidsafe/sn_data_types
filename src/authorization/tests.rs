// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing access_list and limitations relating to use of the SAFE Network
// Software.

use crate::authorization::access_control::*;
use crate::data::*;
use crate::sequence::*;
use crate::shared_data::{Owner, User, Version};
use crate::{Error, PublicKey, XorName};
use std::collections::BTreeMap;
use threshold_crypto::SecretKey;
use unwrap::unwrap;

fn gen_public_key() -> PublicKey {
    PublicKey::Bls(SecretKey::random().public_key())
}

// ------------------------------------------------------------------------------------------
// -----------------------------------  Sequence  -------------------------------------------
// ------------------------------------------------------------------------------------------

#[test]
fn set_sequence_access_list() {
    let mut data = PrivateSentriedSequence::new(XorName([1; 32]), 10000);
    let access_list = PrivateAccessList {
        access_list: BTreeMap::new(),
        expected_data_version: 0,
        expected_owners_version: 0,
    };
    // Set the first access_list with correct ExpectedVersions - should pass.
    let res = data.set_access_list(&access_list, 0);

    match res {
        Ok(()) => (),
        Err(x) => panic!("Unexpected error: {:?}", x),
    }

    // Verify that the access_list are part of the history.
    assert_eq!(
        unwrap!(data.access_list_history_range(Version::FromStart(0), Version::FromEnd(0),))
            .len(),
        1
    );

    let access_list = PrivateAccessList {
        access_list: BTreeMap::new(),
        expected_data_version: 64,
        expected_owners_version: 0,
    };
    // Set access_list with incorrect ExpectedVersions - should fail.
    let res = data.set_access_list(&access_list, 1);

    match res {
        Err(_) => (),
        Ok(()) => panic!("Unexpected Ok(()) result"),
    }

    // Verify that the history of access_list remains unchanged.
    assert_eq!(
        unwrap!(data.access_list_history_range(Version::FromStart(0), Version::FromEnd(0),))
            .len(),
        1
    );
}

#[test]
fn set_sequence_owners() {
    let owner_pk = gen_public_key();

    let mut data = PrivateSentriedSequence::new(XorName([1; 32]), 10000);

    // Set the first owner with correct ExpectedVersions - should pass.
    let res = data.set_owner(
        Owner {
            public_key: owner_pk,
            expected_data_version: 0,
            expected_access_list_version: 0,
        },
        0,
    );

    match res {
        Ok(()) => (),
        Err(x) => panic!("Unexpected error: {:?}", x),
    }

    // Verify that the owner is part of the history.
    assert_eq!(
        unwrap!(data.owner_history_range(Version::FromStart(0), Version::FromEnd(0),)).len(),
        1
    );

    // Set owner with incorrect ExpectedVersions - should fail.
    let res = data.set_owner(
        Owner {
            public_key: owner_pk,
            expected_data_version: 64,
            expected_access_list_version: 0,
        },
        1,
    );

    match res {
        Err(_) => (),
        Ok(()) => panic!("Unexpected Ok(()) result"),
    }

    // Verify that the history of owners remains unchanged.
    assert_eq!(
        unwrap!(data.owner_history_range(Version::FromStart(0), Version::FromEnd(0),)).len(),
        1
    );
}

#[test]
fn gets_sequence_shell() {
    let owner_pk = gen_public_key();
    let owner_pk1 = gen_public_key();

    let mut data = PrivateSentriedSequence::new(XorName([1; 32]), 10000);

    let _ = data.set_owner(
        Owner {
            public_key: owner_pk,
            expected_data_version: 0,
            expected_access_list_version: 0,
        },
        0,
    );

    let _ = data.set_owner(
        Owner {
            public_key: owner_pk1,
            expected_data_version: 0,
            expected_access_list_version: 0,
        },
        1,
    );

    assert_eq!(
        data.expected_owners_version(),
        unwrap!(data.shell(0)).expected_owners_version()
    );
}

#[test]
fn can_retrieve_sequence_access_list() {
    let public_key = gen_public_key();
    let invalid_public_key = gen_public_key();

    let mut public_access_list = PublicAccessList {
        access_list: BTreeMap::new(),
        expected_data_version: 0,
        expected_owners_version: 0,
    };
    let _ = public_access_list.access_list.insert(
        User::Specific(public_key),
        PublicUserAccess::new(BTreeMap::new()),
    );

    let mut private_access_list = PrivateAccessList {
        access_list: BTreeMap::new(),
        expected_data_version: 0,
        expected_owners_version: 0,
    };
    let _ = private_access_list
        .access_list
        .insert(public_key, PrivateUserAccess::new(BTreeMap::new()));

    // public
    let mut data = PublicSequence::new(rand::random(), 20);
    unwrap!(data.set_access_list(&public_access_list, 0));
    let data = SequenceData::from(data);

    assert_eq!(data.public_access_list_at(0), Ok(&public_access_list));
    assert_eq!(data.private_access_list_at(0), Err(Error::InvalidOperation));

    assert_eq!(
        data.public_user_access_at(User::Specific(public_key), 0),
        Ok(PublicUserAccess::new(BTreeMap::new()))
    );
    assert_eq!(
        data.private_user_access_at(public_key, 0),
        Err(Error::InvalidOperation)
    );
    assert_eq!(
        data.public_user_access_at(User::Specific(invalid_public_key), 0),
        Err(Error::NoSuchEntry)
    );

    // public, sentried
    let mut data = PublicSentriedSequence::new(rand::random(), 20);
    unwrap!(data.set_access_list(&public_access_list, 0));
    let data = SequenceData::from(data);

    assert_eq!(data.public_access_list_at(0), Ok(&public_access_list));
    assert_eq!(data.private_access_list_at(0), Err(Error::InvalidOperation));

    assert_eq!(
        data.public_user_access_at(User::Specific(public_key), 0),
        Ok(PublicUserAccess::new(BTreeMap::new()))
    );
    assert_eq!(
        data.private_user_access_at(public_key, 0),
        Err(Error::InvalidOperation)
    );
    assert_eq!(
        data.public_user_access_at(User::Specific(invalid_public_key), 0),
        Err(Error::NoSuchEntry)
    );

    // Private
    let mut data = PrivateSequence::new(rand::random(), 20);
    unwrap!(data.set_access_list(&private_access_list, 0));
    let data = SequenceData::from(data);

    assert_eq!(data.private_access_list_at(0), Ok(&private_access_list));
    assert_eq!(data.public_access_list_at(0), Err(Error::InvalidOperation));

    assert_eq!(
        data.private_user_access_at(public_key, 0),
        Ok(PrivateUserAccess::new(BTreeMap::new()))
    );
    assert_eq!(
        data.public_user_access_at(User::Specific(public_key), 0),
        Err(Error::InvalidOperation)
    );
    assert_eq!(
        data.private_user_access_at(invalid_public_key, 0),
        Err(Error::NoSuchEntry)
    );

    // Private, seq
    let mut data = PrivateSentriedSequence::new(rand::random(), 20);
    unwrap!(data.set_access_list(&private_access_list, 0));
    let data = SequenceData::from(data);

    assert_eq!(data.private_access_list_at(0), Ok(&private_access_list));
    assert_eq!(data.public_access_list_at(0), Err(Error::InvalidOperation));

    assert_eq!(
        data.private_user_access_at(public_key, 0),
        Ok(PrivateUserAccess::new(BTreeMap::new()))
    );
    assert_eq!(
        data.public_user_access_at(User::Specific(public_key), 0),
        Err(Error::InvalidOperation)
    );
    assert_eq!(
        data.private_user_access_at(invalid_public_key, 0),
        Err(Error::NoSuchEntry)
    );
}

#[test]
fn validates_public_sequence_access_list() {
    let public_key_0 = gen_public_key();
    let public_key_1 = gen_public_key();
    let public_key_2 = gen_public_key();
    let mut sequence = PublicSentriedSequence::new(XorName([1; 32]), 100);

    // no owner
    let data = SequenceData::from(sequence.clone());
    assert_eq!(data.is_allowed(AccessType::Append, public_key_0), false);
    // data is Public - read always allowed
    assert_sequence_read_permitted(&data, public_key_0, true);

    // no access_list
    unwrap!(sequence.set_owner(
        Owner {
            public_key: public_key_0,
            expected_data_version: 0,
            expected_access_list_version: 0,
        },
        0,
    ));
    let data = SequenceData::from(sequence.clone());

    assert_eq!(data.is_allowed(AccessType::Append, public_key_0), true);
    assert_eq!(data.is_allowed(AccessType::Append, public_key_1), false);
    // data is Public - read always allowed
    assert_sequence_read_permitted(&data, public_key_0, true);
    assert_sequence_read_permitted(&data, public_key_1, true);

    // with access_list
    let mut access_list = PublicAccessList {
        access_list: BTreeMap::new(),
        expected_data_version: 0,
        expected_owners_version: 1,
    };
    let mut set = BTreeMap::new();
    let _ = set.insert(AccessType::Append, true);
    let _ = access_list
        .access_list
        .insert(User::Anyone, PublicUserAccess::new(set));
    let mut set = BTreeMap::new();
    let _ = set.insert(AccessType::ModifyPermissions, true);
    let _ = access_list
        .access_list
        .insert(User::Specific(public_key_1), PublicUserAccess::new(set));
    unwrap!(sequence.set_access_list(&access_list, 0));
    let data = SequenceData::from(sequence);

    // existing key fallback
    assert_eq!(data.is_allowed(AccessType::Append, public_key_1), true);
    // existing key override
    assert_modify_sequence_access_list_permitted(&data, public_key_1, true);
    // non-existing keys are handled by `Anyone`
    assert_eq!(data.is_allowed(AccessType::Append, public_key_2), true);
    assert_modify_sequence_access_list_permitted(&data, public_key_2, false);
    // data is Public - read always allowed
    assert_sequence_read_permitted(&data, public_key_0, true);
    assert_sequence_read_permitted(&data, public_key_1, true);
    assert_sequence_read_permitted(&data, public_key_2, true);
}

#[test]
fn validates_private_sequence_access_list() {
    let public_key_0 = gen_public_key();
    let public_key_1 = gen_public_key();
    let public_key_2 = gen_public_key();
    let mut sequence = PrivateSentriedSequence::new(XorName([1; 32]), 100);

    // no owner
    let data = SequenceData::from(sequence.clone());
    assert_sequence_read_permitted(&data, public_key_0, false);

    // no access
    unwrap!(sequence.set_owner(
        Owner {
            public_key: public_key_0,
            expected_data_version: 0,
            expected_access_list_version: 0,
        },
        0,
    ));
    let data = SequenceData::from(sequence.clone());

    assert_sequence_read_permitted(&data, public_key_0, true);
    assert_sequence_read_permitted(&data, public_key_1, false);

    // with access
    let mut access_list = PrivateAccessList {
        access_list: BTreeMap::new(),
        expected_data_version: 0,
        expected_owners_version: 1,
    };
    let mut set = BTreeMap::new();
    let _ = set.insert(AccessType::Append, true);
    let _ = set.insert(AccessType::Read, true);
    let _ = set.insert(AccessType::ModifyPermissions, false);
    let _ = access_list
        .access_list
        .insert(public_key_1, PrivateUserAccess::new(set));
    unwrap!(sequence.set_access_list(&access_list, 0));
    let data = SequenceData::from(sequence);

    // existing key
    assert_sequence_read_permitted(&data, public_key_1, true);
    assert_eq!(data.is_allowed(AccessType::Append, public_key_1), true);
    assert_modify_sequence_access_list_permitted(&data, public_key_1, false);

    // non-existing key
    assert_sequence_read_permitted(&data, public_key_2, false);
    assert_eq!(data.is_allowed(AccessType::Append, public_key_2), false);
    assert_modify_sequence_access_list_permitted(&data, public_key_2, false);
}

fn assert_sequence_read_permitted(data: &SequenceData, public_key: PublicKey, permitted: bool) {
    assert_eq!(data.is_allowed(AccessType::Read, public_key), permitted);
}

fn assert_modify_sequence_access_list_permitted(
    data: &SequenceData,
    public_key: PublicKey,
    permitted: bool,
) {
    assert_eq!(
        data.is_allowed(AccessType::ModifyPermissions, public_key),
        permitted
    );
}

// ------------------------------------------------------------------------------------------
// -----------------------------------  MAP  ------------------------------------------------
// ------------------------------------------------------------------------------------------

#[test]
fn set_map_access_list() {
    let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
    let access_list = PrivateAccessList {
        access_list: BTreeMap::new(),
        expected_data_version: 0,
        expected_owners_version: 0,
    };

    // Set the first permission set with correct ExpectedVersions - should pass.
    let res = data.set_access_list(&access_list, 0);

    match res {
        Ok(()) => (),
        Err(x) => panic!("Unexpected error: {:?}", x),
    }

    // Verify that the access_list are part of the history.
    assert_eq!(
        unwrap!(data.access_list_history_range(Version::FromStart(0), Version::FromEnd(0),))
            .len(),
        1
    );
    let access_list = PrivateAccessList {
        access_list: BTreeMap::new(),
        expected_data_version: 64,
        expected_owners_version: 0,
    };
    // Set access_list with incorrect ExpectedVersions - should fail.
    let res = data.set_access_list(&access_list, 1);

    match res {
        Err(_) => (),
        Ok(()) => panic!("Unexpected Ok(()) result"),
    }

    // Verify that the history of access_list remains unchanged.
    assert_eq!(
        unwrap!(data.access_list_history_range(Version::FromStart(0), Version::FromEnd(0),))
            .len(),
        1
    );
}

#[test]
fn set_map_owner() {
    let owner_pk = gen_public_key();

    let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);

    // Set the first owner with correct ExpectedVersions - should pass.
    let res = data.set_owner(
        Owner {
            public_key: owner_pk,
            expected_data_version: 0,
            expected_access_list_version: 0,
        },
        0,
    );

    match res {
        Ok(()) => (),
        Err(x) => panic!("Unexpected error: {:?}", x),
    }

    // Verify that the owner is part of history.
    assert_eq!(
        unwrap!(data.owner_history_range(Version::FromStart(0), Version::FromEnd(0),)).len(),
        1
    );

    // Set new owner with incorrect ExpectedVersions - should fail.
    let res = data.set_owner(
        Owner {
            public_key: owner_pk,
            expected_data_version: 64,
            expected_access_list_version: 0,
        },
        1,
    );

    match res {
        Err(_) => (),
        Ok(()) => panic!("Unexpected Ok(()) result"),
    }

    // Verify that the history of owners remains unchanged.
    assert_eq!(
        unwrap!(data.owner_history_range(Version::FromStart(0), Version::FromEnd(0),)).len(),
        1
    );
}

#[test]
fn gets_map_shell() {
    let owner_pk = gen_public_key();
    let owner_pk1 = gen_public_key();

    let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);

    let _ = data.set_owner(
        Owner {
            public_key: owner_pk,
            expected_data_version: 0,
            expected_access_list_version: 0,
        },
        0,
    );

    let _ = data.set_owner(
        Owner {
            public_key: owner_pk1,
            expected_data_version: 0,
            expected_access_list_version: 0,
        },
        1,
    );

    assert_eq!(
        data.expected_owners_version(),
        unwrap!(data.shell(0)).expected_owners_version()
    );
}

#[test]
fn can_retrieve_map_access_list() {
    let public_key = gen_public_key();
    let invalid_public_key = gen_public_key();

    let mut public_access_list = PublicAccessList {
        access_list: BTreeMap::new(),
        expected_data_version: 0,
        expected_owners_version: 0,
    };
    let _ = public_access_list.access_list.insert(
        User::Specific(public_key),
        PublicUserAccess::new(BTreeMap::new()),
    );

    let mut private_access_list = PrivateAccessList {
        access_list: BTreeMap::new(),
        expected_data_version: 0,
        expected_owners_version: 0,
    };
    let _ = private_access_list
        .access_list
        .insert(public_key, PrivateUserAccess::new(BTreeMap::new()));

    // public
    let mut data = PublicMap::new(rand::random(), 20);
    unwrap!(data.set_access_list(&public_access_list, 0));
    let data = MapData::from(data);

    assert_eq!(data.public_access_list_at(0), Ok(&public_access_list));
    assert_eq!(data.private_access_list_at(0), Err(Error::InvalidOperation));

    assert_eq!(
        data.public_user_access_at(User::Specific(public_key), 0),
        Ok(PublicUserAccess::new(BTreeMap::new()))
    );
    assert_eq!(
        data.private_user_access_at(public_key, 0),
        Err(Error::InvalidOperation)
    );
    assert_eq!(
        data.public_user_access_at(User::Specific(invalid_public_key), 0),
        Err(Error::NoSuchEntry)
    );

    // public, sentried
    let mut data = PublicSentriedMap::new(rand::random(), 20);
    unwrap!(data.set_access_list(&public_access_list, 0));
    let data = MapData::from(data);

    assert_eq!(data.public_access_list_at(0), Ok(&public_access_list));
    assert_eq!(data.private_access_list_at(0), Err(Error::InvalidOperation));

    assert_eq!(
        data.public_user_access_at(User::Specific(public_key), 0),
        Ok(PublicUserAccess::new(BTreeMap::new()))
    );
    assert_eq!(
        data.private_user_access_at(public_key, 0),
        Err(Error::InvalidOperation)
    );
    assert_eq!(
        data.public_user_access_at(User::Specific(invalid_public_key), 0),
        Err(Error::NoSuchEntry)
    );

    // Private
    let mut data = PrivateMap::new(rand::random(), 20);
    unwrap!(data.set_access_list(&private_access_list, 0));
    let data = MapData::from(data);

    assert_eq!(data.private_access_list_at(0), Ok(&private_access_list));
    assert_eq!(data.public_access_list_at(0), Err(Error::InvalidOperation));

    assert_eq!(
        data.private_user_access_at(public_key, 0),
        Ok(PrivateUserAccess::new(BTreeMap::new()))
    );
    assert_eq!(
        data.public_user_access_at(User::Specific(public_key), 0),
        Err(Error::InvalidOperation)
    );
    assert_eq!(
        data.private_user_access_at(invalid_public_key, 0),
        Err(Error::NoSuchEntry)
    );

    // Private, sentried
    let mut data = PrivateSentriedMap::new(rand::random(), 20);
    unwrap!(data.set_access_list(&private_access_list, 0));
    let data = MapData::from(data);

    assert_eq!(data.private_access_list_at(0), Ok(&private_access_list));
    assert_eq!(data.public_access_list_at(0), Err(Error::InvalidOperation));

    assert_eq!(
        data.private_user_access_at(public_key, 0),
        Ok(PrivateUserAccess::new(BTreeMap::new()))
    );
    assert_eq!(
        data.public_user_access_at(User::Specific(public_key), 0),
        Err(Error::InvalidOperation)
    );
    assert_eq!(
        data.private_user_access_at(invalid_public_key, 0),
        Err(Error::NoSuchEntry)
    );
}

#[test]
fn validates_public_map_access_list() {
    let public_key_0 = gen_public_key();
    let public_key_1 = gen_public_key();
    let public_key_2 = gen_public_key();
    let mut map = PublicSentriedMap::new(XorName([1; 32]), 100);

    // no owner
    let data = MapData::from(map.clone());
    assert_eq!(data.is_allowed(AccessType::Insert, public_key_0), false);
    // data is Public - read always allowed
    assert_map_read_permitted(&data, public_key_0, true);

    // no access_list
    unwrap!(map.set_owner(
        Owner {
            public_key: public_key_0,
            expected_data_version: 0,
            expected_access_list_version: 0,
        },
        0,
    ));
    let data = MapData::from(map.clone());

    assert_eq!(data.is_allowed(AccessType::Insert, public_key_0), true);
    assert_eq!(data.is_allowed(AccessType::Insert, public_key_1), false);
    // data is Public - read always allowed
    assert_map_read_permitted(&data, public_key_0, true);
    assert_map_read_permitted(&data, public_key_1, true);

    // with access_list
    let mut access_list = PublicAccessList {
        access_list: BTreeMap::new(),
        expected_data_version: 0,
        expected_owners_version: 1,
    };
    let mut set = BTreeMap::new();
    let _ = set.insert(AccessType::Insert, true);
    let _ = access_list
        .access_list
        .insert(User::Anyone, PublicUserAccess::new(set));
    let mut set = BTreeMap::new();
    let _ = set.insert(AccessType::ModifyPermissions, true);
    let _ = access_list
        .access_list
        .insert(User::Specific(public_key_1), PublicUserAccess::new(set));
    unwrap!(map.set_access_list(&access_list, 0));
    let data = MapData::from(map);

    // existing key fallback
    assert_eq!(data.is_allowed(AccessType::Insert, public_key_1), true);
    // existing key override
    assert_modify_map_access_list_permitted(&data, public_key_1, true);
    // non-existing keys are handled by `Anyone`
    assert_eq!(data.is_allowed(AccessType::Insert, public_key_2), true);
    assert_modify_map_access_list_permitted(&data, public_key_2, false);
    // data is Public - read always allowed
    assert_map_read_permitted(&data, public_key_0, true);
    assert_map_read_permitted(&data, public_key_1, true);
    assert_map_read_permitted(&data, public_key_2, true);
}

#[test]
fn validates_private_map_access_list() {
    let public_key_0 = gen_public_key();
    let public_key_1 = gen_public_key();
    let public_key_2 = gen_public_key();
    let mut map = PrivateSentriedMap::new(XorName([1; 32]), 100);

    // no owner
    let data = MapData::from(map.clone());
    assert_map_read_permitted(&data, public_key_0, false);

    // no access_list
    unwrap!(map.set_owner(
        Owner {
            public_key: public_key_0,
            expected_data_version: 0,
            expected_access_list_version: 0,
        },
        0,
    ));
    let data = MapData::from(map.clone());

    assert_map_read_permitted(&data, public_key_0, true);
    assert_map_read_permitted(&data, public_key_1, false);

    // with access_list
    let mut access_list = PrivateAccessList {
        access_list: BTreeMap::new(),
        expected_data_version: 0,
        expected_owners_version: 1,
    };
    let mut set = BTreeMap::new();
    let _ = set.insert(AccessType::Insert, true);
    let _ = set.insert(AccessType::Read, true);
    let _ = set.insert(AccessType::ModifyPermissions, false);
    let _ = access_list
        .access_list
        .insert(public_key_1, PrivateUserAccess::new(set));
    unwrap!(map.set_access_list(&access_list, 0));
    let data = MapData::from(map);

    // existing key
    assert_map_read_permitted(&data, public_key_1, true);
    assert_eq!(data.is_allowed(AccessType::Insert, public_key_1), true);
    assert_modify_map_access_list_permitted(&data, public_key_1, false);

    // non-existing key
    assert_map_read_permitted(&data, public_key_2, false);
    assert_eq!(data.is_allowed(AccessType::Insert, public_key_2), false);
    assert_modify_map_access_list_permitted(&data, public_key_2, false);
}

fn assert_map_read_permitted(data: &MapData, public_key: PublicKey, permitted: bool) {
    assert_eq!(data.is_allowed(AccessType::Read, public_key), permitted);
}

fn assert_modify_map_access_list_permitted(
    data: &MapData,
    public_key: PublicKey,
    permitted: bool,
) {
    assert_eq!(
        data.is_allowed(AccessType::ModifyPermissions, public_key),
        permitted
    );
}
