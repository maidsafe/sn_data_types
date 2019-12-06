// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#[cfg(test)]
mod tests {
    // pub use access_control::{
    //     MapWriteAccess, DataAccessControl, HardErasureAccess, MapWriteAccessModification,
    //     SequencePermissionModificationAccess, PrivateAccessControl, PrivateAccessControl, PublicAccessControl,
    //     PublicAccessControl, ReadAccess, AccessType, SequenceWriteAccess,
    // };
    use crate::access_control::*;
    // {
    //     HardErasureAccess, MapWriteAccess, MapWriteAccessModification,
    //     SequencePermissionModificationAccess, PrivatePermissions, PrivateAccessControl,
    //     PublicPermissions, PublicAccessControl, ReadAccess, AccessType, SequenceWriteAccess, DataStructReadAccess, DataStructWriteAccess
    // };
    use crate::map::*;
    use crate::sequence::*;
    use crate::shared_data::{Index, Owner, User};
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
    fn set_sequence_permissions() {
        let mut data = PrivateSentriedSequence::new(XorName([1; 32]), 10000);

        // Set the first permissions with correct ExpectedIndices - should pass.
        let res = data.set_permissions(
            PrivateAccessControl {
                permissions: BTreeMap::new(),
                expected_data_index: 0,
                expected_owners_index: 0,
            },
            0,
        );

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }

        // Verify that the permissions are part of the history.
        assert_eq!(
            unwrap!(data.permission_history_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );

        // Set permissions with incorrect ExpectedIndices - should fail.
        let res = data.set_permissions(
            PrivateAccessControl {
                permissions: BTreeMap::new(),
                expected_data_index: 64,
                expected_owners_index: 0,
            },
            1,
        );

        match res {
            Err(_) => (),
            Ok(()) => panic!("Unexpected Ok(()) result"),
        }

        // Verify that the history of permissions remains unchanged.
        assert_eq!(
            unwrap!(data.permission_history_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );
    }

    #[test]
    fn set_sequence_owners() {
        let owner_pk = gen_public_key();

        let mut data = PrivateSentriedSequence::new(XorName([1; 32]), 10000);

        // Set the first owner with correct ExpectedIndices - should pass.
        let res = data.set_owner(
            Owner {
                public_key: owner_pk,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        );

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }

        // Verify that the owner is part of the history.
        assert_eq!(
            unwrap!(data.owner_history_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );

        // Set owner with incorrect ExpectedIndices - should fail.
        let res = data.set_owner(
            Owner {
                public_key: owner_pk,
                expected_data_index: 64,
                expected_permissions_index: 0,
            },
            1,
        );

        match res {
            Err(_) => (),
            Ok(()) => panic!("Unexpected Ok(()) result"),
        }

        // Verify that the history of owners remains unchanged.
        assert_eq!(
            unwrap!(data.owner_history_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
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
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        );

        let _ = data.set_owner(
            Owner {
                public_key: owner_pk1,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            1,
        );

        assert_eq!(
            data.expected_owners_index(),
            unwrap!(data.shell(0)).expected_owners_index()
        );
    }

    #[test]
    fn can_retrieve_sequence_permissions() {
        let public_key = gen_public_key();
        let invalid_public_key = gen_public_key();

        let mut pub_permissions = PublicAccessControl {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 0,
        };
        let _ = pub_permissions.permissions.insert(
            User::Specific(public_key),
            PublicPermissions::new(BTreeMap::new()),
        );

        let mut private_permissions = PrivateAccessControl {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 0,
        };
        let _ = private_permissions
            .permissions
            .insert(public_key, PrivatePermissions::new(BTreeMap::new()));

        // pub, unseq
        let mut data = PublicSequence::new(rand::random(), 20);
        unwrap!(data.set_permissions(pub_permissions.clone(), 0));
        let data = SequenceData::from(data);

        assert_eq!(data.public_permissions_at(0), Ok(&pub_permissions));
        assert_eq!(data.private_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Ok(PublicPermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.public_user_permissions_at(User::Specific(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // pub, seq
        let mut data = PublicSentriedSequence::new(rand::random(), 20);
        unwrap!(data.set_permissions(pub_permissions.clone(), 0));
        let data = SequenceData::from(data);

        assert_eq!(data.public_permissions_at(0), Ok(&pub_permissions));
        assert_eq!(data.private_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Ok(PublicPermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.public_user_permissions_at(User::Specific(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // Private, unseq
        let mut data = PrivateSequence::new(rand::random(), 20);
        unwrap!(data.set_permissions(private_permissions.clone(), 0));
        let data = SequenceData::from(data);

        assert_eq!(data.private_permissions_at(0), Ok(&private_permissions));
        assert_eq!(data.public_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Ok(PrivatePermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.private_user_permissions_at(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );

        // Private, seq
        let mut data = PrivateSentriedSequence::new(rand::random(), 20);
        unwrap!(data.set_permissions(private_permissions.clone(), 0));
        let data = SequenceData::from(data);

        assert_eq!(data.private_permissions_at(0), Ok(&private_permissions));
        assert_eq!(data.public_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Ok(PrivatePermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.private_user_permissions_at(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );
    }

    #[test]
    fn validates_public_sequence_permissions() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut sequence = PublicSentriedSequence::new(XorName([1; 32]), 100);

        // no owner
        let data = SequenceData::from(sequence.clone());
        assert_eq!(data.is_allowed(get_append_cmd(), public_key_0), false);
        // data is Public - read always allowed
        assert_sequence_read_permitted(&data, public_key_0, true);

        // no permissions
        unwrap!(sequence.set_owner(
            Owner {
                public_key: public_key_0,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        ));
        let data = SequenceData::from(sequence.clone());

        assert_eq!(data.is_allowed(get_append_cmd(), public_key_0), true);
        assert_eq!(data.is_allowed(get_append_cmd(), public_key_1), false);
        // data is Public - read always allowed
        assert_sequence_read_permitted(&data, public_key_0, true);
        assert_sequence_read_permitted(&data, public_key_1, true);

        // with permissions
        let mut permissions = PublicAccessControl {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 1,
        };
        let mut set = BTreeMap::new();
        let _ = set.insert(get_append_cmd(), true);
        let _ = permissions
            .permissions
            .insert(User::Anyone, PublicPermissions::new(set));
        let mut set = BTreeMap::new();
        for cmd in get_full_modify_sequence_permissions() {
            let _ = set.insert(cmd, true);
        }
        let _ = permissions
            .permissions
            .insert(User::Specific(public_key_1), PublicPermissions::new(set));
        unwrap!(sequence.set_permissions(permissions, 0));
        let data = SequenceData::from(sequence);

        // existing key fallback
        assert_eq!(data.is_allowed(get_append_cmd(), public_key_1), true);
        // existing key override
        assert_modify_sequence_permissions_permitted(&data, public_key_1, true);
        // non-existing keys are handled by `Anyone`
        assert_eq!(data.is_allowed(get_append_cmd(), public_key_2), true);
        assert_modify_sequence_permissions_permitted(&data, public_key_2, false);
        // data is Public - read always allowed
        assert_sequence_read_permitted(&data, public_key_0, true);
        assert_sequence_read_permitted(&data, public_key_1, true);
        assert_sequence_read_permitted(&data, public_key_2, true);
    }

    #[test]
    fn validates_private_sequence_permissions() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut sequence = PrivateSentriedSequence::new(XorName([1; 32]), 100);

        // no owner
        let data = SequenceData::from(sequence.clone());
        assert_sequence_read_permitted(&data, public_key_0, false);

        // no permissions
        unwrap!(sequence.set_owner(
            Owner {
                public_key: public_key_0,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        ));
        let data = SequenceData::from(sequence.clone());

        assert_sequence_read_permitted(&data, public_key_0, true);
        assert_sequence_read_permitted(&data, public_key_1, false);

        // with permissions
        let mut permissions = PrivateAccessControl {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 1,
        };
        let mut set = BTreeMap::new();
        let _ = set.insert(get_append_cmd(), true);
        for query in get_full_sequence_read_permissions() {
            let _ = set.insert(query, true);
        }
        for cmd in get_full_modify_sequence_permissions() {
            let _ = set.insert(cmd, false);
        }
        let _ = permissions
            .permissions
            .insert(public_key_1, PrivatePermissions::new(set));
        unwrap!(sequence.set_permissions(permissions, 0));
        let data = SequenceData::from(sequence);

        // existing key
        assert_sequence_read_permitted(&data, public_key_1, true);
        assert_eq!(data.is_allowed(get_append_cmd(), public_key_1), true);
        assert_modify_sequence_permissions_permitted(&data, public_key_1, false);

        // non-existing key
        assert_sequence_read_permitted(&data, public_key_2, false);
        assert_eq!(data.is_allowed(get_append_cmd(), public_key_2), false);
        assert_modify_sequence_permissions_permitted(&data, public_key_2, false);
    }

    fn get_append_cmd() -> AccessType {
        AccessType::Write(DataStructWriteAccess::Sequence(SequenceWriteAccess::Append))
    }

    fn get_sequence_read_access(access: ReadAccess) -> AccessType {
        AccessType::Read(DataStructReadAccess::Sequence(access))
    }

    fn get_full_sequence_read_permissions() -> Vec<AccessType> {
        vec![
            AccessType::Read(DataStructReadAccess::Sequence(ReadAccess::Data)),
            AccessType::Read(DataStructReadAccess::Sequence(ReadAccess::Owners)),
            AccessType::Read(DataStructReadAccess::Sequence(ReadAccess::Permissions)),
        ]
    }

    fn get_modify_sequence_permissions(
        permission: SequencePermissionModificationAccess,
    ) -> AccessType {
        AccessType::Write(DataStructWriteAccess::Sequence(
            SequenceWriteAccess::ModifyPermissions(permission),
        ))
    }

    fn get_full_modify_sequence_permissions() -> Vec<AccessType> {
        vec![
            AccessType::Write(DataStructWriteAccess::Sequence(
                SequenceWriteAccess::ModifyPermissions(SequencePermissionModificationAccess::Read(
                    ReadAccess::Data,
                )),
            )),
            AccessType::Write(DataStructWriteAccess::Sequence(
                SequenceWriteAccess::ModifyPermissions(SequencePermissionModificationAccess::Read(
                    ReadAccess::Owners,
                )),
            )),
            AccessType::Write(DataStructWriteAccess::Sequence(
                SequenceWriteAccess::ModifyPermissions(SequencePermissionModificationAccess::Read(
                    ReadAccess::Permissions,
                )),
            )),
            AccessType::Write(DataStructWriteAccess::Sequence(
                SequenceWriteAccess::ModifyPermissions(
                    SequencePermissionModificationAccess::Write(
                        SequenceWriteAccessModification::Append,
                    ),
                ),
            )),
            AccessType::Write(DataStructWriteAccess::Sequence(
                SequenceWriteAccess::ModifyPermissions(
                    SequencePermissionModificationAccess::Write(
                        SequenceWriteAccessModification::ModifyPermissions,
                    ),
                ),
            )),
            AccessType::Write(DataStructWriteAccess::Sequence(
                SequenceWriteAccess::ModifyPermissions(
                    SequencePermissionModificationAccess::Write(
                        SequenceWriteAccessModification::HardErasure(HardErasureAccess::HardDelete),
                    ),
                ),
            )),
            AccessType::Write(DataStructWriteAccess::Sequence(
                SequenceWriteAccess::ModifyPermissions(
                    SequencePermissionModificationAccess::Write(
                        SequenceWriteAccessModification::HardErasure(HardErasureAccess::HardUpdate),
                    ),
                ),
            )),
        ]
    }

    fn assert_sequence_read_permitted(data: &SequenceData, public_key: PublicKey, permitted: bool) {
        assert_eq!(
            data.is_allowed(get_sequence_read_access(ReadAccess::Data), public_key),
            permitted
        );
        assert_eq!(
            data.is_allowed(get_sequence_read_access(ReadAccess::Owners), public_key),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_sequence_read_access(ReadAccess::Permissions),
                public_key
            ),
            permitted
        );
    }

    fn assert_modify_sequence_permissions_permitted(
        data: &SequenceData,
        public_key: PublicKey,
        permitted: bool,
    ) {
        assert_eq!(
            data.is_allowed(
                get_modify_sequence_permissions(SequencePermissionModificationAccess::Read(
                    ReadAccess::Data
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_sequence_permissions(SequencePermissionModificationAccess::Read(
                    ReadAccess::Owners
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_sequence_permissions(SequencePermissionModificationAccess::Read(
                    ReadAccess::Permissions
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_sequence_permissions(SequencePermissionModificationAccess::Write(
                    SequenceWriteAccessModification::Append
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_sequence_permissions(SequencePermissionModificationAccess::Write(
                    SequenceWriteAccessModification::ModifyPermissions
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_sequence_permissions(SequencePermissionModificationAccess::Write(
                    SequenceWriteAccessModification::HardErasure(HardErasureAccess::HardDelete)
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_sequence_permissions(SequencePermissionModificationAccess::Write(
                    SequenceWriteAccessModification::HardErasure(HardErasureAccess::HardUpdate)
                )),
                public_key
            ),
            permitted
        );
    }

    // ------------------------------------------------------------------------------------------
    // -----------------------------------  MAP  ------------------------------------------------
    // ------------------------------------------------------------------------------------------

    #[test]
    fn set_map_permissions() {
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);

        // Set the first permission set with correct ExpectedIndices - should pass.
        let res = data.set_permissions(
            PrivateAccessControl {
                permissions: BTreeMap::new(),
                expected_data_index: 0,
                expected_owners_index: 0,
            },
            0,
        );

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }

        // Verify that the permissions are part of the history.
        assert_eq!(
            unwrap!(data.permission_history_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );

        // Set permissions with incorrect ExpectedIndices - should fail.
        let res = data.set_permissions(
            PrivateAccessControl {
                permissions: BTreeMap::new(),
                expected_data_index: 64,
                expected_owners_index: 0,
            },
            1,
        );

        match res {
            Err(_) => (),
            Ok(()) => panic!("Unexpected Ok(()) result"),
        }

        // Verify that the history of permissions remains unchanged.
        assert_eq!(
            unwrap!(data.permission_history_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );
    }

    #[test]
    fn set_map_owner() {
        let owner_pk = gen_public_key();

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);

        // Set the first owner with correct ExpectedIndices - should pass.
        let res = data.set_owner(
            Owner {
                public_key: owner_pk,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        );

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }

        // Verify that the owner is part of history.
        assert_eq!(
            unwrap!(data.owner_history_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
            1
        );

        // Set new owner with incorrect ExpectedIndices - should fail.
        let res = data.set_owner(
            Owner {
                public_key: owner_pk,
                expected_data_index: 64,
                expected_permissions_index: 0,
            },
            1,
        );

        match res {
            Err(_) => (),
            Ok(()) => panic!("Unexpected Ok(()) result"),
        }

        // Verify that the history of owners remains unchanged.
        assert_eq!(
            unwrap!(data.owner_history_range(Index::FromStart(0), Index::FromEnd(0),)).len(),
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
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        );

        let _ = data.set_owner(
            Owner {
                public_key: owner_pk1,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            1,
        );

        assert_eq!(
            data.expected_owners_index(),
            unwrap!(data.shell(0)).expected_owners_index()
        );
    }

    #[test]
    fn can_retrieve_map_permissions() {
        let public_key = gen_public_key();
        let invalid_public_key = gen_public_key();

        let mut pub_permissions = PublicAccessControl {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 0,
        };
        let _ = pub_permissions.permissions.insert(
            User::Specific(public_key),
            PublicPermissions::new(BTreeMap::new()),
        );

        let mut private_permissions = PrivateAccessControl {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 0,
        };
        let _ = private_permissions
            .permissions
            .insert(public_key, PrivatePermissions::new(BTreeMap::new()));

        // pub, unseq
        let mut data = PublicMap::new(rand::random(), 20);
        unwrap!(data.set_permissions(pub_permissions.clone(), 0));
        let data = MapData::from(data);

        assert_eq!(data.public_permissions_at(0), Ok(&pub_permissions));
        assert_eq!(data.private_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Ok(PublicPermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.public_user_permissions_at(User::Specific(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // pub, seq
        let mut data = PublicSentriedMap::new(rand::random(), 20);
        unwrap!(data.set_permissions(pub_permissions.clone(), 0));
        let data = MapData::from(data);

        assert_eq!(data.public_permissions_at(0), Ok(&pub_permissions));
        assert_eq!(data.private_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Ok(PublicPermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.public_user_permissions_at(User::Specific(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // Private, unseq
        let mut data = PrivateMap::new(rand::random(), 20);
        unwrap!(data.set_permissions(private_permissions.clone(), 0));
        let data = MapData::from(data);

        assert_eq!(data.private_permissions_at(0), Ok(&private_permissions));
        assert_eq!(data.public_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Ok(PrivatePermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.private_user_permissions_at(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );

        // Private, sentried
        let mut data = PrivateSentriedMap::new(rand::random(), 20);
        unwrap!(data.set_permissions(private_permissions.clone(), 0));
        let data = MapData::from(data);

        assert_eq!(data.private_permissions_at(0), Ok(&private_permissions));
        assert_eq!(data.public_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Ok(PrivatePermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Err(Error::NoSuchData)
        );
        assert_eq!(
            data.private_user_permissions_at(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );
    }

    #[test]
    fn validates_public_map_permissions() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut map = PublicSentriedMap::new(XorName([1; 32]), 100);

        // no owner
        let data = MapData::from(map.clone());
        assert_eq!(data.is_allowed(get_insert_cmd(), public_key_0), false);
        // data is Public - read always allowed
        assert_map_read_permitted(&data, public_key_0, true);

        // no permissions
        unwrap!(map.set_owner(
            Owner {
                public_key: public_key_0,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        ));
        let data = MapData::from(map.clone());

        assert_eq!(data.is_allowed(get_insert_cmd(), public_key_0), true);
        assert_eq!(data.is_allowed(get_insert_cmd(), public_key_1), false);
        // data is Public - read always allowed
        assert_map_read_permitted(&data, public_key_0, true);
        assert_map_read_permitted(&data, public_key_1, true);

        // with permissions
        let mut permissions = PublicAccessControl {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 1,
        };
        let mut set = BTreeMap::new();
        let _ = set.insert(get_insert_cmd(), true);
        let _ = permissions
            .permissions
            .insert(User::Anyone, PublicPermissions::new(set));
        let mut set = BTreeMap::new();
        for cmd in get_full_modify_map_permissions() {
            let _ = set.insert(cmd, true);
        }
        let _ = permissions
            .permissions
            .insert(User::Specific(public_key_1), PublicPermissions::new(set));
        unwrap!(map.set_permissions(permissions, 0));
        let data = MapData::from(map);

        // existing key fallback
        assert_eq!(data.is_allowed(get_insert_cmd(), public_key_1), true);
        // existing key override
        assert_modify_map_permissions_permitted(&data, public_key_1, true);
        // non-existing keys are handled by `Anyone`
        assert_eq!(data.is_allowed(get_insert_cmd(), public_key_2), true);
        assert_modify_map_permissions_permitted(&data, public_key_2, false);
        // data is Public - read always allowed
        assert_map_read_permitted(&data, public_key_0, true);
        assert_map_read_permitted(&data, public_key_1, true);
        assert_map_read_permitted(&data, public_key_2, true);
    }

    #[test]
    fn validates_private_map_permissions() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut map = PrivateSentriedMap::new(XorName([1; 32]), 100);

        // no owner
        let data = MapData::from(map.clone());
        assert_map_read_permitted(&data, public_key_0, false);

        // no permissions
        unwrap!(map.set_owner(
            Owner {
                public_key: public_key_0,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        ));
        let data = MapData::from(map.clone());

        assert_map_read_permitted(&data, public_key_0, true);
        assert_map_read_permitted(&data, public_key_1, false);

        // with permissions
        let mut permissions = PrivateAccessControl {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 1,
        };
        let mut set = BTreeMap::new();
        let _ = set.insert(get_insert_cmd(), true);
        for query in get_full_map_read_permissions() {
            let _ = set.insert(query, true);
        }
        for cmd in get_full_modify_map_permissions() {
            let _ = set.insert(cmd, false);
        }
        let _ = permissions
            .permissions
            .insert(public_key_1, PrivatePermissions::new(set));
        unwrap!(map.set_permissions(permissions, 0));
        let data = MapData::from(map);

        // existing key
        assert_map_read_permitted(&data, public_key_1, true);
        assert_eq!(data.is_allowed(get_insert_cmd(), public_key_1), true);
        assert_modify_map_permissions_permitted(&data, public_key_1, false);

        // non-existing key
        assert_map_read_permitted(&data, public_key_2, false);
        assert_eq!(data.is_allowed(get_insert_cmd(), public_key_2), false);
        assert_modify_map_permissions_permitted(&data, public_key_2, false);
    }

    fn get_insert_cmd() -> AccessType {
        AccessType::Write(DataStructWriteAccess::Map(MapWriteAccess::Insert))
    }

    fn get_map_read_access(access: ReadAccess) -> AccessType {
        AccessType::Read(DataStructReadAccess::Map(access))
    }

    fn get_full_map_read_permissions() -> Vec<AccessType> {
        vec![
            AccessType::Read(DataStructReadAccess::Map(ReadAccess::Data)),
            AccessType::Read(DataStructReadAccess::Map(ReadAccess::Owners)),
            AccessType::Read(DataStructReadAccess::Map(ReadAccess::Permissions)),
        ]
    }

    fn get_modify_map_permissions(access: MapPermissionModificationAccess) -> AccessType {
        AccessType::Write(DataStructWriteAccess::Map(
            MapWriteAccess::ModifyPermissions(access),
        ))
    }

    fn get_full_modify_map_permissions() -> Vec<AccessType> {
        vec![
            AccessType::Write(DataStructWriteAccess::Map(
                MapWriteAccess::ModifyPermissions(MapPermissionModificationAccess::Read(
                    ReadAccess::Data,
                )),
            )),
            AccessType::Write(DataStructWriteAccess::Map(
                MapWriteAccess::ModifyPermissions(MapPermissionModificationAccess::Read(
                    ReadAccess::Owners,
                )),
            )),
            AccessType::Write(DataStructWriteAccess::Map(
                MapWriteAccess::ModifyPermissions(MapPermissionModificationAccess::Read(
                    ReadAccess::Permissions,
                )),
            )),
            AccessType::Write(DataStructWriteAccess::Map(
                MapWriteAccess::ModifyPermissions(MapPermissionModificationAccess::Write(
                    MapWriteAccessModification::Insert,
                )),
            )),
            AccessType::Write(DataStructWriteAccess::Map(
                MapWriteAccess::ModifyPermissions(MapPermissionModificationAccess::Write(
                    MapWriteAccessModification::Update,
                )),
            )),
            AccessType::Write(DataStructWriteAccess::Map(
                MapWriteAccess::ModifyPermissions(MapPermissionModificationAccess::Write(
                    MapWriteAccessModification::Delete,
                )),
            )),
            AccessType::Write(DataStructWriteAccess::Map(
                MapWriteAccess::ModifyPermissions(MapPermissionModificationAccess::Write(
                    MapWriteAccessModification::ModifyPermissions,
                )),
            )),
            AccessType::Write(DataStructWriteAccess::Map(
                MapWriteAccess::ModifyPermissions(MapPermissionModificationAccess::Write(
                    MapWriteAccessModification::HardErasure(HardErasureAccess::HardDelete),
                )),
            )),
            AccessType::Write(DataStructWriteAccess::Map(
                MapWriteAccess::ModifyPermissions(MapPermissionModificationAccess::Write(
                    MapWriteAccessModification::HardErasure(HardErasureAccess::HardUpdate),
                )),
            )),
        ]
    }

    fn assert_map_read_permitted(data: &MapData, public_key: PublicKey, permitted: bool) {
        assert_eq!(
            data.is_allowed(get_map_read_access(ReadAccess::Data), public_key),
            permitted
        );
        assert_eq!(
            data.is_allowed(get_map_read_access(ReadAccess::Owners), public_key),
            permitted
        );
        assert_eq!(
            data.is_allowed(get_map_read_access(ReadAccess::Permissions), public_key),
            permitted
        );
    }

    fn assert_modify_map_permissions_permitted(
        data: &MapData,
        public_key: PublicKey,
        permitted: bool,
    ) {
        assert_eq!(
            data.is_allowed(
                get_modify_map_permissions(MapPermissionModificationAccess::Read(ReadAccess::Data)),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_map_permissions(MapPermissionModificationAccess::Read(
                    ReadAccess::Owners
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_map_permissions(MapPermissionModificationAccess::Read(
                    ReadAccess::Permissions
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_map_permissions(MapPermissionModificationAccess::Write(
                    MapWriteAccessModification::Insert
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_map_permissions(MapPermissionModificationAccess::Write(
                    MapWriteAccessModification::Update
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_map_permissions(MapPermissionModificationAccess::Write(
                    MapWriteAccessModification::Delete
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_map_permissions(MapPermissionModificationAccess::Write(
                    MapWriteAccessModification::ModifyPermissions
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_map_permissions(MapPermissionModificationAccess::Write(
                    MapWriteAccessModification::HardErasure(HardErasureAccess::HardDelete)
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_allowed(
                get_modify_map_permissions(MapPermissionModificationAccess::Write(
                    MapWriteAccessModification::HardErasure(HardErasureAccess::HardUpdate)
                )),
                public_key
            ),
            permitted
        );
    }
}
