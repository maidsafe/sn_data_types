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
    use crate::auth::*;
    use crate::map::*;
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
    fn set_sequence_permissions() {
        let mut data = PrivateSentriedSequence::new(XorName([1; 32]), 10000);
        let auth = PrivateAuth {
            permissions: BTreeMap::new(),
            expected_data_version: 0,
            expected_owners_version: 0,
        };
        // Set the first permissions with correct ExpectedVersions - should pass.
        let res = data.set_auth(&auth, 0);

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }

        // Verify that the permissions are part of the history.
        assert_eq!(
            unwrap!(data.auth_history_range(Version::FromStart(0), Version::FromEnd(0),)).len(),
            1
        );

        let auth = PrivateAuth {
            permissions: BTreeMap::new(),
            expected_data_version: 64,
            expected_owners_version: 0,
        };
        // Set permissions with incorrect ExpectedVersions - should fail.
        let res = data.set_auth(&auth, 1);

        match res {
            Err(_) => (),
            Ok(()) => panic!("Unexpected Ok(()) result"),
        }

        // Verify that the history of permissions remains unchanged.
        assert_eq!(
            unwrap!(data.auth_history_range(Version::FromStart(0), Version::FromEnd(0),)).len(),
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
                expected_auth_version: 0,
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
                expected_auth_version: 0,
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
                expected_auth_version: 0,
            },
            0,
        );

        let _ = data.set_owner(
            Owner {
                public_key: owner_pk1,
                expected_data_version: 0,
                expected_auth_version: 0,
            },
            1,
        );

        assert_eq!(
            data.expected_owners_version(),
            unwrap!(data.shell(0)).expected_owners_version()
        );
    }

    #[test]
    fn can_retrieve_sequence_permissions() {
        let public_key = gen_public_key();
        let invalid_public_key = gen_public_key();

        let mut pub_permissions = PublicAuth {
            permissions: BTreeMap::new(),
            expected_data_version: 0,
            expected_owners_version: 0,
        };
        let _ = pub_permissions.permissions.insert(
            User::Specific(public_key),
            PublicPermissions::new(BTreeMap::new()),
        );

        let mut private_permissions = PrivateAuth {
            permissions: BTreeMap::new(),
            expected_data_version: 0,
            expected_owners_version: 0,
        };
        let _ = private_permissions
            .permissions
            .insert(public_key, PrivatePermissions::new(BTreeMap::new()));

        // public
        let mut data = PublicSequence::new(rand::random(), 20);
        unwrap!(data.set_auth(&pub_permissions, 0));
        let data = SequenceData::from(data);

        assert_eq!(data.public_auth_at(0), Ok(&pub_permissions));
        assert_eq!(data.private_auth_at(0), Err(Error::InvalidOperation));

        assert_eq!(
            data.public_permissions_at(User::Specific(public_key), 0),
            Ok(PublicPermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.private_permissions_at(public_key, 0),
            Err(Error::InvalidOperation)
        );
        assert_eq!(
            data.public_permissions_at(User::Specific(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // public, sentried
        let mut data = PublicSentriedSequence::new(rand::random(), 20);
        unwrap!(data.set_auth(&pub_permissions, 0));
        let data = SequenceData::from(data);

        assert_eq!(data.public_auth_at(0), Ok(&pub_permissions));
        assert_eq!(data.private_auth_at(0), Err(Error::InvalidOperation));

        assert_eq!(
            data.public_permissions_at(User::Specific(public_key), 0),
            Ok(PublicPermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.private_permissions_at(public_key, 0),
            Err(Error::InvalidOperation)
        );
        assert_eq!(
            data.public_permissions_at(User::Specific(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // Private
        let mut data = PrivateSequence::new(rand::random(), 20);
        unwrap!(data.set_auth(&private_permissions, 0));
        let data = SequenceData::from(data);

        assert_eq!(data.private_auth_at(0), Ok(&private_permissions));
        assert_eq!(data.public_auth_at(0), Err(Error::InvalidOperation));

        assert_eq!(
            data.private_permissions_at(public_key, 0),
            Ok(PrivatePermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.public_permissions_at(User::Specific(public_key), 0),
            Err(Error::InvalidOperation)
        );
        assert_eq!(
            data.private_permissions_at(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );

        // Private, seq
        let mut data = PrivateSentriedSequence::new(rand::random(), 20);
        unwrap!(data.set_auth(&private_permissions, 0));
        let data = SequenceData::from(data);

        assert_eq!(data.private_auth_at(0), Ok(&private_permissions));
        assert_eq!(data.public_auth_at(0), Err(Error::InvalidOperation));

        assert_eq!(
            data.private_permissions_at(public_key, 0),
            Ok(PrivatePermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.public_permissions_at(User::Specific(public_key), 0),
            Err(Error::InvalidOperation)
        );
        assert_eq!(
            data.private_permissions_at(invalid_public_key, 0),
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
                expected_data_version: 0,
                expected_auth_version: 0,
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
        let mut permissions = PublicAuth {
            permissions: BTreeMap::new(),
            expected_data_version: 0,
            expected_owners_version: 1,
        };
        let mut set = BTreeMap::new();
        let _ = set.insert(get_append_cmd(), true);
        let _ = permissions
            .permissions
            .insert(User::Anyone, PublicPermissions::new(set));
        let mut set = BTreeMap::new();
        let _ = set.insert(get_modify_sequence_permissions(), true);
        let _ = permissions
            .permissions
            .insert(User::Specific(public_key_1), PublicPermissions::new(set));
        unwrap!(sequence.set_auth(&permissions, 0));
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
                expected_data_version: 0,
                expected_auth_version: 0,
            },
            0,
        ));
        let data = SequenceData::from(sequence.clone());

        assert_sequence_read_permitted(&data, public_key_0, true);
        assert_sequence_read_permitted(&data, public_key_1, false);

        // with permissions
        let mut permissions = PrivateAuth {
            permissions: BTreeMap::new(),
            expected_data_version: 0,
            expected_owners_version: 1,
        };
        let mut set = BTreeMap::new();
        let _ = set.insert(get_append_cmd(), true);
        let _ = set.insert(get_sequence_read_access(), true);
        let _ = set.insert(get_modify_sequence_permissions(), false);
        let _ = permissions
            .permissions
            .insert(public_key_1, PrivatePermissions::new(set));
        unwrap!(sequence.set_auth(&permissions, 0));
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
        AccessType::Write(WriteAccess::Sequence(SequenceWriteAccess::Append))
    }

    fn get_sequence_read_access() -> AccessType {
        AccessType::Read(ReadAccess::Sequence)
    }

    fn get_modify_sequence_permissions() -> AccessType {
        AccessType::Write(WriteAccess::Sequence(
            SequenceWriteAccess::ModifyPermissions,
        ))
    }

    fn assert_sequence_read_permitted(data: &SequenceData, public_key: PublicKey, permitted: bool) {
        assert_eq!(
            data.is_allowed(get_sequence_read_access(), public_key),
            permitted
        );
    }

    fn assert_modify_sequence_permissions_permitted(
        data: &SequenceData,
        public_key: PublicKey,
        permitted: bool,
    ) {
        assert_eq!(
            data.is_allowed(get_modify_sequence_permissions(), public_key),
            permitted
        );
    }

    // ------------------------------------------------------------------------------------------
    // -----------------------------------  MAP  ------------------------------------------------
    // ------------------------------------------------------------------------------------------

    #[test]
    fn set_map_permissions() {
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let auth = PrivateAuth {
            permissions: BTreeMap::new(),
            expected_data_version: 0,
            expected_owners_version: 0,
        };

        // Set the first permission set with correct ExpectedVersions - should pass.
        let res = data.set_auth(&auth, 0);

        match res {
            Ok(()) => (),
            Err(x) => panic!("Unexpected error: {:?}", x),
        }

        // Verify that the permissions are part of the history.
        assert_eq!(
            unwrap!(data.auth_history_range(Version::FromStart(0), Version::FromEnd(0),)).len(),
            1
        );
        let auth = PrivateAuth {
            permissions: BTreeMap::new(),
            expected_data_version: 64,
            expected_owners_version: 0,
        };
        // Set permissions with incorrect ExpectedVersions - should fail.
        let res = data.set_auth(&auth, 1);

        match res {
            Err(_) => (),
            Ok(()) => panic!("Unexpected Ok(()) result"),
        }

        // Verify that the history of permissions remains unchanged.
        assert_eq!(
            unwrap!(data.auth_history_range(Version::FromStart(0), Version::FromEnd(0),)).len(),
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
                expected_auth_version: 0,
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
                expected_auth_version: 0,
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
                expected_auth_version: 0,
            },
            0,
        );

        let _ = data.set_owner(
            Owner {
                public_key: owner_pk1,
                expected_data_version: 0,
                expected_auth_version: 0,
            },
            1,
        );

        assert_eq!(
            data.expected_owners_version(),
            unwrap!(data.shell(0)).expected_owners_version()
        );
    }

    #[test]
    fn can_retrieve_map_permissions() {
        let public_key = gen_public_key();
        let invalid_public_key = gen_public_key();

        let mut pub_permissions = PublicAuth {
            permissions: BTreeMap::new(),
            expected_data_version: 0,
            expected_owners_version: 0,
        };
        let _ = pub_permissions.permissions.insert(
            User::Specific(public_key),
            PublicPermissions::new(BTreeMap::new()),
        );

        let mut private_permissions = PrivateAuth {
            permissions: BTreeMap::new(),
            expected_data_version: 0,
            expected_owners_version: 0,
        };
        let _ = private_permissions
            .permissions
            .insert(public_key, PrivatePermissions::new(BTreeMap::new()));

        // public
        let mut data = PublicMap::new(rand::random(), 20);
        unwrap!(data.set_auth(&pub_permissions, 0));
        let data = MapData::from(data);

        assert_eq!(data.public_auth_at(0), Ok(&pub_permissions));
        assert_eq!(data.private_auth_at(0), Err(Error::InvalidOperation));

        assert_eq!(
            data.public_permissions_at(User::Specific(public_key), 0),
            Ok(PublicPermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.private_permissions_at(public_key, 0),
            Err(Error::InvalidOperation)
        );
        assert_eq!(
            data.public_permissions_at(User::Specific(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // public, sentried
        let mut data = PublicSentriedMap::new(rand::random(), 20);
        unwrap!(data.set_auth(&pub_permissions, 0));
        let data = MapData::from(data);

        assert_eq!(data.public_auth_at(0), Ok(&pub_permissions));
        assert_eq!(data.private_auth_at(0), Err(Error::InvalidOperation));

        assert_eq!(
            data.public_permissions_at(User::Specific(public_key), 0),
            Ok(PublicPermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.private_permissions_at(public_key, 0),
            Err(Error::InvalidOperation)
        );
        assert_eq!(
            data.public_permissions_at(User::Specific(invalid_public_key), 0),
            Err(Error::NoSuchEntry)
        );

        // Private
        let mut data = PrivateMap::new(rand::random(), 20);
        unwrap!(data.set_auth(&private_permissions, 0));
        let data = MapData::from(data);

        assert_eq!(data.private_auth_at(0), Ok(&private_permissions));
        assert_eq!(data.public_auth_at(0), Err(Error::InvalidOperation));

        assert_eq!(
            data.private_permissions_at(public_key, 0),
            Ok(PrivatePermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.public_permissions_at(User::Specific(public_key), 0),
            Err(Error::InvalidOperation)
        );
        assert_eq!(
            data.private_permissions_at(invalid_public_key, 0),
            Err(Error::NoSuchEntry)
        );

        // Private, sentried
        let mut data = PrivateSentriedMap::new(rand::random(), 20);
        unwrap!(data.set_auth(&private_permissions, 0));
        let data = MapData::from(data);

        assert_eq!(data.private_auth_at(0), Ok(&private_permissions));
        assert_eq!(data.public_auth_at(0), Err(Error::InvalidOperation));

        assert_eq!(
            data.private_permissions_at(public_key, 0),
            Ok(PrivatePermissions::new(BTreeMap::new()))
        );
        assert_eq!(
            data.public_permissions_at(User::Specific(public_key), 0),
            Err(Error::InvalidOperation)
        );
        assert_eq!(
            data.private_permissions_at(invalid_public_key, 0),
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
                expected_data_version: 0,
                expected_auth_version: 0,
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
        let mut permissions = PublicAuth {
            permissions: BTreeMap::new(),
            expected_data_version: 0,
            expected_owners_version: 1,
        };
        let mut set = BTreeMap::new();
        let _ = set.insert(get_insert_cmd(), true);
        let _ = permissions
            .permissions
            .insert(User::Anyone, PublicPermissions::new(set));
        let mut set = BTreeMap::new();
        let _ = set.insert(get_modify_map_permissions(), true);
        let _ = permissions
            .permissions
            .insert(User::Specific(public_key_1), PublicPermissions::new(set));
        unwrap!(map.set_auth(&permissions, 0));
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
                expected_data_version: 0,
                expected_auth_version: 0,
            },
            0,
        ));
        let data = MapData::from(map.clone());

        assert_map_read_permitted(&data, public_key_0, true);
        assert_map_read_permitted(&data, public_key_1, false);

        // with permissions
        let mut auth = PrivateAuth {
            permissions: BTreeMap::new(),
            expected_data_version: 0,
            expected_owners_version: 1,
        };
        let mut set = BTreeMap::new();
        let _ = set.insert(get_insert_cmd(), true);
        let _ = set.insert(get_map_read_permissions(), true);
        let _ = set.insert(get_modify_map_permissions(), false);
        let _ = auth
            .permissions
            .insert(public_key_1, PrivatePermissions::new(set));
        unwrap!(map.set_auth(&auth, 0));
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
        AccessType::Write(WriteAccess::Map(MapWriteAccess::Insert))
    }

    fn get_map_read_access() -> AccessType {
        AccessType::Read(ReadAccess::Map)
    }

    fn get_map_read_permissions() -> AccessType {
        AccessType::Read(ReadAccess::Map)
    }

    fn get_modify_map_permissions() -> AccessType {
        AccessType::Write(WriteAccess::Map(MapWriteAccess::ModifyPermissions))
    }

    fn assert_map_read_permitted(data: &MapData, public_key: PublicKey, permitted: bool) {
        assert_eq!(
            data.is_allowed(get_map_read_access(), public_key),
            permitted
        );
    }

    fn assert_modify_map_permissions_permitted(
        data: &MapData,
        public_key: PublicKey,
        permitted: bool,
    ) {
        assert_eq!(
            data.is_allowed(get_modify_map_permissions(), public_key),
            permitted
        );
    }
}
