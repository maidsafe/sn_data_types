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
    use std::collections::BTreeMap;
    use threshold_crypto::SecretKey;
    //use unwrap::{unwrap, unwrap_err};
    use crate::permissions::{
        CmdType, HardErasureCmd, ModifyableSequencePermissions, PrivatePermissionSet,
        PrivatePermissions, PublicPermissionSet, PublicPermissions, QueryType, Request,
        SequenceCmd, SequenceQuery, SequenceWrite,
    };
    use crate::sequence::*;
    use crate::shared_data::{Address, Index, Owner, User};
    use crate::{Error, PublicKey, XorName};
    use unwrap::unwrap;

    pub fn get_append_cmd() -> Request {
        Request::Cmd(CmdType::Sequence(SequenceCmd::Append))
    }

    fn get_read_query(query: SequenceQuery) -> Request {
        Request::Query(QueryType::Sequence(query))
    }

    fn get_full_read_permissions() -> Vec<Request> {
        vec![
            Request::Query(QueryType::Sequence(SequenceQuery::ReadData)),
            Request::Query(QueryType::Sequence(SequenceQuery::ReadOwners)),
            Request::Query(QueryType::Sequence(SequenceQuery::ReadPermissions)),
        ]
    }

    fn get_modify_permissions(permission: ModifyableSequencePermissions) -> Request {
        Request::Cmd(CmdType::Sequence(SequenceCmd::ModifyPermissions(
            permission,
        )))
    }

    fn get_full_modify_permissions() -> Vec<Request> {
        vec![
            Request::Cmd(CmdType::Sequence(SequenceCmd::ModifyPermissions(
                ModifyableSequencePermissions::ReadData,
            ))),
            Request::Cmd(CmdType::Sequence(SequenceCmd::ModifyPermissions(
                ModifyableSequencePermissions::ReadOwners,
            ))),
            Request::Cmd(CmdType::Sequence(SequenceCmd::ModifyPermissions(
                ModifyableSequencePermissions::ReadPermissions,
            ))),
            Request::Cmd(CmdType::Sequence(SequenceCmd::ModifyPermissions(
                ModifyableSequencePermissions::Write(SequenceWrite::Append),
            ))),
            Request::Cmd(CmdType::Sequence(SequenceCmd::ModifyPermissions(
                ModifyableSequencePermissions::Write(SequenceWrite::ModifyPermissions),
            ))),
            Request::Cmd(CmdType::Sequence(SequenceCmd::ModifyPermissions(
                ModifyableSequencePermissions::Write(SequenceWrite::HardErasure(
                    HardErasureCmd::HardDelete,
                )),
            ))),
            Request::Cmd(CmdType::Sequence(SequenceCmd::ModifyPermissions(
                ModifyableSequencePermissions::Write(SequenceWrite::HardErasure(
                    HardErasureCmd::HardUpdate,
                )),
            ))),
        ]
    }

    pub fn assert_read_permitted(data: &Data, public_key: PublicKey, permitted: bool) {
        assert_eq!(
            data.is_permitted(get_read_query(SequenceQuery::ReadData), public_key),
            permitted
        );
        assert_eq!(
            data.is_permitted(get_read_query(SequenceQuery::ReadOwners), public_key),
            permitted
        );
        assert_eq!(
            data.is_permitted(get_read_query(SequenceQuery::ReadPermissions), public_key),
            permitted
        );
    }

    pub fn assert_modify_permissions_permitted(
        data: &Data,
        public_key: PublicKey,
        permitted: bool,
    ) {
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableSequencePermissions::ReadData),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableSequencePermissions::ReadOwners),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableSequencePermissions::ReadPermissions),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableSequencePermissions::Write(SequenceWrite::Append)),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableSequencePermissions::Write(
                    SequenceWrite::ModifyPermissions
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableSequencePermissions::Write(
                    SequenceWrite::HardErasure(HardErasureCmd::HardDelete)
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableSequencePermissions::Write(
                    SequenceWrite::HardErasure(HardErasureCmd::HardUpdate)
                )),
                public_key
            ),
            permitted
        );
    }

    #[test]
    fn set_permissions() {
        let mut data = PrivateSentriedSequence::new(XorName([1; 32]), 10000);

        // Set the first permissions with correct ExpectedIndices - should pass.
        let res = data.set_permissions(
            PrivatePermissions {
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
            PrivatePermissions {
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
    fn set_owners() {
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
    fn append_sentried_data() {
        let mut data = PublicSentriedSequence::new(XorName([1; 32]), 10000);
        unwrap!(data.append(vec![b"hello".to_vec(), b"world".to_vec()], 0));
    }

    #[test]
    fn assert_shell() {
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
    fn zbase32_encode_decode_adata_address() {
        let name = XorName(rand::random());
        let address = Address::PrivateSentried { name, tag: 15000 };
        let encoded = address.encode_to_zbase32();
        let decoded = unwrap!(self::Address::decode_from_zbase32(&encoded));
        assert_eq!(address, decoded);
    }

    #[test]
    fn append_private_data() {
        let mut data = PrivateSequence::new(XorName(rand::random()), 10);

        // Assert that the Values are appended.
        let values1 = vec![
            b"KEY1".to_vec(),
            b"VALUE1".to_vec(),
            b"KEY2".to_vec(),
            b"VALUE2".to_vec(),
        ];

        unwrap!(data.append(values1));
    }

    #[test]
    fn append_private_sentried_data() {
        let mut data = PrivateSentriedSequence::new(XorName(rand::random()), 10);

        // Assert that the values are appended.
        let values1 = vec![
            b"KEY1".to_vec(),
            b"VALUE1".to_vec(),
            b"KEY2".to_vec(),
            b"VALUE2".to_vec(),
        ];
        unwrap!(data.append(values1, 0));
    }

    #[test]
    fn in_range() {
        let mut data = PublicSentriedSequence::new(rand::random(), 10);
        let values = vec![
            b"key0".to_vec(),
            b"value0".to_vec(),
            b"key1".to_vec(),
            b"value1".to_vec(),
        ];
        unwrap!(data.append(values, 0));

        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromStart(0)),
            Some(vec![])
        );
        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromStart(2)),
            Some(vec![b"key0".to_vec(), b"value0".to_vec()])
        );
        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromStart(4)),
            Some(vec![
                b"key0".to_vec(),
                b"value0".to_vec(),
                b"key1".to_vec(),
                b"value1".to_vec(),
            ])
        );

        assert_eq!(
            data.in_range(Index::FromEnd(4), Index::FromEnd(2)),
            Some(vec![b"key0".to_vec(), b"value0".to_vec(),])
        );
        assert_eq!(
            data.in_range(Index::FromEnd(4), Index::FromEnd(0)),
            Some(vec![
                b"key0".to_vec(),
                b"value0".to_vec(),
                b"key1".to_vec(),
                b"value1".to_vec(),
            ])
        );

        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromEnd(0)),
            Some(vec![
                b"key0".to_vec(),
                b"value0".to_vec(),
                b"key1".to_vec(),
                b"value1".to_vec(),
            ])
        );

        // start > end
        assert_eq!(
            data.in_range(Index::FromStart(1), Index::FromStart(0)),
            None
        );
        assert_eq!(data.in_range(Index::FromEnd(1), Index::FromEnd(2)), None);

        // overflow
        assert_eq!(
            data.in_range(Index::FromStart(0), Index::FromStart(5)),
            None
        );
        assert_eq!(data.in_range(Index::FromEnd(5), Index::FromEnd(0)), None);
    }

    #[test]
    fn can_retrieve_permissions() {
        let public_key = gen_public_key();
        let invalid_public_key = gen_public_key();

        let mut pub_permissions = PublicPermissions {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 0,
        };
        let _ = pub_permissions.permissions.insert(
            User::Specific(public_key),
            PublicPermissionSet::new(BTreeMap::new()),
        );

        let mut private_permissions = PrivatePermissions {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 0,
        };
        let _ = private_permissions
            .permissions
            .insert(public_key, PrivatePermissionSet::new(BTreeMap::new()));

        // pub, unseq
        let mut data = PublicSequence::new(rand::random(), 20);
        unwrap!(data.set_permissions(pub_permissions.clone(), 0));
        let data = Data::from(data);

        assert_eq!(data.public_permissions_at(0), Ok(&pub_permissions));
        assert_eq!(data.private_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Ok(PublicPermissionSet::new(BTreeMap::new()))
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
        let data = Data::from(data);

        assert_eq!(data.public_permissions_at(0), Ok(&pub_permissions));
        assert_eq!(data.private_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.public_user_permissions_at(User::Specific(public_key), 0),
            Ok(PublicPermissionSet::new(BTreeMap::new()))
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
        let data = Data::from(data);

        assert_eq!(data.private_permissions_at(0), Ok(&private_permissions));
        assert_eq!(data.public_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Ok(PrivatePermissionSet::new(BTreeMap::new()))
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
        let data = Data::from(data);

        assert_eq!(data.private_permissions_at(0), Ok(&private_permissions));
        assert_eq!(data.public_permissions_at(0), Err(Error::NoSuchData));

        assert_eq!(
            data.private_user_permissions_at(public_key, 0),
            Ok(PrivatePermissionSet::new(BTreeMap::new()))
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

    fn gen_public_key() -> PublicKey {
        PublicKey::Bls(SecretKey::random().public_key())
    }

    #[test]
    fn validates_public_permissions() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut map = PublicSentriedSequence::new(XorName([1; 32]), 100);

        // no owner
        let data = Data::from(map.clone());
        assert_eq!(data.is_permitted(get_append_cmd(), public_key_0), false);
        // data is Public - read always allowed
        assert_read_permitted(&data, public_key_0, true);

        // no permissions
        unwrap!(map.set_owner(
            Owner {
                public_key: public_key_0,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        ));
        let data = Data::from(map.clone());

        assert_eq!(data.is_permitted(get_append_cmd(), public_key_0), true);
        assert_eq!(data.is_permitted(get_append_cmd(), public_key_1), false);
        // data is Public - read always allowed
        assert_read_permitted(&data, public_key_0, true);
        assert_read_permitted(&data, public_key_1, true);

        // with permissions
        let mut permissions = PublicPermissions {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 1,
        };
        let mut set = BTreeMap::new();
        let _ = set.insert(get_append_cmd(), true);
        let _ = permissions
            .permissions
            .insert(User::Anyone, PublicPermissionSet::new(set));
        let mut set = BTreeMap::new();
        for cmd in get_full_modify_permissions() {
            let _ = set.insert(cmd, true);
        }
        let _ = permissions
            .permissions
            .insert(User::Specific(public_key_1), PublicPermissionSet::new(set));
        unwrap!(map.set_permissions(permissions, 0));
        let data = Data::from(map);

        // existing key fallback
        assert_eq!(data.is_permitted(get_append_cmd(), public_key_1), true);
        // existing key override
        assert_modify_permissions_permitted(&data, public_key_1, true);
        // non-existing keys are handled by `Anyone`
        assert_eq!(data.is_permitted(get_append_cmd(), public_key_2), true);
        assert_modify_permissions_permitted(&data, public_key_2, false);
        // data is Public - read always allowed
        assert_read_permitted(&data, public_key_0, true);
        assert_read_permitted(&data, public_key_1, true);
        assert_read_permitted(&data, public_key_2, true);
    }

    #[test]
    fn validates_private_permissions() {
        let public_key_0 = gen_public_key();
        let public_key_1 = gen_public_key();
        let public_key_2 = gen_public_key();
        let mut map = PrivateSentriedSequence::new(XorName([1; 32]), 100);

        // no owner
        let data = Data::from(map.clone());
        assert_read_permitted(&data, public_key_0, false);

        // no permissions
        unwrap!(map.set_owner(
            Owner {
                public_key: public_key_0,
                expected_data_index: 0,
                expected_permissions_index: 0,
            },
            0,
        ));
        let data = Data::from(map.clone());

        assert_read_permitted(&data, public_key_0, true);
        assert_read_permitted(&data, public_key_1, false);

        // with permissions
        let mut permissions = PrivatePermissions {
            permissions: BTreeMap::new(),
            expected_data_index: 0,
            expected_owners_index: 1,
        };
        let mut set = BTreeMap::new();
        let _ = set.insert(get_append_cmd(), true);
        for query in get_full_read_permissions() {
            let _ = set.insert(query, true);
        }
        for cmd in get_full_modify_permissions() {
            let _ = set.insert(cmd, false);
        }
        let _ = permissions
            .permissions
            .insert(public_key_1, PrivatePermissionSet::new(set));
        unwrap!(map.set_permissions(permissions, 0));
        let data = Data::from(map);

        // existing key
        assert_read_permitted(&data, public_key_1, true);
        assert_eq!(data.is_permitted(get_append_cmd(), public_key_1), true);
        assert_modify_permissions_permitted(&data, public_key_1, false);

        // non-existing key
        assert_read_permitted(&data, public_key_2, false);
        assert_eq!(data.is_permitted(get_append_cmd(), public_key_2), false);
        assert_modify_permissions_permitted(&data, public_key_2, false);
    }
}
