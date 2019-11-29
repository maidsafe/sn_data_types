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
    use crate::map::*;
    use crate::permissions::{
        CmdType, HardErasureCmd, MapCmd, MapQuery, MapWrite, ModifyableMapPermissions,
        PrivatePermissionSet, PrivatePermissions, PublicPermissionSet, PublicPermissions,
        QueryType, Request,
    };
    use crate::shared_data::{Address, Index, Owner, User};
    use crate::{EntryError, Error, PublicKey, XorName};
    use std::collections::BTreeMap;
    use threshold_crypto::SecretKey;
    use unwrap::{unwrap, unwrap_err};

    pub fn get_insert_cmd() -> Request {
        Request::Cmd(CmdType::Map(MapCmd::Insert))
    }

    fn get_read_query(query: MapQuery) -> Request {
        Request::Query(QueryType::Map(query))
    }

    fn get_full_read_permissions() -> Vec<Request> {
        vec![
            Request::Query(QueryType::Map(MapQuery::ReadData)),
            Request::Query(QueryType::Map(MapQuery::ReadOwners)),
            Request::Query(QueryType::Map(MapQuery::ReadPermissions)),
        ]
    }

    fn get_modify_permissions(permission: ModifyableMapPermissions) -> Request {
        Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(permission)))
    }

    fn get_full_modify_permissions() -> Vec<Request> {
        vec![
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::ReadData,
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::ReadOwners,
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::ReadPermissions,
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::Write(MapWrite::Insert),
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::Write(MapWrite::Update),
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::Write(MapWrite::Delete),
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::Write(MapWrite::ModifyPermissions),
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::Write(MapWrite::HardErasure(HardErasureCmd::HardDelete)),
            ))),
            Request::Cmd(CmdType::Map(MapCmd::ModifyPermissions(
                ModifyableMapPermissions::Write(MapWrite::HardErasure(HardErasureCmd::HardUpdate)),
            ))),
        ]
    }

    pub fn assert_read_permitted(data: &Data, public_key: PublicKey, permitted: bool) {
        assert_eq!(
            data.is_permitted(get_read_query(MapQuery::ReadData), public_key),
            permitted
        );
        assert_eq!(
            data.is_permitted(get_read_query(MapQuery::ReadOwners), public_key),
            permitted
        );
        assert_eq!(
            data.is_permitted(get_read_query(MapQuery::ReadPermissions), public_key),
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
                get_modify_permissions(ModifyableMapPermissions::ReadData),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::ReadOwners),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::ReadPermissions),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::Write(MapWrite::Insert)),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::Write(MapWrite::Update)),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::Write(MapWrite::Delete)),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::Write(
                    MapWrite::ModifyPermissions
                )),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::Write(MapWrite::HardErasure(
                    HardErasureCmd::HardDelete
                ))),
                public_key
            ),
            permitted
        );
        assert_eq!(
            data.is_permitted(
                get_modify_permissions(ModifyableMapPermissions::Write(MapWrite::HardErasure(
                    HardErasureCmd::HardUpdate
                ))),
                public_key
            ),
            permitted
        );
    }

    #[test]
    fn insert() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let insert_1 = SentriedCmd::Insert(((vec![1], vec![0]), 0));
        let insert_2 = SentriedCmd::Insert(((vec![2], vec![0]), 0));
        let tx = vec![insert_0, insert_1, insert_2];
        unwrap!(data.commit(tx));

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let insert_1 = SentriedCmd::Insert(((vec![1], vec![0]), 0));
        let insert_2 = SentriedCmd::Insert(((vec![2], vec![0]), 0));
        let tx = vec![insert_0, insert_1, insert_2];
        unwrap!(data.commit(tx));

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let insert_1 = Cmd::Insert((vec![1], vec![0]));
        let insert_2 = Cmd::Insert((vec![2], vec![0]));
        let tx = vec![insert_0, insert_1, insert_2];
        unwrap!(data.commit(tx));

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let insert_1 = Cmd::Insert((vec![1], vec![0]));
        let insert_2 = Cmd::Insert((vec![2], vec![0]));
        let tx = vec![insert_0, insert_1, insert_2];
        unwrap!(data.commit(tx))
    }

    #[test]
    fn update() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let update_2 = SentriedCmd::Update(((vec![0], vec![0]), 2));
        let tx = vec![insert_0, update_1, update_2];
        unwrap!(data.commit(tx));

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let update_2 = SentriedCmd::Update(((vec![0], vec![0]), 2));
        let tx = vec![insert_0, update_1, update_2];
        unwrap!(data.commit(tx));

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let update_1 = Cmd::Update((vec![0], vec![0]));
        let update_2 = Cmd::Update((vec![0], vec![0]));
        let tx = vec![insert_0, update_1, update_2];
        unwrap!(data.commit(tx));

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let update_1 = Cmd::Update((vec![0], vec![0]));
        let update_2 = Cmd::Update((vec![0], vec![0]));
        let tx = vec![insert_0, update_1, update_2];
        unwrap!(data.commit(tx))
    }

    #[test]
    fn delete() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx));

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx));

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let update_1 = Cmd::Update((vec![0], vec![0]));
        let delete_2 = Cmd::Delete(vec![0]);
        let tx = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx));

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let update_1 = Cmd::Update((vec![0], vec![0]));
        let delete_2 = Cmd::Delete(vec![0]);
        let tx = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx))
    }

    #[test]
    fn re_insert() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx_0 = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx_0));
        let insert_3 = SentriedCmd::Insert(((vec![0], vec![0]), 3));
        let tx_1 = vec![insert_3];
        unwrap!(data.commit(tx_1));

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx_0 = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx_0));
        let insert_3 = SentriedCmd::Insert(((vec![0], vec![0]), 3));
        let tx_1 = vec![insert_3];
        unwrap!(data.commit(tx_1));

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let update_1 = Cmd::Update((vec![0], vec![0]));
        let delete_2 = Cmd::Delete(vec![0]);
        let tx_0 = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx_0));
        let insert_3 = Cmd::Insert((vec![0], vec![0]));
        let tx_1 = vec![insert_3];
        unwrap!(data.commit(tx_1));

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let update_1 = Cmd::Update((vec![0], vec![0]));
        let delete_2 = Cmd::Delete(vec![0]);
        let tx_0 = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(tx_0));
        let insert_3 = Cmd::Insert((vec![0], vec![0]));
        let tx_1 = vec![insert_3];
        unwrap!(data.commit(tx_1));
    }

    #[test]
    fn insert_when_exists_fails() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let tx = vec![insert_0];
        unwrap!(data.commit(tx));
        let insert_1 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let tx = vec![insert_1];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::EntryExists(1), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let tx = vec![insert_0];
        unwrap!(data.commit(tx));
        let insert_1 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let tx = vec![insert_1];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::EntryExists(1), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let tx = vec![insert_0];
        unwrap!(data.commit(tx));
        let insert_1 = Cmd::Insert((vec![0], vec![0]));
        let tx = vec![insert_1];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::EntryExists(1), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let tx = vec![insert_0];
        unwrap!(data.commit(tx));
        let insert_1 = Cmd::Insert((vec![0], vec![0]));
        let tx = vec![insert_1];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::EntryExists(1), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }

    #[test]
    fn update_with_wrong_version_fails() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let update_2 = SentriedCmd::Update(((vec![0], vec![0]), 3)); // <-- wrong version
        let tx = vec![insert_0, update_1, update_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(2), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let update_1 = SentriedCmd::Update(((vec![0], vec![0]), 1));
        let update_2 = SentriedCmd::Update(((vec![0], vec![0]), 3)); // <-- wrong version
        let tx = vec![insert_0, update_1, update_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(2), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }

    #[test]
    fn delete_with_wrong_version_fails() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let delete_1 = SentriedCmd::Delete((vec![0], 3)); // <-- wrong version
        let tx = vec![insert_0, delete_1];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(1), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let delete_1 = SentriedCmd::Delete((vec![0], 3)); // <-- wrong version
        let tx = vec![insert_0, delete_1];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(1), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }

    #[test]
    fn re_insert_with_wrong_version_fails() {
        // PublicSentriedMap
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let delete_1 = SentriedCmd::Delete((vec![0], 1));
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(tx));
        let insert_2 = SentriedCmd::Insert(((vec![0], vec![0]), 3)); // <-- wrong version
        let tx = vec![insert_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(2), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PrivateSentriedMap
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let delete_1 = SentriedCmd::Delete((vec![0], 1));
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(tx));
        let insert_2 = SentriedCmd::Insert(((vec![0], vec![0]), 3)); // <-- wrong version
        let tx = vec![insert_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(2), *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }
    #[test]
    fn delete_or_update_nonexisting_fails() {
        // PublicSentriedMap
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        // Delete
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = SentriedCmd::Update(((vec![0], vec![0]), 3));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PrivateSentriedMap
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        // Delete
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = SentriedCmd::Update(((vec![0], vec![0]), 3));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PublicMap
        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        // Delete
        let delete_2 = Cmd::Delete(vec![0]);
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = Cmd::Update((vec![0], vec![0]));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PrivateMap
        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        // Delete
        let delete_2 = Cmd::Delete(vec![0]);
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = Cmd::Update((vec![0], vec![0]));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }

    #[test]
    fn delete_or_update_deleted_fails() {
        // PublicSentriedMap
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let delete_1 = SentriedCmd::Delete((vec![0], 1));
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(tx));
        // Delete
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = SentriedCmd::Update(((vec![0], vec![0]), 3));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PrivateSentriedMap
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedCmd::Insert(((vec![0], vec![0]), 0));
        let delete_1 = SentriedCmd::Delete((vec![0], 1));
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(tx));
        // Delete
        let delete_2 = SentriedCmd::Delete((vec![0], 2));
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = SentriedCmd::Update(((vec![0], vec![0]), 3));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PublicMap
        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let delete_1 = Cmd::Delete(vec![0]);
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(tx));
        // Delete
        let delete_2 = Cmd::Delete(vec![0]);
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = Cmd::Update((vec![0], vec![0]));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }

        // PrivateMap
        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = Cmd::Insert((vec![0], vec![0]));
        let delete_1 = Cmd::Delete(vec![0]);
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(tx));
        // Delete
        let delete_2 = Cmd::Delete(vec![0]);
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
        // Update
        let update_3 = Cmd::Update((vec![0], vec![0]));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(tx)) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0]) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => assert!(false),
            },
            _ => assert!(false),
        }
    }

    #[test]
    fn set_permissions() {
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);

        // Set the first permission set with correct ExpectedIndices - should pass.
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
    fn set_owner() {
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
    fn assert_shell() {
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
    fn zbase32_encode_decode_adata_address() {
        let name = XorName(rand::random());
        let address = Address::PrivateSentried { name, tag: 15000 };
        let encoded = address.encode_to_zbase32();
        let decoded = unwrap!(self::Address::decode_from_zbase32(&encoded));
        assert_eq!(address, decoded);
    }

    // #[test]
    // fn in_range() {
    //     let mut data = PublicSentriedMap::new(rand::random(), 10);
    //     let entries = vec![
    //         Entry::new(b"key0".to_vec(), b"value0".to_vec()),
    //         Entry::new(b"key1".to_vec(), b"value1".to_vec()),
    //     ];
    //     unwrap!(data.append(entries, 0));

    //     assert_eq!(
    //         data.in_range(Index::FromStart(0), Index::FromStart(0)),
    //         Some(vec![])
    //     );
    //     assert_eq!(
    //         data.in_range(Index::FromStart(0), Index::FromStart(1)),
    //         Some(vec![Entry::new(b"key0".to_vec(), b"value0".to_vec())])
    //     );
    //     assert_eq!(
    //         data.in_range(Index::FromStart(0), Index::FromStart(2)),
    //         Some(vec![
    //             Entry::new(b"key0".to_vec(), b"value0".to_vec()),
    //             Entry::new(b"key1".to_vec(), b"value1".to_vec())
    //         ])
    //     );

    //     assert_eq!(
    //         data.in_range(Index::FromEnd(2), Index::FromEnd(1)),
    //         Some(vec![Entry::new(b"key0".to_vec(), b"value0".to_vec()),])
    //     );
    //     assert_eq!(
    //         data.in_range(Index::FromEnd(2), Index::FromEnd(0)),
    //         Some(vec![
    //             Entry::new(b"key0".to_vec(), b"value0".to_vec()),
    //             Entry::new(b"key1".to_vec(), b"value1".to_vec())
    //         ])
    //     );

    //     assert_eq!(
    //         data.in_range(Index::FromStart(0), Index::FromEnd(0)),
    //         Some(vec![
    //             Entry::new(b"key0".to_vec(), b"value0".to_vec()),
    //             Entry::new(b"key1".to_vec(), b"value1".to_vec())
    //         ])
    //     );

    //     // start > end
    //     assert_eq!(
    //         data.in_range(Index::FromStart(1), Index::FromStart(0)),
    //         None
    //     );
    //     assert_eq!(data.in_range(Index::FromEnd(1), Index::FromEnd(2)), None);

    //     // overflow
    //     assert_eq!(
    //         data.in_range(Index::FromStart(0), Index::FromStart(3)),
    //         None
    //     );
    //     assert_eq!(data.in_range(Index::FromEnd(3), Index::FromEnd(0)), None);
    // }

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
        let mut data = PublicMap::new(rand::random(), 20);
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
        let mut data = PublicSentriedMap::new(rand::random(), 20);
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
        let mut data = PrivateMap::new(rand::random(), 20);
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
        let mut data = PrivateSentriedMap::new(rand::random(), 20);
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
        let mut map = PublicSentriedMap::new(XorName([1; 32]), 100);

        // no owner
        let data = Data::from(map.clone());
        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_0), false);
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

        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_0), true);
        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_1), false);
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
        let _ = set.insert(get_insert_cmd(), true);
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
        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_1), true);
        // existing key override
        assert_modify_permissions_permitted(&data, public_key_1, true);
        // non-existing keys are handled by `Anyone`
        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_2), true);
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
        let mut map = PrivateSentriedMap::new(XorName([1; 32]), 100);

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
        let _ = set.insert(get_insert_cmd(), true);
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
        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_1), true);
        assert_modify_permissions_permitted(&data, public_key_1, false);

        // non-existing key
        assert_read_permitted(&data, public_key_2, false);
        assert_eq!(data.is_permitted(get_insert_cmd(), public_key_2), false);
        assert_modify_permissions_permitted(&data, public_key_2, false);
    }
}
