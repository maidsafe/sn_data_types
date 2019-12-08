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
    use crate::{EntryError, Error, XorName};
    use unwrap::{unwrap, unwrap_err};

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
}