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
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let insert_1 = SentriedMapCmd::Insert(((vec![1].into(), vec![0]), 0));
        let insert_2 = SentriedMapCmd::Insert(((vec![2].into(), vec![0]), 0));
        let tx = vec![insert_0, insert_1, insert_2];
        unwrap!(data.commit(&tx.into()));

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let insert_1 = SentriedMapCmd::Insert(((vec![1].into(), vec![0]), 0));
        let insert_2 = SentriedMapCmd::Insert(((vec![2].into(), vec![0]), 0));
        let tx = vec![insert_0, insert_1, insert_2];
        unwrap!(data.commit(&tx.into()));

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = MapCmd::Insert((vec![0].into(), vec![0]));
        let insert_1 = MapCmd::Insert((vec![1].into(), vec![0]));
        let insert_2 = MapCmd::Insert((vec![2].into(), vec![0]));
        let tx = vec![insert_0, insert_1, insert_2];
        unwrap!(data.commit(&tx.into()));

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = MapCmd::Insert((vec![0].into(), vec![0]));
        let insert_1 = MapCmd::Insert((vec![1].into(), vec![0]));
        let insert_2 = MapCmd::Insert((vec![2].into(), vec![0]));
        let tx = vec![insert_0, insert_1, insert_2];
        unwrap!(data.commit(&tx.into()))
    }

    #[test]
    fn update() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let update_1 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 1));
        let update_2 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 2));
        let tx = vec![insert_0, update_1, update_2];
        unwrap!(data.commit(&tx.into()));

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let update_1 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 1));
        let update_2 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 2));
        let tx = vec![insert_0, update_1, update_2];
        unwrap!(data.commit(&tx.into()));

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = MapCmd::Insert((vec![0].into(), vec![0]));
        let update_1 = MapCmd::Update((vec![0].into(), vec![0]));
        let update_2 = MapCmd::Update((vec![0].into(), vec![0]));
        let tx = vec![insert_0, update_1, update_2];
        unwrap!(data.commit(&tx.into()));

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = MapCmd::Insert((vec![0].into(), vec![0]));
        let update_1 = MapCmd::Update((vec![0].into(), vec![0]));
        let update_2 = MapCmd::Update((vec![0].into(), vec![0]));
        let tx = vec![insert_0, update_1, update_2];
        unwrap!(data.commit(&tx.into()))
    }

    #[test]
    fn delete() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let update_1 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 1));
        let delete_2 = SentriedMapCmd::Delete((vec![0].into(), 2));
        let tx = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(&tx.into()));

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let update_1 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 1));
        let delete_2 = SentriedMapCmd::Delete((vec![0].into(), 2));
        let tx = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(&tx.into()));

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = MapCmd::Insert((vec![0].into(), vec![0]));
        let update_1 = MapCmd::Update((vec![0].into(), vec![0]));
        let delete_2 = MapCmd::Delete(vec![0].into());
        let tx = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(&tx.into()));

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = MapCmd::Insert((vec![0].into(), vec![0]));
        let update_1 = MapCmd::Update((vec![0].into(), vec![0]));
        let delete_2 = MapCmd::Delete(vec![0].into());
        let tx = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(&tx.into()))
    }

    #[test]
    fn re_insert() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let update_1 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 1));
        let delete_2 = SentriedMapCmd::Delete((vec![0].into(), 2));
        let tx_0 = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(&tx_0.into()));
        let insert_3 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 3));
        let tx_1 = vec![insert_3];
        unwrap!(data.commit(&tx_1.into()));

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let update_1 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 1));
        let delete_2 = SentriedMapCmd::Delete((vec![0].into(), 2));
        let tx_0 = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(&tx_0.into()));
        let insert_3 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 3));
        let tx_1 = vec![insert_3];
        unwrap!(data.commit(&tx_1.into()));

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = MapCmd::Insert((vec![0].into(), vec![0]));
        let update_1 = MapCmd::Update((vec![0].into(), vec![0]));
        let delete_2 = MapCmd::Delete(vec![0].into());
        let tx_0 = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(&tx_0.into()));
        let insert_3 = MapCmd::Insert((vec![0].into(), vec![0]));
        let tx_1 = vec![insert_3];
        unwrap!(data.commit(&tx_1.into()));

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = MapCmd::Insert((vec![0].into(), vec![0]));
        let update_1 = MapCmd::Update((vec![0].into(), vec![0]));
        let delete_2 = MapCmd::Delete(vec![0].into());
        let tx_0 = vec![insert_0, update_1, delete_2];
        unwrap!(data.commit(&tx_0.into()));
        let insert_3 = MapCmd::Insert((vec![0].into(), vec![0]));
        let tx_1 = vec![insert_3];
        unwrap!(data.commit(&tx_1.into()));
    }

    #[test]
    fn insert_when_exists_fails() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let tx = vec![insert_0];
        unwrap!(data.commit(&tx.into()));
        let insert_1 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let tx = vec![insert_1];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::EntryExists(1), *error),
                _ => panic!(),
            },
            _ => panic!(),
        }

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let tx = vec![insert_0];
        unwrap!(data.commit(&tx.into()));
        let insert_1 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let tx = vec![insert_1];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::EntryExists(1), *error),
                _ => panic!(),
            },
            _ => panic!(),
        }

        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = MapCmd::Insert((vec![0].into(), vec![0]));
        let tx = vec![insert_0];
        unwrap!(data.commit(&tx.into()));
        let insert_1 = MapCmd::Insert((vec![0].into(), vec![0]));
        let tx = vec![insert_1];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::EntryExists(1), *error),
                _ => panic!(),
            },
            _ => panic!(),
        }

        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = MapCmd::Insert((vec![0].into(), vec![0]));
        let tx = vec![insert_0];
        unwrap!(data.commit(&tx.into()));
        let insert_1 = MapCmd::Insert((vec![0].into(), vec![0]));
        let tx = vec![insert_1];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::EntryExists(1), *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn update_with_wrong_version_fails() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let update_1 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 1));
        let update_2 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 3)); // <-- wrong version
        let tx = vec![insert_0, update_1, update_2];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(2), *error),
                _ => panic!(),
            },
            _ => panic!(),
        }

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let update_1 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 1));
        let update_2 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 3)); // <-- wrong version
        let tx = vec![insert_0, update_1, update_2];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(2), *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn delete_with_wrong_version_fails() {
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let delete_1 = SentriedMapCmd::Delete((vec![0].into(), 3)); // <-- wrong version
        let tx = vec![insert_0, delete_1];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(1), *error),
                _ => panic!(),
            },
            _ => panic!(),
        }

        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let delete_1 = SentriedMapCmd::Delete((vec![0].into(), 3)); // <-- wrong version
        let tx = vec![insert_0, delete_1];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(1), *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn re_insert_with_wrong_version_fails() {
        // PublicSentriedMap
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let delete_1 = SentriedMapCmd::Delete((vec![0].into(), 1));
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(&tx.into()));
        let insert_2 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 3)); // <-- wrong version
        let tx = vec![insert_2];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(2), *error),
                _ => panic!(),
            },
            _ => panic!(),
        }

        // PrivateSentriedMap
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let delete_1 = SentriedMapCmd::Delete((vec![0].into(), 1));
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(&tx.into()));
        let insert_2 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 3)); // <-- wrong version
        let tx = vec![insert_2];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::InvalidSuccessor(2), *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
    }
    #[test]
    fn delete_or_update_nonexisting_fails() {
        // PublicSentriedMap
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        // Delete
        let delete_2 = SentriedMapCmd::Delete((vec![0].into(), 2));
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
        // Update
        let update_3 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 3));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }

        // PrivateSentriedMap
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        // Delete
        let delete_2 = SentriedMapCmd::Delete((vec![0].into(), 2));
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
        // Update
        let update_3 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 3));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }

        // PublicMap
        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        // Delete
        let delete_2 = MapCmd::Delete(vec![0].into());
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
        // Update
        let update_3 = MapCmd::Update((vec![0].into(), vec![0]));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }

        // PrivateMap
        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        // Delete
        let delete_2 = MapCmd::Delete(vec![0].into());
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
        // Update
        let update_3 = MapCmd::Update((vec![0].into(), vec![0]));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn delete_or_update_deleted_fails() {
        // PublicSentriedMap
        let mut data = PublicSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let delete_1 = SentriedMapCmd::Delete((vec![0].into(), 1));
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(&tx.into()));
        // Delete
        let delete_2 = SentriedMapCmd::Delete((vec![0].into(), 2));
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
        // Update
        let update_3 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 3));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }

        // PrivateSentriedMap
        let mut data = PrivateSentriedMap::new(XorName([1; 32]), 10000);
        let insert_0 = SentriedMapCmd::Insert(((vec![0].into(), vec![0]), 0));
        let delete_1 = SentriedMapCmd::Delete((vec![0].into(), 1));
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(&tx.into()));
        // Delete
        let delete_2 = SentriedMapCmd::Delete((vec![0].into(), 2));
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
        // Update
        let update_3 = SentriedMapCmd::Update(((vec![0].into(), vec![0]), 3));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }

        // PublicMap
        let mut data = PublicMap::new(XorName([1; 32]), 10000);
        let insert_0 = MapCmd::Insert((vec![0].into(), vec![0]));
        let delete_1 = MapCmd::Delete(vec![0].into());
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(&tx.into()));
        // Delete
        let delete_2 = MapCmd::Delete(vec![0].into());
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
        // Update
        let update_3 = MapCmd::Update((vec![0].into(), vec![0]));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }

        // PrivateMap
        let mut data = PrivateMap::new(XorName([1; 32]), 10000);
        let insert_0 = MapCmd::Insert((vec![0].into(), vec![0]));
        let delete_1 = MapCmd::Delete(vec![0].into());
        let tx = vec![insert_0, delete_1];
        unwrap!(data.commit(&tx.into()));
        // Delete
        let delete_2 = MapCmd::Delete(vec![0].into());
        let tx = vec![delete_2];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
        // Update
        let update_3 = MapCmd::Update((vec![0].into(), vec![0]));
        let tx = vec![update_3];
        match unwrap_err!(data.commit(&tx.into())) {
            Error::InvalidEntryActions(errors) => match errors.get(&vec![0].into()) {
                Some(error) => assert_eq!(EntryError::NoSuchEntry, *error),
                _ => panic!(),
            },
            _ => panic!(),
        }
    }
}