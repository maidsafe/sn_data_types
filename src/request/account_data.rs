// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{Error, PublicKey, Result, Signature, XorName};
use serde::{Deserialize, Serialize};

/// Account packet size is limited .
pub const MAX_ACCOUNT_DATA_BYTES: usize = 1024 * 1024; // 1 MB

/// Account packet containing arbitrary user's account information.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct AccountData {
    destination: XorName,
    authorised_getter: PublicKey, // deterministically created from passwords
    data: Vec<u8>,
    signature: Signature,
}

impl AccountData {
    pub fn new(
        destination: XorName,
        authorised_getter: PublicKey,
        data: Vec<u8>,
        signature: Signature,
    ) -> Result<Self> {
        let account_data = Self {
            destination,
            authorised_getter,
            data,
            signature,
        };
        if account_data.size_is_valid() {
            Ok(account_data)
        } else {
            Err(Error::ExceededSize)
        }
    }

    pub fn size_is_valid(&self) -> bool {
        self.data.len() <= MAX_ACCOUNT_DATA_BYTES
    }

    pub fn destination(&self) -> &XorName {
        &self.destination
    }

    pub fn authorised_getter(&self) -> &PublicKey {
        &self.authorised_getter
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountData, MAX_ACCOUNT_DATA_BYTES};
    use crate::{ClientFullId, Error};
    use rand;

    #[test]
    fn exceed_size_limit() {
        let our_id = ClientFullId::new_ed25519(&mut rand::thread_rng());

        let acc_data = vec![0; MAX_ACCOUNT_DATA_BYTES + 1];
        let signature = our_id.sign(&acc_data);

        let res = AccountData::new(
            rand::random(),
            *our_id.public_id().public_key(),
            acc_data,
            signature,
        );

        match res {
            Err(Error::ExceededSize) => (),
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn valid() {
        let our_id = ClientFullId::new_ed25519(&mut rand::thread_rng());

        let acc_data = vec![1; 16];
        let signature = our_id.sign(&acc_data);

        let res = AccountData::new(
            rand::random(),
            *our_id.public_id().public_key(),
            acc_data.clone(),
            signature,
        );

        match res {
            Ok(ad) => {
                assert_eq!(ad.data(), acc_data.as_slice());
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
}
