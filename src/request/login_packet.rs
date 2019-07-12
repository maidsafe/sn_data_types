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

/// Login packet size is limited .
pub const MAX_LOGIN_PACKET_BYTES: usize = 1024 * 1024; // 1 MB

/// Login packet containing arbitrary user's login information.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct LoginPacket {
    destination: XorName,
    authorised_getter: PublicKey, // deterministically created from passwords
    data: Vec<u8>,
    signature: Signature,
}

impl LoginPacket {
    pub fn new(
        destination: XorName,
        authorised_getter: PublicKey,
        data: Vec<u8>,
        signature: Signature,
    ) -> Result<Self> {
        let login_packet_data = Self {
            destination,
            authorised_getter,
            data,
            signature,
        };
        if login_packet_data.size_is_valid() {
            Ok(login_packet_data)
        } else {
            Err(Error::ExceededSize)
        }
    }

    pub fn size_is_valid(&self) -> bool {
        self.data.len() <= MAX_LOGIN_PACKET_BYTES
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
    use super::{LoginPacket, MAX_LOGIN_PACKET_BYTES};
    use crate::{ClientFullId, Error};
    use rand;

    #[test]
    fn exceed_size_limit() {
        let our_id = ClientFullId::new_ed25519(&mut rand::thread_rng());

        let acc_data = vec![0; MAX_LOGIN_PACKET_BYTES + 1];
        let signature = our_id.sign(&acc_data);

        let res = LoginPacket::new(
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

        let res = LoginPacket::new(
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
