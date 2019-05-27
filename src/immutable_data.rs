// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{XorName, XOR_NAME_LEN};
use rust_sodium::crypto::sign::{PublicKey, PUBLICKEYBYTES};
use tiny_keccak;

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct UnpubImmutableData {
    /// Contained ImmutableData.
    data: Vec<u8>,
    /// Contains a set of owners of this data. DataManagers enforce that a
    /// DELETE or OWNED-GET type of request is coming from the
    /// MaidManager Authority of the owners.
    owners: PublicKey,
}

impl UnpubImmutableData {
    /// Name.
    pub fn name(&self) -> XorName {
        // TODO: Use low-level arrays or slices instead of Vec.
        let mut bytes = Vec::with_capacity(XOR_NAME_LEN + PUBLICKEYBYTES);
        bytes.extend_from_slice(&tiny_keccak::sha3_256(&self.data));
        bytes.extend_from_slice(&self.owners.0);
        tiny_keccak::sha3_256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_name() {
        let data1 = b"Hello".to_vec();
        let data2 = b"Goodbye".to_vec();

        let owner1 = PublicKey([0; PUBLICKEYBYTES]);
        let owner2 = PublicKey([1; PUBLICKEYBYTES]);

        let idata1 = UnpubImmutableData {
            data: data1.clone(),
            owners: owner1,
        };
        let idata2 = UnpubImmutableData {
            data: data1,
            owners: owner2,
        };
        let idata3 = UnpubImmutableData {
            data: data2,
            owners: owner1,
        };

        assert_eq!(idata1.name(), idata1.name());
        assert_eq!(idata2.name(), idata2.name());
        assert_eq!(idata3.name(), idata3.name());

        assert_ne!(idata1.name(), idata2.name());
        assert_ne!(idata1.name(), idata3.name());
        assert_ne!(idata2.name(), idata3.name());
    }
}
