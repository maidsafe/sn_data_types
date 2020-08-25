// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub mod client;
pub mod node;

use crate::{utils, PublicKey, Result, XorName};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};

/// An enum representing the identity of a network Node or Client.
///
/// It includes public signing key(s), and provides the entity's network address, i.e. its `name()`.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
pub enum PublicId {
    /// The public identity of a network Node.
    Node(node::PublicId),
    /// The public identity of a network Client.
    Client(client::PublicId),
}

impl PublicId {
    /// Returns the entity's network address.
    pub fn name(&self) -> &XorName {
        match self {
            Self::Node(pub_id) => pub_id.name(),
            Self::Client(pub_id) => pub_id.name(),
        }
    }

    /// Returns the node public id, if applicable.
    pub fn node_public_id(&self) -> Option<&node::PublicId> {
        if let Self::Node(id) = self {
            Some(id)
        } else {
            None
        }
    }

    /// Returns the client public id, if applicable.
    pub fn client_public_id(&self) -> Option<&client::PublicId> {
        if let Self::Client(id) = self {
            Some(id)
        } else {
            None
        }
    }

    /// Returns the entity's public key, if applicable.
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Node(pub_id) => (*pub_id.ed25519_public_key()).into(),
            Self::Client(pub_id) => *pub_id.public_key(),
        }
    }

    /// Returns the PublicId serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Creates from z-base-32 encoded string.
    pub fn decode_from_zbase32<T: AsRef<str>>(encoded: T) -> Result<Self> {
        utils::decode(encoded)
    }
}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            Self::Node(pub_id) => write!(formatter, "{:?}", pub_id),
            Self::Client(pub_id) => write!(formatter, "{:?}", pub_id),
        }
    }
}

impl Display for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use unwrap::unwrap;

    #[test]
    fn zbase32_encode_decode_client_public_id() {
        let mut rng = rand::thread_rng();
        let id = client::FullId::new_ed25519(&mut rng);
        assert_eq!(
            unwrap!(client::PublicId::decode_from_zbase32(
                &id.public_id().encode_to_zbase32()
            )),
            *id.public_id()
        );

        let node_id = node::FullId::new(&mut rng);
        assert!(match client::PublicId::decode_from_zbase32(
            &node_id.public_id().encode_to_zbase32()
        ) {
            Err(Error::FailedToParse(_)) => true,
            _ => false,
        });
        assert!(client::PublicId::decode_from_zbase32("sdkjf832939fjs").is_err());
    }

    #[test]
    fn zbase32_encode_decode_node_public_id() {
        let mut rng = rand::thread_rng();
        let mut id = node::FullId::new(&mut rng);
        let bls_secret_key = threshold_crypto::SecretKeySet::random(1, &mut rng);
        id.set_bls_keys(
            bls_secret_key.secret_key_share(0),
            bls_secret_key.public_keys(),
        );
        assert_eq!(
            unwrap!(node::PublicId::decode_from_zbase32(
                &id.public_id().encode_to_zbase32()
            )),
            *id.public_id()
        );
        assert!(node::PublicId::decode_from_zbase32("7djsk38").is_err());
    }

    #[test]
    fn zbase32_encode_decode_enum_public_id() {
        let mut rng = rand::thread_rng();
        let id = PublicId::Client(client::FullId::new_ed25519(&mut rng).public_id().clone());
        assert_eq!(
            id,
            unwrap!(PublicId::decode_from_zbase32(&id.encode_to_zbase32()))
        );
        assert!(PublicId::decode_from_zbase32("c419cxim9").is_err());
    }
}
