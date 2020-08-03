// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub mod app;
pub mod client;
pub mod node;

use crate::{utils, AppFullId, ClientFullId, Keypair, PublicKey, Result, Signature, XorName};
use multibase::Decodable;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;

/// An enum representing the Full Id variants for a Client or App.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeKey {
    /// Represents an application authorised by a client.
    App(Arc<AppFullId>),
    /// Represents a network client.
    Client(Arc<ClientFullId>),
}

impl SafeKey {
    /// Creates a client full ID.
    pub fn client(full_id: ClientFullId) -> Self {
        Self::Client(Arc::new(full_id))
    }

    /// Retrieve the underlying keypair
    pub fn keypair(&self) -> Keypair {
        match self {
            Self::App(app_full_id) => app_full_id.keypair.clone(),
            Self::Client(client_full_id) => client_full_id.keypair.clone(),
        }
    }

    /// Creates an app full ID.
    pub fn app(full_id: AppFullId) -> Self {
        Self::App(Arc::new(full_id))
    }

    /// Signs a given message using the App / Client full id as required.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        match self {
            Self::App(app_full_id) => app_full_id.sign(msg),
            Self::Client(client_full_id) => client_full_id.sign(msg),
        }
    }

    /// Returns a corresponding public ID.
    pub fn public_id(&self) -> PublicId {
        match self {
            Self::App(app_full_id) => PublicId::App(app_full_id.public_id().clone()),
            Self::Client(client_full_id) => PublicId::Client(client_full_id.public_id().clone()),
        }
    }

    /// Returns a corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::App(app_full_id) => *app_full_id.public_id().public_key(),
            Self::Client(client_full_id) => *client_full_id.public_id().public_key(),
        }
    }
}

/// An enum representing the identity of a network Node or Client.
///
/// It includes public signing key(s), and provides the entity's network address, i.e. its `name()`.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
pub enum PublicId {
    /// The public identity of a network Node.
    Node(node::PublicId),
    /// The public identity of a network Client.
    Client(client::PublicId),
    /// The public identity of a network App.
    App(app::PublicId),
}

impl PublicId {
    /// Returns the entity's network address.
    pub fn name(&self) -> &XorName {
        match self {
            Self::Node(pub_id) => pub_id.name(),
            Self::Client(pub_id) => pub_id.name(),
            Self::App(pub_id) => pub_id.owner_name(),
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

    /// Returns the app public id, if applicable.
    pub fn app_public_id(&self) -> Option<&app::PublicId> {
        if let Self::App(id) = self {
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
            Self::App(pub_id) => *pub_id.public_key(),
        }
    }

    /// Returns the PublicId serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Creates from z-base-32 encoded string.
    pub fn decode_from_zbase32<T: Decodable>(encoded: T) -> Result<Self> {
        utils::decode(encoded)
    }
}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            Self::Node(pub_id) => write!(formatter, "{:?}", pub_id),
            Self::Client(pub_id) => write!(formatter, "{:?}", pub_id),
            Self::App(pub_id) => write!(formatter, "{:?}", pub_id),
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
    use crate::{ClientFullId, Error};
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
    fn zbase32_encode_decode_app_public_id() {
        let mut rng = rand::thread_rng();
        let owner = ClientFullId::new_ed25519(&mut rng);
        let id = app::FullId::new_ed25519(&mut rng, owner.public_id().clone());
        assert_eq!(
            unwrap!(app::PublicId::decode_from_zbase32(
                &id.public_id().encode_to_zbase32()
            )),
            *id.public_id()
        );
        assert!(app::PublicId::decode_from_zbase32("7od8fh2").is_err());
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
