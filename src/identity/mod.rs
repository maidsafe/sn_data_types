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

use crate::{Error, XorName};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};
use threshold_crypto::{
    serde_impl::SerdeSecret, PublicKey as BlsPublicKey, PublicKeyShare as BlsPublicKeyShare,
    SecretKey as BlsSecretKey, SecretKeyShare as BlsSecretKeyShare,
};
use unwrap::unwrap;

/// An enum representing the identity of a network Node or Client.
///
/// It includes public signing key(s), and provides the entity's network address, i.e. its `name()`.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
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
            PublicId::Node(pub_id) => pub_id.name(),
            PublicId::Client(pub_id) => pub_id.name(),
            PublicId::App(pub_id) => pub_id.owner_name(),
        }
    }
}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            PublicId::Node(pub_id) => write!(formatter, "{:?}", pub_id),
            PublicId::Client(pub_id) => write!(formatter, "{:?}", pub_id),
            PublicId::App(pub_id) => write!(formatter, "{:?}", pub_id),
        }
    }
}

impl Display for PublicId {
    #[allow(trivial_casts)]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        (self as &Debug).fmt(formatter)
    }
}

#[derive(Serialize, Deserialize)]
struct BlsKeypair {
    pub secret: SerdeSecret<BlsSecretKey>,
    pub public: BlsPublicKey,
}

#[derive(Serialize, Deserialize)]
struct BlsKeypairShare {
    pub secret: SerdeSecret<BlsSecretKeyShare>,
    pub public: BlsPublicKeyShare,
}

fn encode_to_base64<T: Serialize>(data: &T) -> String {
    let serialised = unwrap!(bincode::serialize(&data));
    base64::encode(&serialised)
}

fn decode_from_base64<I: ?Sized + AsRef<[u8]>, O: DeserializeOwned>(
    encoded: &I,
) -> Result<O, Error> {
    let decoded =
        base64::decode(encoded).map_err(|e| Error::FailedToParseIdentity(e.to_string()))?;
    Ok(bincode::deserialize(&decoded).map_err(|e| Error::FailedToParseIdentity(e.to_string()))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientFullId;
    use unwrap::unwrap;

    #[test]
    fn encode_client_public_id_to_base64() {
        let mut rng = rand::thread_rng();
        let id = client::FullId::new_ed25519(&mut rng);
        assert_eq!(
            unwrap!(client::PublicId::decode_from_base64(
                &id.public_id().encode_to_base64()
            )),
            *id.public_id()
        );

        let node_id = node::FullId::new(&mut rng);
        assert!(
            match client::PublicId::decode_from_base64(&node_id.public_id().encode_to_base64()) {
                Err(Error::FailedToParseIdentity(_)) => true,
                _ => false,
            }
        );
        assert!(client::PublicId::decode_from_base64("sdkjf832939fjs").is_err());
    }

    #[test]
    fn encode_node_public_id_to_base64() {
        let mut rng = rand::thread_rng();
        let mut id = node::FullId::new(&mut rng);
        let bls_secret_key = threshold_crypto::SecretKeySet::random(1, &mut rng);
        id.set_bls_keys(bls_secret_key.secret_key_share(0));
        assert_eq!(
            unwrap!(node::PublicId::decode_from_base64(
                &id.public_id().encode_to_base64()
            )),
            *id.public_id()
        );
        assert!(node::PublicId::decode_from_base64("7djsk38").is_err());
    }

    #[test]
    fn encode_app_public_id_to_base64() {
        let mut rng = rand::thread_rng();
        let owner = ClientFullId::new_ed25519(&mut rng);
        let id = app::FullId::new_ed25519(&mut rng, owner.public_id().clone());
        assert_eq!(
            unwrap!(app::PublicId::decode_from_base64(
                &id.public_id().encode_to_base64()
            )),
            *id.public_id()
        );
        assert!(app::PublicId::decode_from_base64("7od8fh2").is_err());
    }
}
