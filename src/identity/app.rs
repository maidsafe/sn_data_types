// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    keys::SignatureShare, utils, ClientFullId, ClientPublicId, Ed25519Digest, Error, Keypair,
    PublicKey, Signature, XorName,
};
use multibase::Decodable;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};
use threshold_crypto::SecretKeyShare as BlsSecretKeyShare;

/// A struct holding a keypair variant and the corresponding public ID for a network App.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FullId {
    pub(crate) keypair: Keypair,
    pub(crate) public_id: PublicId,
}

impl FullId {
    /// Constructs a `FullId` with a random Ed25519 keypair.
    pub fn new_ed25519<T: CryptoRng + Rng>(rng: &mut T, owner: ClientPublicId) -> Self {
        Self::new(ClientFullId::new_ed25519(rng), owner)
    }

    /// Constructs a `FullId` with a random BLS keypair.
    pub fn new_bls<T: CryptoRng + Rng>(rng: &mut T, owner: ClientPublicId) -> Self {
        Self::new(ClientFullId::new_bls(rng), owner)
    }

    // /// Constructs a `FullId` from a BLS secret key share.
    // pub fn new_bls_share(bls_secret_key_share: BlsSecretKeyShare, owner: ClientPublicId) -> Self {
    //     Self::new(ClientFullId::new_bls_share(bls_secret_key_share), owner)
    // }

    fn new(new_id: ClientFullId, owner: ClientPublicId) -> Self {
        let public_id = PublicId {
            public_key: *new_id.public_id().public_key(),
            owner,
        };
        Self {
            keypair: new_id.keypair,
            public_id,
        }
    }

    /// Creates a detached signature of `data`.
    pub fn sign<T: AsRef<[u8]>>(&self, data: T) -> Signature {
        match &self.keypair {
            Keypair::Ed25519(keys) => Signature::Ed25519(keys.sign::<Ed25519Digest>(data.as_ref())),
            Keypair::Bls(keys) => Signature::Bls(keys.secret.inner().sign(data)),
            Keypair::BlsShare(keys) => Signature::BlsShare(SignatureShare {
                index: keys.index,
                share: keys.secret.inner().sign(data),
            }),
        }
    }

    /// Returns the public ID.
    pub fn public_id(&self) -> &PublicId {
        &self.public_id
    }
}

/// A struct representing the public identity of a network App.
///
/// It includes the public signing key, and the App owner's `ClientPublicId`.  The owner's `name()`
/// defines the App's network address.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, PartialOrd, Ord, Hash)]
pub struct PublicId {
    pub(crate) public_key: PublicKey,
    pub(crate) owner: ClientPublicId,
}

impl PublicId {
    /// Returns the App's network address, i.e. its owner's `name()`.
    pub fn owner_name(&self) -> &XorName {
        self.owner.name()
    }

    /// Returns the App's public signing key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the App owner's public ID.
    pub fn owner(&self) -> &ClientPublicId {
        &self.owner
    }

    /// Returns the PublicId serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Creates from z-base-32 encoded string.
    pub fn decode_from_zbase32<T: Decodable>(encoded: T) -> Result<Self, Error> {
        utils::decode(encoded)
    }
}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "App({:?}, owner: {:?})",
            self.public_key,
            self.owner.public_key()
        )
    }
}

impl Display for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, formatter)
    }
}
