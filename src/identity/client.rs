// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{BlsKeypair, BlsKeypairShare};
use crate::{utils, Ed25519Digest, Error, PublicKey, Signature, XorName};
use ed25519_dalek::Keypair as Ed25519Keypair;
use multibase::Decodable;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{self, Debug, Display, Formatter};
use threshold_crypto::{
    serde_impl::SerdeSecret, SecretKey as BlsSecretKey, SecretKeyShare as BlsSecretKeyShare,
};

#[derive(Serialize, Deserialize)]
pub(super) enum Keypair {
    Ed25519(Ed25519Keypair),
    Bls(BlsKeypair),
    BlsShare(BlsKeypairShare),
}

/// A struct holding a keypair variant and the corresponding public ID for a network Client.
#[derive(Serialize, Deserialize)]
pub struct FullId {
    pub(super) keypair: Keypair,
    public_id: PublicId,
}

impl FullId {
    /// Constructs a `FullId` with a random Ed25519 keypair.
    pub fn new_ed25519<T: CryptoRng + Rng>(rng: &mut T) -> Self {
        let ed25519_keypair = Ed25519Keypair::generate::<Ed25519Digest, _>(rng);
        let public_key = PublicKey::Ed25519(ed25519_keypair.public);
        let public_id = PublicId {
            name: public_key.into(),
            public_key,
        };
        Self {
            keypair: Keypair::Ed25519(ed25519_keypair),
            public_id,
        }
    }

    /// Constructs a `FullId` with a random BLS keypair.
    pub fn new_bls<T: CryptoRng + Rng>(rng: &mut T) -> Self {
        let bls_secret_key = rng.gen::<BlsSecretKey>();
        let bls_public_key = bls_secret_key.public_key();
        let bls_keypair = BlsKeypair {
            secret: SerdeSecret(bls_secret_key),
            public: bls_public_key,
        };
        let public_key = PublicKey::Bls(bls_public_key);
        let public_id = PublicId {
            name: public_key.into(),
            public_key,
        };
        Self {
            keypair: Keypair::Bls(bls_keypair),
            public_id,
        }
    }

    /// Constructs a `FullId` from a BLS secret key share.
    pub fn new_bls_share(bls_secret_key_share: BlsSecretKeyShare) -> Self {
        let bls_public_key_share = bls_secret_key_share.public_key_share();
        let bls_keypair_share = BlsKeypairShare {
            secret: SerdeSecret(bls_secret_key_share),
            public: bls_public_key_share,
        };
        let public_key = PublicKey::BlsShare(bls_public_key_share);
        let public_id = PublicId {
            name: public_key.into(),
            public_key,
        };
        Self {
            keypair: Keypair::BlsShare(bls_keypair_share),
            public_id,
        }
    }

    /// Creates a detached signature of `data`.
    pub fn sign<T: AsRef<[u8]>>(&self, data: T) -> Signature {
        match &self.keypair {
            Keypair::Ed25519(keys) => Signature::Ed25519(keys.sign::<Ed25519Digest>(data.as_ref())),
            Keypair::Bls(keys) => Signature::Bls(keys.secret.inner().sign(data)),
            Keypair::BlsShare(keys) => Signature::BlsShare(keys.secret.inner().sign(data)),
        }
    }

    /// Returns the public ID.
    pub fn public_id(&self) -> &PublicId {
        &self.public_id
    }

    // TODO: Remove this once the authenticator is updated
    // to create random FullIds instead of AppKeys / ClientKeys
    /// Constructs a `FullId` with a particular BLS secret key.
    #[doc(hidden)]
    pub fn with_bls_key(bls_sk: BlsSecretKey) -> Self {
        let bls_pk = bls_sk.public_key();
        let bls_keypair = BlsKeypair {
            secret: SerdeSecret(bls_sk),
            public: bls_pk,
        };
        let public_key = PublicKey::Bls(bls_pk);
        let public_id = PublicId {
            name: public_key.into(),
            public_key,
        };
        Self {
            keypair: Keypair::Bls(bls_keypair),
            public_id,
        }
    }
}

/// A struct representing the public identity of a network Client.
///
/// It includes the public signing key, and this provides the Client's network address, i.e.
/// `name()`.
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct PublicId {
    name: XorName,
    public_key: PublicKey,
}

impl PublicId {
    /// Returns the Client's network address.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Returns the Client's public signing key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    // TODO: Remove this once the authenticator is updated
    // to create random FullIds instead of AppKeys / ClientKeys
    #[doc(hidden)]
    pub fn new(name: XorName, public_key: PublicKey) -> Self {
        Self { name, public_key }
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

impl Serialize for PublicId {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        (&self.public_key).serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PublicId {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
        let public_key: PublicKey = Deserialize::deserialize(deserialiser)?;
        let name = public_key.into();
        Ok(PublicId { name, public_key })
    }
}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Client({:?})", self.public_key)
    }
}

impl Display for PublicId {
    #[allow(trivial_casts)]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        (self as &Debug).fmt(formatter)
    }
}
