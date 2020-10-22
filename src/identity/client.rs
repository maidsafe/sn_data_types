// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::keys::{BlsKeypair, BlsKeypairShare, SignatureShare};
use crate::{utils, Error, Keypair, PublicKey, Signature};
use ed25519_dalek::{
    Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey,
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use signature::Signer;
use std::fmt::{self, Debug, Display, Formatter};
use threshold_crypto::{serde_impl::SerdeSecret, SecretKey as BlsSecretKey};
use xor_name::XorName;

/// A struct holding a keypair variant and the corresponding public ID for a network Client.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FullId {
    keypair: Keypair,
    public_id: PublicId,
}

impl FullId {
    /// Constructs a `FullId` with a random Ed25519 keypair.
    pub fn new_ed25519<T: CryptoRng + Rng>(rng: &mut T) -> Self {
        let keypair = Keypair::new_ed25519(rng);
        let public_key = keypair.public_key();
        let public_id = PublicId {
            name: public_key.into(),
            public_key,
        };
        Self { keypair, public_id }
    }

    /// Constructs a `FullId` with a random BLS keypair.
    pub fn new_bls<T: CryptoRng + Rng>(rng: &mut T) -> Self {
        let keypair = Keypair::new_bls(rng);
        let public_key = keypair.public_key();
        let public_id = PublicId {
            name: public_key.into(),
            public_key,
        };
        Self { keypair, public_id }
    }

    /// Creates a detached signature of `data`.
    pub fn sign<T: AsRef<[u8]>>(&self, data: T) -> Signature {
        match &self.keypair {
            Keypair::Ed25519(keys) => Signature::Ed25519(keys.sign(data.as_ref())),
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

    /// Returns the PublicKey of the PublicId.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_id.public_key()
    }

    /// Returns a reference to the Keypair
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}

impl From<Keypair> for FullId {
    fn from(keypair: Keypair) -> Self {
        match keypair {
            Keypair::Bls(keypair) => Self::from(keypair),
            Keypair::BlsShare(keypair) => Self::from(keypair),
            Keypair::Ed25519(keypair) => Self::from(keypair),
        }
    }
}

impl From<BlsSecretKey> for FullId {
    fn from(bls_sk: BlsSecretKey) -> Self {
        let public = bls_sk.public_key();
        let keypair = Keypair::Bls(BlsKeypair {
            secret: SerdeSecret(bls_sk),
            public,
        });
        let public_key = keypair.public_key();
        let public_id = PublicId {
            name: public_key.into(),
            public_key,
        };
        Self { keypair, public_id }
    }
}

impl From<SerdeSecret<BlsSecretKey>> for FullId {
    fn from(bls_sk: SerdeSecret<BlsSecretKey>) -> Self {
        let public = bls_sk.public_key();
        let keypair = Keypair::Bls(BlsKeypair {
            secret: bls_sk,
            public,
        });
        let public_key = keypair.public_key();
        let public_id = PublicId {
            name: public_key.into(),
            public_key,
        };
        Self { keypair, public_id }
    }
}

impl From<BlsKeypair> for FullId {
    fn from(bls_keypair: BlsKeypair) -> Self {
        let keypair = Keypair::Bls(bls_keypair);
        let public_key = keypair.public_key();
        let public_id = PublicId {
            name: public_key.into(),
            public_key,
        };
        Self { keypair, public_id }
    }
}

impl From<BlsKeypairShare> for FullId {
    fn from(bls_share_keypair: BlsKeypairShare) -> Self {
        let keypair = Keypair::BlsShare(bls_share_keypair);
        let public_key = keypair.public_key();
        let public_id = PublicId {
            name: public_key.into(),
            public_key,
        };
        Self { keypair, public_id }
    }
}

impl From<Ed25519Keypair> for FullId {
    fn from(ed25519_keypair: Ed25519Keypair) -> Self {
        let keypair = Keypair::Ed25519(ed25519_keypair);
        let public_key = keypair.public_key();
        let public_id = PublicId {
            name: public_key.into(),
            public_key,
        };
        Self { keypair, public_id }
    }
}

impl From<Ed25519SecretKey> for FullId {
    fn from(secret: Ed25519SecretKey) -> Self {
        let public: Ed25519PublicKey = (&secret).into();
        let pk = PublicKey::Ed25519(public);
        let public_id = PublicId {
            name: pk.into(),
            public_key: pk,
        };
        let keypair = Keypair::Ed25519(Ed25519Keypair { public, secret });
        Self { keypair, public_id }
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

    /// Returns the PublicId serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Creates from z-base-32 encoded string.
    pub fn decode_from_zbase32<T: AsRef<str>>(encoded: T) -> Result<Self, Error> {
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
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, formatter)
    }
}
