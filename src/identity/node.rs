// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::BlsKeypairShare;
use crate::{Ed25519Digest, Error, PublicKey, Signature, XorName};
use ed25519_dalek::{Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{self, Debug, Display, Formatter};
use threshold_crypto::{
    serde_impl::SerdeSecret, PublicKeyShare as BlsPublicKeyShare,
    SecretKeyShare as BlsSecretKeyShare,
};

/// A struct holding an Ed25519 keypair, an optional BLS keypair share, and the corresponding public
/// ID for a network Node.
#[derive(Serialize, Deserialize)]
pub struct FullId {
    ed25519: Ed25519Keypair,
    bls: Option<BlsKeypairShare>,
    public_id: PublicId,
}

impl FullId {
    /// Constructs a `FullId` with a random Ed25519 keypair and no BLS keys.
    pub fn new<T: CryptoRng + Rng>(rng: &mut T) -> Self {
        let ed25519 = Ed25519Keypair::generate::<Ed25519Digest, _>(rng);
        let name = PublicKey::Ed25519(ed25519.public).into();
        let public_id = PublicId {
            name,
            ed25519: ed25519.public,
            bls: None,
        };
        Self {
            ed25519,
            bls: None,
            public_id,
        }
    }

    /// Constructs a `FullId` whose name is in the interval [start, end] (both endpoints inclusive).
    pub fn within_range<T: CryptoRng + Rng>(start: &XorName, end: &XorName, rng: &mut T) -> Self {
        let mut ed25519 = Ed25519Keypair::generate::<Ed25519Digest, _>(rng);
        loop {
            let name = PublicKey::Ed25519(ed25519.public).into();
            if name >= *start && name <= *end {
                let public_id = PublicId {
                    name,
                    ed25519: ed25519.public,
                    bls: None,
                };
                return Self {
                    ed25519,
                    bls: None,
                    public_id,
                };
            }
            ed25519 = Ed25519Keypair::generate::<Ed25519Digest, _>(rng);
        }
    }

    /// Returns the public ID.
    pub fn public_id(&self) -> &PublicId {
        &self.public_id
    }

    /// Creates a detached Ed25519 signature of `data`.
    pub fn sign_using_ed25519<T: AsRef<[u8]>>(&self, data: T) -> Signature {
        Signature::Ed25519(self.ed25519.sign::<Ed25519Digest>(data.as_ref()))
    }

    /// Creates a detached BLS signature share of `data` if the `self` holds a BLS keypair share.
    pub fn sign_using_bls<T: AsRef<[u8]>>(&self, data: T) -> Option<Signature> {
        self.bls
            .as_ref()
            .map(|bls_keys| Signature::BlsShare(bls_keys.secret.inner().sign(data)))
    }

    /// Sets the `FullId`'s BLS keypair share using the provided BLS secret key share.
    pub fn set_bls_keys(&mut self, bls_secret_key_share: BlsSecretKeyShare) {
        let public = bls_secret_key_share.public_key_share();
        let secret = SerdeSecret(bls_secret_key_share);
        self.public_id.bls = Some(public);
        self.bls = Some(BlsKeypairShare { secret, public });
    }

    /// Clears the `FullId`'s BLS keypair share, i.e. sets it to `None`.
    pub fn clear_bls_keys(&mut self) {
        self.public_id.bls = None;
        self.bls = None;
    }
}

/// A struct representing the public identity of a network Node.
///
/// It includes the Ed25519 public key and the optional BLS public key.  This struct also provides
/// the Node's network address, i.e. `name()` derived from the Ed25519 public key.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicId {
    name: XorName,
    ed25519: Ed25519PublicKey,
    bls: Option<BlsPublicKeyShare>,
}

impl PublicId {
    /// Returns the Node's network address.
    pub fn name(&self) -> &XorName {
        &self.name
    }

    /// Returns the Node's Ed25519 public key.
    pub fn ed25519_public_key(&self) -> &Ed25519PublicKey {
        &self.ed25519
    }

    /// Returns the Node's BLS public key share.
    pub fn bls_public_key(&self) -> &Option<BlsPublicKeyShare> {
        &self.bls
    }

    /// Returns the PublicId serialised and encoded in standard base64.
    pub fn encode_to_base64(&self) -> String {
        super::encode_to_base64(&self)
    }

    /// Create from standard base64 encoded string.
    pub fn decode_from_base64<T: ?Sized + AsRef<[u8]>>(encoded: &T) -> Result<Self, Error> {
        super::decode_from_base64(encoded)
    }
}

impl Serialize for PublicId {
    fn serialize<S: Serializer>(&self, serialiser: S) -> Result<S::Ok, S::Error> {
        (&self.ed25519, &self.bls).serialize(serialiser)
    }
}

impl<'de> Deserialize<'de> for PublicId {
    fn deserialize<D: Deserializer<'de>>(deserialiser: D) -> Result<Self, D::Error> {
        let (ed25519, bls): (Ed25519PublicKey, Option<BlsPublicKeyShare>) =
            Deserialize::deserialize(deserialiser)?;
        let name = PublicKey::Ed25519(ed25519).into();
        Ok(PublicId { name, ed25519, bls })
    }
}

impl Debug for PublicId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Node({:?})", self.ed25519)
    }
}

impl Display for PublicId {
    #[allow(trivial_casts)]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        (self as &Debug).fmt(formatter)
    }
}
