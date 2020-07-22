// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{utils, PublicKey, Signature, SignatureShare};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Debug, Formatter},
    hash::{Hash, Hasher},
};

///
#[derive(Debug, Hash, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proof {
    ///
    Bls(BlsProof),
    ///
    BlsShare(BlsProofShare),
    ///
    Ed25519(Ed25519Proof),
}

impl Proof {
    ///
    pub fn id(&self) -> PublicKey {
        use Proof::*;
        match self {
            Bls(proof) => proof.id(),
            BlsShare(proof) => proof.id(),
            Ed25519(proof) => proof.id(),
        }
    }

    ///
    pub fn signature(&self) -> Signature {
        use Proof::*;
        match self {
            Bls(proof) => proof.signature(),
            BlsShare(proof) => proof.signature(),
            Ed25519(proof) => proof.signature(),
        }
    }

    ///
    pub fn verify(&self, payload: &[u8]) -> bool {
        use Proof::*;
        match self {
            Bls(proof) => proof.verify(payload),
            BlsShare(proof) => proof.verify(payload),
            Ed25519(proof) => proof.verify(payload),
        }
    }
}

///
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ed25519Proof {
    /// The public key.
    pub public_key: ed25519_dalek::PublicKey,
    /// The signature corresponding to the public key.
    pub signature: ed25519_dalek::Signature,
}

impl Ed25519Proof {
    ///
    pub fn id(&self) -> PublicKey {
        PublicKey::Ed25519(self.public_key)
    }

    ///
    pub fn signature(&self) -> Signature {
        Signature::Ed25519(self.signature)
    }

    /// Verifies this proof against the payload.
    pub fn verify(&self, payload: &[u8]) -> bool {
        self.id().verify(&self.signature(), payload).is_ok()
    }
}

// Need to manually implement this due to a missing impl in `Ed25519::Keypair`.
impl PartialEq for Ed25519Proof {
    fn eq(&self, other: &Self) -> bool {
        // TODO: After const generics land, remove the `to_vec()` calls.
        self.public_key.to_bytes().to_vec() == other.public_key.to_bytes().to_vec()
            && self.signature.to_bytes().to_vec() == other.signature.to_bytes().to_vec()
    }
}

// Need to manually implement this due to a missing impl in `Ed25519::Keypair`.
impl Eq for Ed25519Proof {}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Ed25519Proof {
    fn hash<H: Hasher>(&self, state: &mut H) {
        utils::serialise(&self).hash(state)
    }
}

/// Proof that a quorum of the section elders has agreed on something.
#[derive(Clone, Hash, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BlsProof {
    /// The public key.
    pub public_key: bls::PublicKey,
    /// The signature corresponding to the public key.
    pub signature: bls::Signature,
}

impl BlsProof {
    /// Verifies this proof against the payload.
    pub fn verify(&self, payload: &[u8]) -> bool {
        self.public_key.verify(&self.signature, payload)
    }

    ///
    pub fn id(&self) -> PublicKey {
        PublicKey::Bls(self.public_key)
    }

    ///
    pub fn signature(&self) -> Signature {
        Signature::Bls(self.signature.clone())
    }
}

/// Single share of `Proof`.
#[derive(Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsProofShare {
    /// BLS public key set.
    pub public_key_set: bls::PublicKeySet,
    /// Index of the node that created this proof share.
    pub index: usize,
    /// BLS signature share corresponding to the `index`-th public key share of the public key set.
    pub signature_share: bls::SignatureShare,
}

impl BlsProofShare {
    /// Creates new proof share.
    pub fn new(
        public_key_set: bls::PublicKeySet,
        index: usize,
        secret_key_share: &bls::SecretKeyShare,
        payload: &[u8],
    ) -> Self {
        Self {
            public_key_set,
            index,
            signature_share: secret_key_share.sign(payload),
        }
    }

    ///
    pub fn id(&self) -> PublicKey {
        PublicKey::BlsShare(self.public_key_set.public_key_share(self.index))
    }

    ///
    pub fn signature(&self) -> Signature {
        Signature::BlsShare(SignatureShare {
            index: self.index,
            share: self.signature_share.clone(),
        })
    }

    /// Verifies this proof share against the payload.
    pub fn verify(&self, payload: &[u8]) -> bool {
        self.public_key_set
            .public_key_share(self.index)
            .verify(&self.signature_share, payload)
    }
}

impl Debug for BlsProofShare {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "ProofShare {{ public_key: {:?}, index: {}, .. }}",
            self.public_key_set.public_key(),
            self.index
        )
    }
}

/// A value together with the proof that it was agreed on by the quorum of the section elders.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Proven<T> {
    ///
    pub value: T,
    ///
    pub proof: BlsProof,
}

impl<T> Proven<T> {
    ///
    pub fn new(value: T, proof: BlsProof) -> Self {
        Self { value, proof }
    }
}
