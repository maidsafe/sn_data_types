// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{Ed25519Digest, Error, XorName, XOR_NAME_LEN};
use ed25519_dalek;
use hex_fmt::HexFmt;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use threshold_crypto;

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum PublicKey {
    Ed25519(ed25519_dalek::PublicKey),
    Bls(threshold_crypto::PublicKey),
    BlsShare(threshold_crypto::PublicKeyShare),
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            PublicKey::Ed25519(ref pk) => pk.as_bytes().hash(state),
            PublicKey::Bls(ref pk) => pk.hash(state),
            PublicKey::BlsShare(ref pk) => pk.hash(state),
        }
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &PublicKey) -> Ordering {
        (&*self.as_bytes()).cmp(&*other.as_bytes())
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PublicKey {
    fn as_bytes(&self) -> Box<[u8]> {
        // TODO: return &[u8] for efficiency
        match self {
            PublicKey::Ed25519(ref pk) => Box::new(*pk.as_bytes()),
            PublicKey::Bls(ref pk) => Box::new(pk.to_bytes()),
            PublicKey::BlsShare(ref pk) => Box::new(pk.to_bytes()),
        }
    }

    pub fn verify_detached<T: AsRef<[u8]>>(
        &self,
        signature: &Signature,
        data: T,
    ) -> Result<(), Error> {
        let is_valid = match (self, signature) {
            (PublicKey::Ed25519(pub_key), Signature::Ed25519(sig)) => {
                pub_key.verify::<Ed25519Digest>(data.as_ref(), sig).is_ok()
            }
            (PublicKey::Bls(pub_key), Signature::Bls(sig)) => pub_key.verify(sig, data),
            (PublicKey::BlsShare(pub_key), Signature::BlsShare(sig)) => pub_key.verify(sig, data),
            _ => return Err(Error::SigningKeyTypeMismatch),
        };
        if is_valid {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl From<PublicKey> for XorName {
    fn from(public_key: PublicKey) -> Self {
        let bytes = match public_key {
            PublicKey::Ed25519(pub_key) => {
                return XorName(pub_key.to_bytes());
            }
            PublicKey::Bls(pub_key) => pub_key.to_bytes(),
            PublicKey::BlsShare(pub_key) => pub_key.to_bytes(),
        };
        let mut xor_name = XorName::default();
        xor_name.0.clone_from_slice(&bytes[..XOR_NAME_LEN]);
        xor_name
    }
}

impl From<threshold_crypto::PublicKey> for PublicKey {
    fn from(pk: threshold_crypto::PublicKey) -> Self {
        PublicKey::Bls(pk)
    }
}

impl Debug for PublicKey {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            PublicKey::Ed25519(pub_key) => {
                write!(formatter, "Ed25519({:<8})", HexFmt(&pub_key.to_bytes()))
            }
            PublicKey::Bls(pub_key) => write!(
                formatter,
                "Bls({:<8})",
                HexFmt(&pub_key.to_bytes()[..XOR_NAME_LEN])
            ),
            PublicKey::BlsShare(pub_key) => write!(
                formatter,
                "BlsShare({:<8})",
                HexFmt(&pub_key.to_bytes()[..XOR_NAME_LEN])
            ),
        }
    }
}

impl Display for PublicKey {
    #[allow(trivial_casts)]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        (self as &Debug).fmt(formatter)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum Signature {
    Ed25519(ed25519_dalek::Signature),
    Bls(threshold_crypto::Signature),
    BlsShare(threshold_crypto::SignatureShare),
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Signature::Ed25519(ref sig) => sig.to_bytes().hash(state),
            Signature::Bls(ref sig) => sig.hash(state),
            Signature::BlsShare(ref sig) => sig.hash(state),
        }
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Signature) -> Ordering {
        (&*self.as_bytes()).cmp(&*other.as_bytes())
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Signature) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Signature {
    fn as_bytes(&self) -> Box<[u8]> {
        // TODO: return &[u8] for efficiency
        match self {
            Signature::Ed25519(ref sig) => Box::new(sig.to_bytes()),
            Signature::Bls(ref sig) => Box::new(sig.to_bytes()),
            Signature::BlsShare(ref sig) => Box::new(sig.to_bytes()),
        }
    }
}

impl Debug for Signature {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            Signature::Ed25519(_) => write!(formatter, "Ed25519 Sig(..)"),
            Signature::Bls(_) => write!(formatter, "Bls Sig(..)"),
            Signature::BlsShare(_) => write!(formatter, "BlsShare Sig(..)"),
        }
    }
}
