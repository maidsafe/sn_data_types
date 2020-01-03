// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{utils, Ed25519Digest, Error, Result, XorName, XOR_NAME_LEN};
use ed25519_dalek;
use hex_fmt::HexFmt;
use multibase::Decodable;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    fmt::{self, Debug, Display, Formatter},
    hash::{Hash, Hasher},
};
use threshold_crypto;

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum PublicKey {
    Ed25519(ed25519_dalek::PublicKey),
    Bls(threshold_crypto::PublicKey),
    BlsShare(threshold_crypto::PublicKeyShare),
}

impl PublicKey {
    pub fn verify<T: AsRef<[u8]>>(&self, signature: &Signature, data: T) -> Result<()> {
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

    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    pub fn decode_from_zbase32<I: Decodable>(encoded: I) -> Result<Self> {
        utils::decode(encoded)
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        utils::serialise(&self).hash(state)
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &PublicKey) -> Ordering {
        utils::serialise(&self).cmp(&utils::serialise(other))
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
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

impl From<ed25519_dalek::PublicKey> for PublicKey {
    fn from(public_key: ed25519_dalek::PublicKey) -> Self {
        PublicKey::Ed25519(public_key)
    }
}

impl From<threshold_crypto::PublicKey> for PublicKey {
    fn from(public_key: threshold_crypto::PublicKey) -> Self {
        PublicKey::Bls(public_key)
    }
}

impl From<threshold_crypto::PublicKeyShare> for PublicKey {
    fn from(public_key: threshold_crypto::PublicKeyShare) -> Self {
        PublicKey::BlsShare(public_key)
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
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, formatter)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum Signature {
    Ed25519(ed25519_dalek::Signature),
    Bls(threshold_crypto::Signature),
    BlsShare(threshold_crypto::SignatureShare),
}

impl From<threshold_crypto::Signature> for Signature {
    fn from(sig: threshold_crypto::Signature) -> Self {
        Signature::Bls(sig)
    }
}

impl From<ed25519_dalek::Signature> for Signature {
    fn from(sig: ed25519_dalek::Signature) -> Self {
        Signature::Ed25519(sig)
    }
}

impl From<threshold_crypto::SignatureShare> for Signature {
    fn from(sig: threshold_crypto::SignatureShare) -> Self {
        Signature::BlsShare(sig)
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        utils::serialise(&self).hash(state)
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Signature) -> Ordering {
        utils::serialise(&self).cmp(&utils::serialise(other))
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Signature) -> Option<Ordering> {
        Some(self.cmp(other))
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

#[cfg(test)]
mod test {
    use super::*;
    use threshold_crypto::SecretKey;

    #[test]
    fn zbase32_encode_decode_public_key() {
        use unwrap::unwrap;
        let key = PublicKey::Bls(SecretKey::random().public_key());
        assert_eq!(
            key,
            unwrap!(PublicKey::decode_from_zbase32(&key.encode_to_zbase32()))
        );
    }
}
