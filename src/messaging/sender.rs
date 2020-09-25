// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub use xor_name::Prefix;

use crate::{utils, AdultDuties, Duty, ElderDuties, PublicKey, Signature};
use ed25519_dalek::PublicKey as Ed25519PublicKey;
use ed25519_dalek::Signature as Ed25519Signature;
use serde::{Deserialize, Serialize};
use signature::Verifier;
use std::{
    fmt::Debug,
    hash::{Hash, Hasher},
};
use threshold_crypto::{
    PublicKey as BlsPublicKey, PublicKeyShare as BlsPublicKeyShare, Signature as BlsSignature,
    SignatureShare as BlsSignatureShare,
};
use xor_name::XorName;

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct MsgSender {
    entity: Entity,
    sig: EntitySignature,
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct SectionKey {
    prefix: Prefix,
    bls_key: BlsPublicKey,
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct ElderKey {
    node_id: Ed25519PublicKey,
    bls_key: BlsPublicKeyShare,
}

/// An entity in the messaging ecosystem.
/// It has an address that can be used for messaging.
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum Entity {
    ///
    Client(PublicKey),
    /// Elder, Adult, or any other sort of node.
    AnyNode(Ed25519PublicKey, Duty),
    ///
    AdultNode(Ed25519PublicKey, AdultDuties),
    ///
    ElderNode(ElderKey, ElderDuties),
    ///
    Section(SectionKey, ElderDuties),
}

///
pub enum EntityId {
    /// Not an xorspace id.
    Client(PublicKey),
    /// An xorspace id.
    Node(Ed25519PublicKey),
    /// Not an xorspace id.
    Section(BlsPublicKey),
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum EntitySignature {
    /// Any constellation.
    Client(Signature),
    /// When acting individually.
    Node(Ed25519Signature),
    /// Elders acting in group.
    Elder(BlsSignatureShare),
    /// The group.
    Section(BlsSignature),
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for EntitySignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        utils::serialise(&self).hash(state)
    }
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum Address {
    ///
    Client(XorName),
    ///
    Node(XorName),
    ///
    Section(XorName),
}

impl Address {
    /// Extracts the underlying XorName.
    pub fn xorname(&self) -> XorName {
        use Address::*;
        match self {
            Client(xorname) | Node(xorname) | Section(xorname) => *xorname,
        }
    }
}

impl MsgSender {
    /// The id of the sender.
    pub fn id(&self) -> EntityId {
        self.entity.id()
    }

    /// The network address of the sender.
    pub fn address(&self) -> Address {
        self.entity.address()
    }

    /// The duty under which the sender operated.
    pub fn duty(&self) -> Option<Duty> {
        use Entity::*;
        match self.entity {
            Client(_) => None,
            AnyNode(_, duty) => Some(duty),
            AdultNode(_, duty) => Some(Duty::Adult(duty)),
            ElderNode(_, duty) | Section(_, duty) => Some(Duty::Elder(duty)),
        }
    }

    /// Verifies a payload as sent by this sender.
    pub fn verify(&self, payload: &[u8]) -> bool {
        self.entity.try_verify(&self.sig, payload)
    }
}

impl Entity {
    /// The id of the entity.
    pub fn id(&self) -> EntityId {
        use Entity::*;
        match self {
            Client(key) => EntityId::Client(*key),
            AnyNode(node_id, ..) | AdultNode(node_id, ..) => EntityId::Node(*node_id),
            ElderNode(key, ..) => EntityId::Node(key.node_id),
            Section(key, ..) => EntityId::Section(key.bls_key),
        }
    }

    /// The address of the entity,
    /// used to send messages to it.
    pub fn address(&self) -> Address {
        use Entity::*;
        match self {
            Client(key) => Address::Client((*key).into()),
            AnyNode(key, ..) | AdultNode(key, ..) => Address::Node(PublicKey::Ed25519(*key).into()),
            ElderNode(key, ..) => Address::Node(PublicKey::Ed25519(key.node_id).into()),
            Section(key, ..) => Address::Section(key.prefix.name()),
        }
    }

    ///
    pub fn try_verify(&self, sig: &EntitySignature, data: &[u8]) -> bool {
        use Entity::*;
        match self {
            Client(key) => {
                if let EntitySignature::Client(sig) = sig {
                    key.verify(sig, data).is_ok()
                } else {
                    false
                }
            }
            AnyNode(key, ..) | AdultNode(key, ..) => {
                if let EntitySignature::Node(sig) = sig {
                    key.verify(data, sig).is_ok()
                } else {
                    false
                }
            }
            ElderNode(key, ..) => {
                if let EntitySignature::Elder(sig) = sig {
                    key.bls_key.verify(sig, data)
                } else if let EntitySignature::Node(sig) = sig {
                    key.node_id.verify(data, sig).is_ok()
                } else {
                    false
                }
            }
            Section(key, ..) => {
                if let EntitySignature::Section(sig) = sig {
                    key.bls_key.verify(sig, data)
                } else {
                    false
                }
            }
        }
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Entity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        utils::serialise(&self).hash(state)
    }
}
