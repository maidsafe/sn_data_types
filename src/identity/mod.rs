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

use crate::XorName;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};
use threshold_crypto::{
    serde_impl::SerdeSecret, PublicKey as BlsPublicKey, PublicKeyShare as BlsPublicKeyShare,
    SecretKey as BlsSecretKey, SecretKeyShare as BlsSecretKeyShare,
};

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
