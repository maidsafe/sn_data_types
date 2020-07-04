// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod account;
mod blob;
mod client;
mod gateway;
mod map;
mod money;
mod node;
mod read;
mod sequence;
mod system;
mod write;

pub use self::{
    account::{Account, AccountRead, AccountWrite, MAX_LOGIN_PACKET_BYTES},
    blob::{BlobRead, BlobWrite},
    client::ClientRequest,
    gateway::GatewayRequest,
    map::{MapRead, MapWrite},
    node::NodeRequest,
    read::Read,
    sequence::{SequenceRead, SequenceWrite},
    system::{ClientAuth, SystemOp, Transfers},
    write::Write,
};
use crate::{Error, Response, XorName};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// TODO
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Client
    Client(ClientRequest),
    /// Gateway
    Gateway(GatewayRequest),
    /// Node
    Node(NodeRequest),
}

/// The type of a `Request`.
#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Type {
    /// Request is a Read of public data.
    PublicRead,
    /// Request is a Read of private data.
    PrivateRead,
    /// Request is a Write.
    Write,
    /// Request is a Transfer.
    Transfer,
}

/// The kind of authorisation needed for a request.
pub enum AuthorisationKind {
    /// Authorisation for data requests.
    Data(DataAuthKind),
    /// Authorisation for money requests.
    Money(MoneyAuthKind),
    /// Miscellaneous authorisation kinds.
    /// NB: Not very well categorized yet
    Misc(MiscAuthKind),
    /// When none required.
    None,
}

/// Authorisation for data requests.
pub enum DataAuthKind {
    /// Read of public data.
    PublicRead,
    /// Read of private data.
    PrivateRead,
    /// Write of data/metadata.
    Write,
}

/// Authorisation for money requests.
pub enum MoneyAuthKind {
    /// Request to get key balance.
    ReadBalance,
    /// Request to get key transfer history.
    ReadHistory,
    /// Request to transfer money from key.
    Transfer,
}

/// Miscellaneous authorisation kinds.
/// NB: Not very well categorized yet
pub enum MiscAuthKind {
    /// Request to manage app keys.
    ManageAppKeys,
    /// Request to mutate and transfer money from key.
    WriteAndTransfer,
}

impl Request {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use Request::*;
        match self {
            Node(req) => req.get_type(),
            Client(req) => req.get_type(),
            Gateway(req) => req.get_type(),
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use Request::*;
        match self {
            Node(req) => req.error_response(error),
            Client(req) => req.error_response(error),
            Gateway(req) => req.error_response(error),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use Request::*;
        match self {
            Node(req) => req.authorisation_kind(),
            Client(req) => req.authorisation_kind(),
            Gateway(req) => req.authorisation_kind(),
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> Option<Cow<XorName>> {
        use Request::*;
        match self {
            Node(req) => req.dst_address(),
            Client(req) => req.dst_address(),
            Gateway(req) => req.dst_address(),
        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use Request::*;
        match self {
            Node(req) => write!(formatter, "{:?}", req),
            Client(req) => write!(formatter, "{:?}", req),
            Gateway(req) => write!(formatter, "{:?}", req),
        }
    }
}
