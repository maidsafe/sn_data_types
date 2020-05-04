// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod adata;
mod client_req;
mod coins;
mod idata;
mod login_packet;
mod mdata;

pub use self::login_packet::{LoginPacket, LoginPacketRequest, MAX_LOGIN_PACKET_BYTES};
use crate::{Error, Response};
pub use adata::ADataRequest;
pub use client_req::ClientRequest;
pub use coins::CoinsRequest;
pub use idata::IDataRequest;
pub use mdata::MDataRequest;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The type of a `Request`.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Type {
    /// Request is a Get for public data.
    PublicGet,
    /// Request is a Get for private data.
    PrivateGet,
    /// Request is a Mutation.
    Mutation,
    /// Request is a Transaction.
    Transaction,
}

/// RPC Request that is sent to vaults.
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Request {
    /// ImmutableData request
    IData(IDataRequest),
    /// MutableData request
    MData(MDataRequest),
    /// AppendOnlyData request
    AData(ADataRequest),
    /// Coins request
    Coins(CoinsRequest),
    /// LoginPacket request
    LoginPacket(LoginPacketRequest),
    /// Client (Owner) request
    Client(ClientRequest),
}

impl Request {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use Request::*;

        match self {
            IData(req) => req.get_type(),
            MData(req) => req.get_type(),
            AData(req) => req.get_type(),
            Coins(req) => req.get_type(),
            LoginPacket(req) => req.get_type(),
            Client(req) => req.get_type(),
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use Request::*;

        match self {
            IData(req) => req.error_response(error),
            MData(req) => req.error_response(error),
            AData(req) => req.error_response(error),
            Coins(req) => req.error_response(error),
            LoginPacket(req) => req.error_response(error),
            Client(req) => req.error_response(error),
        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use Request::*;

        match self {
            IData(req) => write!(formatter, "{:?}", req),
            MData(req) => write!(formatter, "{:?}", req),
            AData(req) => write!(formatter, "{:?}", req),
            Coins(req) => write!(formatter, "{:?}", req),
            LoginPacket(req) => write!(formatter, "{:?}", req),
            Client(req) => write!(formatter, "{:?}", req),
        }
    }
}
