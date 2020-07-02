// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{
    account::AccountWrite, blob::BlobWrite, map::MapWrite, sequence::SequenceWrite,
    AuthorisationKind, Type,
};
use crate::{Error, Response, XorName};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// TODO: docs
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum Write {
    /// TODO: docs
    Blob(BlobWrite),
    /// TODO: docs
    Map(MapWrite),
    /// TODO: docs
    Sequence(SequenceWrite),
    /// Use this only while we don't
    /// have Authenticator as its own app.
    Account(AccountWrite), // <- "LoginPacket"
}

impl Write {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use Write::*;
        match self {
            Blob(req) => req.get_type(),
            Map(req) => req.get_type(),
            Sequence(req) => req.get_type(),
            Account(req) => req.get_type(),
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use Write::*;
        match self {
            Blob(req) => req.error_response(error),
            Map(req) => req.error_response(error),
            Sequence(req) => req.error_response(error),
            Account(req) => req.error_response(error),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use Write::*;
        match self {
            Blob(req) => req.authorisation_kind(),
            Map(req) => req.authorisation_kind(),
            Sequence(req) => req.authorisation_kind(),
            Account(req) => req.authorisation_kind(),
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> Option<Cow<XorName>> {
        use Write::*;
        match self {
            Blob(req) => req.dst_address(),
            Map(req) => req.dst_address(),
            Sequence(req) => req.dst_address(),
            Account(req) => req.dst_address(),
        }
    }
}

impl fmt::Debug for Write {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use Write::*;
        match self {
            Blob(req) => write!(formatter, "{:?}", req),
            Map(req) => write!(formatter, "{:?}", req),
            Sequence(req) => write!(formatter, "{:?}", req),
            Account(req) => write!(formatter, "{:?}", req),
        }
    }
}
