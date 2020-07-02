// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub use super::money::MoneyRequest as Transfers;
use super::{AuthorisationKind, MiscAuthKind, Type};
use crate::{AppPermissions, Error, PublicKey, Response, XorName};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// Read and Write
/// requests _without_ cost.
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum SystemOp {
    /// Former MoneyRequest (just playing around to try find a good name)
    Transfers(Transfers),
    /// Former ClientAuth
    /// To be removed.
    /// Use this only while we don't
    /// have Authenticator as its own app.
    ClientAuth(ClientAuth),
}

impl SystemOp {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use SystemOp::*;
        match self {
            Transfers(req) => req.get_type(),
            ClientAuth(req) => req.get_type(),
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use SystemOp::*;
        match self {
            Transfers(req) => req.error_response(error),
            ClientAuth(req) => req.error_response(error),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use SystemOp::*;
        match self {
            Transfers(req) => req.authorisation_kind(),
            ClientAuth(req) => req.authorisation_kind(),
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> Option<Cow<XorName>> {
        use SystemOp::*;
        match self {
            Transfers(req) => req.dst_address(),
            ClientAuth(req) => req.dst_address(),
        }
    }
}

impl fmt::Debug for SystemOp {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use SystemOp::*;
        match self {
            Transfers(req) => write!(formatter, "{:?}", req),
            ClientAuth(req) => write!(formatter, "{:?}", req),
        }
    }
}

/// Former ClientAuth
/// To be removed.
/// Use this only while we don't
/// have Authenticator as its own app.
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum ClientAuth {
    /// List authorised keys and version stored by Elders.
    ListAuthKeysAndVersion,
    /// Insert an authorised key (for an app, user, etc.).
    InsAuthKey {
        /// Authorised key to be inserted
        key: PublicKey,
        /// Incremented version
        version: u64,
        /// Permissions
        permissions: AppPermissions,
    },
    /// Delete an authorised key.
    DelAuthKey {
        /// Authorised key to be deleted
        key: PublicKey,
        /// Incremented version
        version: u64,
    },
}

impl ClientAuth {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use ClientAuth::*;
        match *self {
            ListAuthKeysAndVersion => Type::PrivateRead,
            InsAuthKey { .. } | DelAuthKey { .. } => Type::Write,
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use ClientAuth::*;
        match *self {
            ListAuthKeysAndVersion => Response::ListAuthKeysAndVersion(Err(error)),
            InsAuthKey { .. } | DelAuthKey { .. } => Response::Write(Err(error)),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        AuthorisationKind::Misc(MiscAuthKind::ManageAppKeys)
    }

    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> Option<Cow<XorName>> {
        None
    }
}

impl fmt::Debug for ClientAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use ClientAuth::*;
        write!(
            formatter,
            "Request::{}",
            match *self {
                ListAuthKeysAndVersion => "ListAuthKeysAndVersion",
                InsAuthKey { .. } => "InsAuthKey",
                DelAuthKey { .. } => "DelAuthKey",
            }
        )
    }
}
