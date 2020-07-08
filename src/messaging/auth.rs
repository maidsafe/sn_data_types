// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

pub use super::transfer::{TransferCmd, TransferQuery};
use super::{AuthorisationKind, CmdError, MiscAuthKind, QueryResponse};
use crate::{AppPermissions, Error, PublicKey, XorName};
use serde::{Deserialize, Serialize};
use std::fmt;

/// To be removed.
/// Use this only while we don't
/// have Authenticator as its own app.
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum AuthCmd {
    /// Insert an authorised key (for an app, user, etc.).
    InsAuthKey {
        /// The Client id.
        client: PublicKey,
        /// Authorised key to be inserted
        key: PublicKey,
        /// Incremented version
        version: u64,
        /// Permissions
        permissions: AppPermissions,
    },
    /// Delete an authorised key.
    DelAuthKey {
        /// The Client id.
        client: PublicKey,
        /// Authorised key to be deleted
        key: PublicKey,
        /// Incremented version
        version: u64,
    },
}

/// Former ClientAuth
/// To be removed.
/// Use this only while we don't
/// have Authenticator as its own app.
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum AuthQuery {
    /// Insert an authorised key (for an app, user, etc.).
    ListAuthKeysAndVersion {
        /// The Client id.
        client: PublicKey,
    },
}

impl AuthCmd {
    // /// Get the `Type` of this `Request`.
    // pub fn get_type(&self) -> Type {
    //     use ClientAuth::*;
    //     match *self {
    //         ListAuthKeysAndVersion => Type::PrivateRead,
    //         InsAuthKey { .. } | DelAuthKey { .. } => Type::Write,
    //     }
    // }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> CmdError {
        CmdError::Auth(error)
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        AuthorisationKind::Misc(MiscAuthKind::ManageAppKeys)
    }

    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> XorName {
        use AuthCmd::*;
        match *self {
            InsAuthKey { client, .. } | DelAuthKey { client, .. } => client.into(),
        }
    }
}

impl fmt::Debug for AuthCmd {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use AuthCmd::*;
        write!(
            formatter,
            "AuthCmd::{}",
            match *self {
                InsAuthKey { .. } => "InsAuthKey",
                DelAuthKey { .. } => "DelAuthKey",
            }
        )
    }
}

impl AuthQuery {
    // /// Get the `Type` of this `Request`.
    // pub fn get_type(&self) -> Type {
    //     use ClientAuth::*;
    //     match *self {
    //         ListAuthKeysAndVersion => Type::PrivateRead,
    //         InsAuthKey { .. } | DelAuthKey { .. } => Type::Write,
    //     }
    // }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> QueryResponse {
        use AuthQuery::*;
        match *self {
            ListAuthKeysAndVersion { .. } => QueryResponse::ListAuthKeysAndVersion(Err(error)),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        AuthorisationKind::Misc(MiscAuthKind::ManageAppKeys)
    }

    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> XorName {
        use AuthQuery::*;
        match *self {
            ListAuthKeysAndVersion { client, .. } => client.into(),
        }
    }
}

impl fmt::Debug for AuthQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use AuthQuery::*;
        write!(
            formatter,
            "AuthQuery::{}",
            match *self {
                ListAuthKeysAndVersion { .. } => "ListAuthKeysAndVersion",
            }
        )
    }
}
