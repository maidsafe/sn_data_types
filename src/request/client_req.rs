// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{AuthorisationKind, MiscAuthKind, Type};
use crate::{AppPermissions, Error, PublicKey, Response, XorName};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// Client (Owner) request that is sent to vaults.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum ClientRequest {
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

impl ClientRequest {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use ClientRequest::*;
        match *self {
            ListAuthKeysAndVersion => Type::PrivateRead,
            InsAuthKey { .. } | DelAuthKey { .. } => Type::Write,
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use ClientRequest::*;
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
    pub fn dest_address(&self) -> Option<Cow<XorName>> {
        None
    }
}

impl fmt::Debug for ClientRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use ClientRequest::*;

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
