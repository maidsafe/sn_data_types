// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{AuthorisationKind, Type};
use crate::{
    Error, PublicKey, Response, SData, SDataAddress, SDataIndex, SDataMutationOperation,
    SDataPermissions, SDataUser, XorName,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// Sequence request that is sent to vaults.
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum SDataRequest {
    /// Store a new Sequence onto the network.
    Store(SData),
    /// Get Sequence from the network.
    Get(SDataAddress),
    /// Delete a private Sequence.
    ///
    /// This operation MUST return an error if applied to public Sequence. Only the current
    /// owner(s) can perform this action.
    Delete(SDataAddress),
    /// Get a range of entries from an Sequence object on the network.
    GetRange {
        /// Sequence address.
        address: SDataAddress,
        /// Range of entries to fetch.
        ///
        /// For example, get 10 last entries:
        /// range: (Index::FromEnd(10), Index::FromEnd(0))
        ///
        /// Get all entries:
        /// range: (Index::FromStart(0), Index::FromEnd(0))
        ///
        /// Get first 5 entries:
        /// range: (Index::FromStart(0), Index::FromStart(5))
        range: (SDataIndex, SDataIndex),
    },
    /// Get last entry from the Sequence.
    GetLastEntry(SDataAddress),
    /// List all permissions at the provided index.
    GetPermissions {
        /// Sequence address.
        address: SDataAddress,
        /// Permissions index.
        permissions_index: SDataIndex,
    },
    /// Get permissions for a specified user(s).
    GetUserPermissions {
        /// Sequence address.
        address: SDataAddress,
        /// Permissions index.
        permissions_index: SDataIndex,
        /// User to get permissions for.
        user: SDataUser,
    },
    /// Get owners at the provided index.
    GetOwner {
        /// Sequence address.
        address: SDataAddress,
        /// Onwers index.
        owners_index: SDataIndex,
    },
    /// Set new permissions.
    SetPermissions {
        /// Sequence address.
        address: SDataAddress,
        /// New permissions to set.
        permissions: SDataPermissions,
    },
    /// Add a new `owners` entry. Only the current owner(s) can perform this action.
    SetOwner {
        /// Sequence address.
        address: SDataAddress,
        /// New owner.
        owner: PublicKey,
    },
    /// Mutate the Sequence (insert/remove entry).
    Mutate(SDataMutationOperation),
}

impl SDataRequest {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use SDataRequest::*;

        match *self {
            Get(address)
            | GetRange { address, .. }
            | GetLastEntry(address)
            | GetPermissions { address, .. }
            | GetUserPermissions { address, .. }
            | GetOwner { address, .. } => {
                if address.is_pub() {
                    Type::PublicGet
                } else {
                    Type::PrivateGet
                }
            }
            Store(_) | Delete(_) | SetPermissions { .. } | SetOwner { .. } | Mutate(_) => {
                Type::Mutation
            }
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use SDataRequest::*;

        match *self {
            Get(_) => Response::GetSData(Err(error)),
            GetRange { .. } => Response::GetSDataRange(Err(error)),
            GetLastEntry(_) => Response::GetSDataLastEntry(Err(error)),
            GetPermissions { .. } => Response::GetSDataPermissions(Err(error)),
            GetUserPermissions { .. } => Response::GetSDataUserPermissions(Err(error)),
            GetOwner { .. } => Response::GetSDataOwner(Err(error)),
            Store(_) | Delete(_) | SetPermissions { .. } | SetOwner { .. } | Mutate(_) => {
                Response::Mutation(Err(error))
            }
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use SDataRequest::*;
        match *self {
            Store(_) | Delete(_) | SetPermissions { .. } | SetOwner { .. } | Mutate(_) => {
                AuthorisationKind::Mutation
            }
            Get(address)
            | GetRange { address, .. }
            | GetLastEntry(address)
            | GetPermissions { address, .. }
            | GetUserPermissions { address, .. }
            | GetOwner { address, .. } => {
                if address.is_pub() {
                    AuthorisationKind::GetPub
                } else {
                    AuthorisationKind::GetPriv
                }
            }
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dest_address(&self) -> Option<Cow<XorName>> {
        use SDataRequest::*;
        match self {
            Store(ref data) => Some(Cow::Borrowed(data.name())),
            Get(ref address)
            | Delete(ref address)
            | GetRange { ref address, .. }
            | GetLastEntry(ref address)
            | GetPermissions { ref address, .. }
            | GetUserPermissions { ref address, .. }
            | GetOwner { ref address, .. }
            | SetPermissions { ref address, .. }
            | SetOwner { ref address, .. } => Some(Cow::Borrowed(address.name())),
            Mutate(ref append) => Some(Cow::Borrowed(append.address.name())),
        }
    }
}

impl fmt::Debug for SDataRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use SDataRequest::*;

        write!(
            formatter,
            "Request::{}",
            match *self {
                Store(_) => "StoreSData",
                Get(_) => "GetSData",
                Delete(_) => "DeleteSData",
                GetRange { .. } => "GetSDataRange",
                GetLastEntry(_) => "GetSDataLastEntry",
                GetPermissions { .. } => "GetSDataPermissions",
                GetUserPermissions { .. } => "GetSDataUserPermissions",
                GetOwner { .. } => "GetSDataOwner",
                SetPermissions { .. } => "SetSDataPermissions",
                SetOwner { .. } => "SetSDataOwner",
                Mutate(_) => "Mutate",
            }
        )
    }
}
