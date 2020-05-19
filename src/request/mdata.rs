// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{AuthorisationKind, DataAuthKind, Type};
use crate::{
    Error, MData, MDataAddress, MDataEntryActions, MDataPermissionSet, PublicKey, Response, XorName,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// MutableData request that is sent to vaults.
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum MDataRequest {
    /// Put MutableData.
    Put(MData),
    /// Get MutableData.
    Get(MDataAddress),
    /// Get MutableData value.
    GetValue {
        /// MutableData address.
        address: MDataAddress,
        /// Key to get.
        key: Vec<u8>,
    },
    /// Delete MutableData.
    Delete(MDataAddress),
    /// Get MutableData shell.
    GetShell(MDataAddress),
    /// Get MutableData version.
    GetVersion(MDataAddress),
    /// List MutableData entries.
    ListEntries(MDataAddress),
    /// List MutableData keys.
    ListKeys(MDataAddress),
    /// List MutableData values.
    ListValues(MDataAddress),
    /// Set MutableData user permissions.
    SetUserPermissions {
        /// MutableData address.
        address: MDataAddress,
        /// User to set permissions for.
        user: PublicKey,
        /// New permissions.
        permissions: MDataPermissionSet,
        /// Version to set.
        version: u64,
    },
    /// Delete MutableData user permissions.
    DelUserPermissions {
        /// MutableData address.
        address: MDataAddress,
        /// User to delete permissions for.
        user: PublicKey,
        /// Version to delete.
        version: u64,
    },
    /// List MutableData permissions.
    ListPermissions(MDataAddress),
    /// Get MutableData permissions for a user.
    ListUserPermissions {
        /// MutableData address.
        address: MDataAddress,
        /// User to get permissions for.
        user: PublicKey,
    },
    /// Mutate MutableData entries.
    MutateEntries {
        /// MutableData address.
        address: MDataAddress,
        /// Mutation actions to perform.
        actions: MDataEntryActions,
    },
}

impl MDataRequest {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use MDataRequest::*;

        match *self {
            // MData requests (always unpub)
            Get(_)
            | GetValue { .. }
            | GetShell(_)
            | GetVersion(_)
            | ListEntries(_)
            | ListKeys(_)
            | ListValues(_)
            | ListPermissions(_)
            | ListUserPermissions { .. } => Type::PrivateGet,
            Put(_)
            | Delete(_)
            | SetUserPermissions { .. }
            | DelUserPermissions { .. }
            | MutateEntries { .. } => Type::Mutation,
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use MDataRequest::*;

        match *self {
            Get(_) => Response::GetMData(Err(error)),
            GetValue { .. } => Response::GetMDataValue(Err(error)),
            GetShell(_) => Response::GetMDataShell(Err(error)),
            GetVersion(_) => Response::GetMDataVersion(Err(error)),
            ListEntries(_) => Response::ListMDataEntries(Err(error)),
            ListKeys(_) => Response::ListMDataKeys(Err(error)),
            ListValues(_) => Response::ListMDataValues(Err(error)),
            ListPermissions(_) => Response::ListMDataPermissions(Err(error)),
            ListUserPermissions { .. } => Response::ListMDataUserPermissions(Err(error)),
            Put(_)
            | Delete(_)
            | SetUserPermissions { .. }
            | DelUserPermissions { .. }
            | MutateEntries { .. } => Response::Mutation(Err(error)),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use MDataRequest::*;
        match *self {
            Put(_)
            | Delete(_)
            | SetUserPermissions { .. }
            | DelUserPermissions { .. }
            | MutateEntries { .. } => AuthorisationKind::Data(DataAuthKind::Mutation),
            Get(_)
            | GetValue { .. }
            | GetShell(_)
            | GetVersion(_)
            | ListEntries(_)
            | ListKeys(_)
            | ListValues(_)
            | ListPermissions(_)
            | ListUserPermissions { .. } => AuthorisationKind::Data(DataAuthKind::GetPrivate),
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dest_address(&self) -> Option<Cow<XorName>> {
        use MDataRequest::*;
        match self {
            Put(ref data) => Some(Cow::Borrowed(data.name())),
            Get(ref address)
            | GetValue { ref address, .. }
            | Delete(ref address)
            | GetShell(ref address)
            | GetVersion(ref address)
            | ListEntries(ref address)
            | ListKeys(ref address)
            | ListValues(ref address)
            | SetUserPermissions { ref address, .. }
            | DelUserPermissions { ref address, .. }
            | ListPermissions(ref address)
            | ListUserPermissions { ref address, .. }
            | MutateEntries { ref address, .. } => Some(Cow::Borrowed(address.name())),
        }
    }
}

impl fmt::Debug for MDataRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use MDataRequest::*;

        write!(
            formatter,
            "Request::{}",
            match *self {
                Put(_) => "PutMData",
                Get(_) => "GetMData",
                GetValue { .. } => "GetMDataValue",
                Delete(_) => "DeleteMData",
                GetShell(_) => "GetMDataShell",
                GetVersion(_) => "GetMDataVersion",
                ListEntries(_) => "ListMDataEntries",
                ListKeys(_) => "ListMDataKeys",
                ListValues(_) => "ListMDataValues",
                SetUserPermissions { .. } => "SetMDataUserPermissions",
                DelUserPermissions { .. } => "DelMDataUserPermissions",
                ListPermissions(_) => "ListMDataPermissions",
                ListUserPermissions { .. } => "ListMDataUserPermissions",
                MutateEntries { .. } => "MutateMDataEntries",
            }
        )
    }
}
