// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{AuthorisationKind, DataAuthKind, Type};
use crate::{
    Error, MData as Map, MDataAddress as Address, MDataEntryActions as Changes,
    MDataPermissionSet as PermissionSet, PublicKey, Response, XorName,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// TODO: docs
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum MapRead {
    /// Get Map.
    Get(Address),
    /// Get Map value.
    GetValue {
        /// Map address.
        address: Address,
        /// Key to get.
        key: Vec<u8>,
    },
    /// Get Map shell.
    GetShell(Address),
    /// Get Map version.
    GetVersion(Address),
    /// List Map entries.
    ListEntries(Address),
    /// List Map keys.
    ListKeys(Address),
    /// List Map values.
    ListValues(Address),
    /// List Map permissions.
    ListPermissions(Address),
    /// Get Map permissions for a user.
    ListUserPermissions {
        /// Map address.
        address: Address,
        /// User to get permissions for.
        user: PublicKey,
    },
}

/// TODO: docs
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum MapWrite {
    /// Create new Map.
    New(Map),
    /// Delete instance.
    Delete(Address),
    /// Edit entries.
    Edit {
        /// Map address.
        address: Address,
        /// Changes to apply.
        changes: Changes,
    },
    /// Delete user permissions.
    DelUserPermissions {
        /// Map address.
        address: Address,
        /// User to delete permissions for.
        user: PublicKey,
        /// Version to delete.
        version: u64,
    },
    /// Set user permissions.
    SetUserPermissions {
        /// Map address.
        address: Address,
        /// User to set permissions for.
        user: PublicKey,
        /// New permissions.
        permissions: PermissionSet,
        /// Version to set.
        version: u64,
    },
}

impl MapRead {
    /// Get the `Type` of this request.
    pub fn get_type(&self) -> Type {
        use MapRead::*;
        match *self {
            // Map requests
            Get(_)
            | GetValue { .. }
            | GetShell(_)
            | GetVersion(_)
            | ListEntries(_)
            | ListKeys(_)
            | ListValues(_)
            | ListPermissions(_)
            | ListUserPermissions { .. } => Type::PrivateRead,
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use MapRead::*;
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
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use MapRead::*;
        match *self {
            Get(_)
            | GetValue { .. }
            | GetShell(_)
            | GetVersion(_)
            | ListEntries(_)
            | ListKeys(_)
            | ListValues(_)
            | ListPermissions(_)
            | ListUserPermissions { .. } => AuthorisationKind::Data(DataAuthKind::PrivateRead),
        }
    }

    /// Returns the address of the destination for request.
    pub fn dst_address(&self) -> Option<Cow<XorName>> {
        use MapRead::*;
        match self {
            Get(ref address)
            | GetValue { ref address, .. }
            | GetShell(ref address)
            | GetVersion(ref address)
            | ListEntries(ref address)
            | ListKeys(ref address)
            | ListValues(ref address)
            | ListPermissions(ref address)
            | ListUserPermissions { ref address, .. } => Some(Cow::Borrowed(address.name())),
        }
    }
}

impl fmt::Debug for MapRead {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use MapRead::*;
        write!(
            formatter,
            "Request::{}",
            match *self {
                Get(_) => "GetMap",
                GetValue { .. } => "GetMapValue",
                GetShell(_) => "GetMapShell",
                GetVersion(_) => "GetMapVersion",
                ListEntries(_) => "ListMapEntries",
                ListKeys(_) => "ListMapKeys",
                ListValues(_) => "ListMapValues",
                ListPermissions(_) => "ListMapPermissions",
                ListUserPermissions { .. } => "ListMapUserPermissions",
            }
        )
    }
}

impl MapWrite {
    /// Get the `Type` of this write.
    pub fn get_type(&self) -> Type {
        Type::Write
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        Response::Write(Err(error))
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        AuthorisationKind::Data(DataAuthKind::Write)
    }

    /// Returns the address of the destination for request.
    pub fn dst_address(&self) -> Option<Cow<XorName>> {
        use MapWrite::*;
        match self {
            New(ref data) => Some(Cow::Borrowed(data.name())),
            Delete(ref address)
            | SetUserPermissions { ref address, .. }
            | DelUserPermissions { ref address, .. }
            | Edit { ref address, .. } => Some(Cow::Borrowed(address.name())),
        }
    }
}

impl fmt::Debug for MapWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use MapWrite::*;
        write!(
            formatter,
            "Request::{}",
            match *self {
                New(_) => "NewMap",
                Delete(_) => "DeleteMap",
                SetUserPermissions { .. } => "SetMapUserPermissions",
                DelUserPermissions { .. } => "DelMapUserPermissions",
                Edit { .. } => "EditMap",
            }
        )
    }
}
