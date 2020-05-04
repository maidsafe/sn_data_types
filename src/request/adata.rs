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
    AData, ADataAddress, ADataAppendOperation, ADataIndex, ADataOwner, ADataPubPermissions,
    ADataUnpubPermissions, ADataUser, Error, PublicKey, Response, XorName,
};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// AppendOnlyData request that is sent to vaults.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum ADataRequest {
    /// Put a new AppendOnlyData onto the network.
    Put(AData),
    /// Get AppendOnlyData from the network.
    Get(ADataAddress),
    /// Get AppendOnlyData shell at a certain point in history (`data_index` refers to the list of
    /// data).
    GetShell {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Index of the data at which to get the shell.
        data_index: ADataIndex,
    },
    /// Delete an unpublished `AppendOnlyData`.
    ///
    /// This operation MUST return an error if applied to published AppendOnlyData. Only the current
    /// owner(s) can perform this action.
    Delete(ADataAddress),
    /// Get a range of entries from an AppendOnlyData object on the network.
    GetRange {
        /// AppendOnlyData address.
        address: ADataAddress,
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
        range: (ADataIndex, ADataIndex),
    },
    /// Get AppendOnlyData value.
    GetValue {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Key to get.
        key: Vec<u8>,
    },
    /// Get current indices: data, owners, permissions.
    GetIndices(ADataAddress),
    /// Get an entry with the current index.
    GetLastEntry(ADataAddress),
    /// List all permissions at the provided index.
    GetPermissions {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Permissions index.
        permissions_index: ADataIndex,
    },
    /// Get published permissions for a specified user(s).
    GetPubUserPermissions {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Permissions index.
        permissions_index: ADataIndex,
        /// User to get permissions for.
        user: ADataUser,
    },
    /// Get unpublished permissions for a specified user(s).
    GetUnpubUserPermissions {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Permissions index.
        permissions_index: ADataIndex,
        /// User to get permissions for.
        public_key: PublicKey,
    },
    /// Get owners at the provided index.
    GetOwners {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Onwers index.
        owners_index: ADataIndex,
    },
    /// Add a new published `permissions` entry.
    AddPubPermissions {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Published permissions.
        permissions: ADataPubPermissions,
        /// Index to add to.
        permissions_index: u64,
    },
    /// Add a new unpublished `permissions` entry.
    AddUnpubPermissions {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// Unpublished permissions.
        permissions: ADataUnpubPermissions,
        /// Index to add to.
        permissions_index: u64,
    },
    /// Add a new `owners` entry. Only the current owner(s) can perform this action.
    SetOwner {
        /// AppendOnlyData address.
        address: ADataAddress,
        /// New owner.
        owner: ADataOwner,
        /// Owners index.
        owners_index: u64,
    },
    /// Append sequenced AppendOnlyData at the given index.
    AppendSeq {
        /// Entries to append.
        append: ADataAppendOperation,
        /// Index.
        index: u64,
    },
    /// Append unsequenced AppendOnlyData.
    AppendUnseq(ADataAppendOperation),
}

impl ADataRequest {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use ADataRequest::*;
        match *self {
            Get(address)
            | GetShell { address, .. }
            | GetRange { address, .. }
            | GetValue { address, .. }
            | GetIndices(address)
            | GetLastEntry(address)
            | GetPermissions { address, .. }
            | GetPubUserPermissions { address, .. }
            | GetUnpubUserPermissions { address, .. }
            | GetOwners { address, .. } => {
                if address.is_pub() {
                    Type::PublicGet
                } else {
                    Type::PrivateGet
                }
            }
            Put(_)
            | Delete(_)
            | AddPubPermissions { .. }
            | AddUnpubPermissions { .. }
            | SetOwner { .. }
            | AppendSeq { .. }
            | AppendUnseq(_) => Type::Mutation,
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use ADataRequest::*;
        match *self {
            Get(_) => Response::GetAData(Err(error)),
            GetShell { .. } => Response::GetADataShell(Err(error)),
            GetValue { .. } => Response::GetADataValue(Err(error)),
            GetRange { .. } => Response::GetADataRange(Err(error)),
            GetIndices(_) => Response::GetADataIndices(Err(error)),
            GetLastEntry(_) => Response::GetADataLastEntry(Err(error)),
            GetPermissions { .. } => Response::GetADataPermissions(Err(error)),
            GetPubUserPermissions { .. } => Response::GetPubADataUserPermissions(Err(error)),
            GetUnpubUserPermissions { .. } => Response::GetUnpubADataUserPermissions(Err(error)),
            GetOwners { .. } => Response::GetADataOwners(Err(error)),
            Put(_)
            | Delete(_)
            | AddPubPermissions { .. }
            | AddUnpubPermissions { .. }
            | SetOwner { .. }
            | AppendSeq { .. }
            | AppendUnseq(_) => Response::Mutation(Err(error)),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use ADataRequest::*;
        match *self {
            Put(_)
            | Delete(_)
            | AddPubPermissions { .. }
            | AddUnpubPermissions { .. }
            | SetOwner { .. }
            | AppendSeq { .. }
            | AppendUnseq(_) => AuthorisationKind::Mutation,
            Get(address)
            | GetValue { address, .. }
            | GetShell { address, .. }
            | GetRange { address, .. }
            | GetIndices(address)
            | GetLastEntry(address)
            | GetPermissions { address, .. }
            | GetPubUserPermissions { address, .. }
            | GetUnpubUserPermissions { address, .. }
            | GetOwners { address, .. } => {
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
        use ADataRequest::*;
        match self {
            Put(ref data) => Some(Cow::Borrowed(data.name())),
            Get(ref address)
            | GetValue { ref address, .. }
            | GetShell { ref address, .. }
            | Delete(ref address)
            | GetRange { ref address, .. }
            | GetIndices(ref address)
            | GetLastEntry(ref address)
            | GetPermissions { ref address, .. }
            | GetPubUserPermissions { ref address, .. }
            | GetUnpubUserPermissions { ref address, .. }
            | GetOwners { ref address, .. }
            | AddPubPermissions { ref address, .. }
            | AddUnpubPermissions { ref address, .. }
            | SetOwner { ref address, .. } => Some(Cow::Borrowed(address.name())),
            AppendSeq { ref append, .. } | AppendUnseq(ref append) => {
                Some(Cow::Borrowed(append.address.name()))
            }
        }
    }
}

impl fmt::Debug for ADataRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use ADataRequest::*;
        write!(
            formatter,
            "Request::{}",
            match *self {
                Put(_) => "PutAData",
                Get(_) => "GetAData",
                GetShell { .. } => "GetADataShell",
                GetValue { .. } => "GetADataValue ",
                Delete(_) => "DeleteAData",
                GetRange { .. } => "GetADataRange",
                GetIndices(_) => "GetADataIndices",
                GetLastEntry(_) => "GetADataLastEntry",
                GetPermissions { .. } => "GetADataPermissions",
                GetPubUserPermissions { .. } => "GetPubADataUserPermissions",
                GetUnpubUserPermissions { .. } => "GetUnpubADataUserPermissions",
                GetOwners { .. } => "GetADataOwners",
                AddPubPermissions { .. } => "AddPubADataPermissions",
                AddUnpubPermissions { .. } => "AddUnpubADataPermissions",
                SetOwner { .. } => "SetADataOwner",
                AppendSeq { .. } => "AppendSeq",
                AppendUnseq(_) => "AppendUnseq",
            }
        )
    }
}
