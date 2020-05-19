// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{AuthorisationKind, DataAuthKind, Type};
use crate::{Error, IData, IDataAddress, Response, XorName};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// ImmutableData request that is sent to vaults.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum IDataRequest {
    /// Put ImmutableData.
    Put(IData),
    /// Get ImmutableData.
    Get(IDataAddress),
    /// Delete unpublished ImmutableData.
    DeleteUnpub(IDataAddress),
}

impl IDataRequest {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use IDataRequest::*;
        match *self {
            Get(IDataAddress::Pub(_)) => Type::PublicGet,
            Get(IDataAddress::Unpub(_)) => Type::PrivateGet,
            Put(_) | DeleteUnpub(_) => Type::Mutation,
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use IDataRequest::*;
        match *self {
            Get(_) => Response::GetIData(Err(error)),
            Put(_) | DeleteUnpub(_) => Response::Mutation(Err(error)),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use IDataRequest::*;
        match *self {
            Get(IDataAddress::Pub(_)) => AuthorisationKind::Data(DataAuthKind::GetPublic),
            Get(IDataAddress::Unpub(_)) => AuthorisationKind::Data(DataAuthKind::GetPrivate),
            Put(_) | DeleteUnpub(_) => AuthorisationKind::Data(DataAuthKind::Mutation),
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dest_address(&self) -> Option<Cow<XorName>> {
        use IDataRequest::*;
        match self {
            Get(ref address) | DeleteUnpub(ref address) => Some(Cow::Borrowed(address.name())),
            Put(ref data) => Some(Cow::Borrowed(data.name())),
        }
    }
}

impl fmt::Debug for IDataRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use IDataRequest::*;
        write!(
            formatter,
            "Request::{}",
            match *self {
                Put(_) => "PutIData",
                Get(_) => "GetIData",
                DeleteUnpub(_) => "DeleteUnpubIData",
            }
        )
    }
}
