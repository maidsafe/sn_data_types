// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::Type;
use crate::{Error, IData, IDataAddress, Response};
use serde::{Deserialize, Serialize};
use std::fmt;

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
            Get(address) => {
                if address.is_pub() {
                    Type::PublicGet
                } else {
                    Type::PrivateGet
                }
            }
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
