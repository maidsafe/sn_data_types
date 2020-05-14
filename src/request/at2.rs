// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{AuthorisationKind, Type};
use crate::{Error, RegisterTransfer, Response, TransferRestrictions, ValidateTransfer, XorName};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// AT2 request that is sent to Elders.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum AT2Request {
    // ===== AT2 =====
    //
    /// Request to validate transfer.
    Validate {
        /// The cmd to validate a transfer.
        payload: ValidateTransfer,
    },
    /// Request to register transfer.
    Register {
        /// The cmd to register the consensused transfer.
        payload: RegisterTransfer,
    },
    /// Get account balance.
    GetBalance(XorName),
    /// Get account history.
    GetHistory(XorName),
}

impl AT2Request {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use AT2Request::*;
        match *self {
            GetBalance(_) => Type::PrivateGet,
            GetHistory(_) => Type::PrivateGet,
            Validate { .. } => Type::Transfer, // TODO: fix..
            Register { .. } => Type::Transfer, // TODO: fix..
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use AT2Request::*;
        match *self {
            GetBalance(_) => Response::GetBalance(Err(error)),
            GetHistory(_) => Response::GetHistory(Err(error)),
            Validate { .. } => Response::TransferValidated(Err(error)),
            Register { .. } => Response::TransferRegistered(Err(error)),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use AT2Request::*;
        use TransferRestrictions::*;
        match self.clone() {
            Register { .. } => AuthorisationKind::None, // the proof has the authority within it
            Validate { payload, .. } => {
                match payload.transfer.restrictions {
                    NoRestriction => AuthorisationKind::MutAndTransferMoney,
                    RequireHistory => AuthorisationKind::TransferMoney,
                    ExpectNoHistory => {
                        if payload.transfer.amount.as_nano() == 0 {
                            return AuthorisationKind::Mutation; // just create the account
                        } else {
                            // create and transfer the amount
                            return AuthorisationKind::MutAndTransferMoney;
                        };
                    }
                }
            }
            GetBalance(_) => AuthorisationKind::GetBalance, // current state
            GetHistory(_) => AuthorisationKind::GetHistory, // history of transfers
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dest_address(&self) -> Option<Cow<XorName>> {
        use AT2Request::*;
        match self {
            Register { ref payload, .. } => Some(Cow::Owned(XorName::from(
                payload.proof.transfer_cmd.transfer.to,
            ))),
            Validate { ref payload, .. } => Some(Cow::Owned(XorName::from(payload.transfer.to))),
            GetBalance(_) => None,
            GetHistory(_) => None,
        }
    }
}

impl fmt::Debug for AT2Request {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use AT2Request::*;
        write!(
            formatter,
            "AT2Request::{}",
            match *self {
                Register { .. } => "Register",
                Validate { .. } => "Validate",
                GetBalance(_) => "GetBalance",
                GetHistory(_) => "GetHistory",
            }
        )
    }
}
