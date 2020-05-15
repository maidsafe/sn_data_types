// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{AuthorisationKind, Type};
use crate::{Error, RegisterTransfer, Response, ValidateTransfer, XorName};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// Money request that is sent to Elders.
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum MoneyRequest {
    // ===== Money =====
    //
    /// Request to validate transfer.
    ValidateTransfer {
        /// The cmd to validate a transfer.
        payload: ValidateTransfer,
    },
    /// Request to register transfer.
    RegisterTransfer {
        /// The cmd to register the consensused transfer.
        payload: RegisterTransfer,
    },
    /// Request to propagate transfer.
    PropagateTransfer {
        /// The cmd to register the consensused transfer.
        payload: RegisterTransfer,
    },
    /// Get key balance.
    GetBalance(XorName),
    /// Get key history since specified index.
    GetHistory {
        /// The xor name of the balance key.
        at: XorName,
        /// The last index of transfers we know of.
        since_index: u64,
    },
}

impl MoneyRequest {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use MoneyRequest::*;
        match *self {
            GetBalance(_) => Type::PrivateGet,
            GetHistory { .. } => Type::PrivateGet,
            ValidateTransfer { .. } => Type::Transfer, // TODO: fix..
            RegisterTransfer { .. } => Type::Transfer, // TODO: fix..
            PropagateTransfer { .. } => Type::Transfer, // TODO: fix..
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use MoneyRequest::*;
        match *self {
            GetBalance(_) => Response::GetBalance(Err(error)),
            GetHistory { .. } => Response::GetHistory(Err(error)),
            ValidateTransfer { .. } => Response::TransferValidation(Err(error)),
            RegisterTransfer { .. } => Response::TransferRegistration(Err(error)),
            PropagateTransfer { .. } => Response::TransferPropagation(Err(error)),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use MoneyRequest::*;
        match self.clone() {
            PropagateTransfer { .. } => AuthorisationKind::None, // the proof has the authority within it
            RegisterTransfer { .. } => AuthorisationKind::None, // the proof has the authority within it
            ValidateTransfer { .. } => AuthorisationKind::MutAndTransferMoney,
            GetBalance(_) => AuthorisationKind::GetBalance, // current state
            GetHistory { .. } => AuthorisationKind::GetHistory, // history of transfers
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dest_address(&self) -> Option<Cow<XorName>> {
        use MoneyRequest::*;
        match self {
            PropagateTransfer { ref payload, .. } => Some(Cow::Owned(XorName::from(
                payload.proof.transfer_cmd.transfer.to, // sent to section where credit is made
            ))),
            RegisterTransfer { ref payload, .. } => Some(Cow::Owned(XorName::from(
                payload.proof.transfer_cmd.transfer.id.actor, // this is handled where the debit is made
            ))),
            ValidateTransfer { ref payload, .. } => {
                Some(Cow::Owned(XorName::from(payload.transfer.id.actor))) // this is handled where the debit is made
            }
            GetBalance(_) => None,
            GetHistory { .. } => None,
        }
    }
}

impl fmt::Debug for MoneyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use MoneyRequest::*;
        write!(
            formatter,
            "MoneyRequest::{}",
            match *self {
                PropagateTransfer { .. } => "PropagateTransfer",
                RegisterTransfer { .. } => "RegisterTransfer",
                ValidateTransfer { .. } => "ValidateTransfer",
                GetBalance(_) => "GetBalance",
                GetHistory { .. } => "GetHistory",
            }
        )
    }
}
