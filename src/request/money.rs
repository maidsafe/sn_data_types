// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{AuthorisationKind, Type};
use crate::{Error, Money, PublicKey, Response, TransferId, XorName};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// Money request that is sent to vaults.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum MoneyRequest {
    // ===== Money =====
    //
    /// Money transfer.
    Transfer {
        /// The transfer source.
        from: PublicKey,
        /// The destination to transfer to.
        to: PublicKey,
        /// The amount to transfer.
        amount: Money,
        /// If false, the transfer will be rejected if account doesn't exist.
        /// If true, the account will be created, and transfer made. If account exist, the transfer will be rejected.
        new_account: bool,
        // /// A signature over the transfer.
        // signature: Signature,
        /// Transfer id
        transfer_id: TransferId,
    },
    // /// Last part of a money transfer.
    // DepositMoney {
    //     /// The destination to transfer to.
    //     from: XorName,
    //     /// The destination to transfer to.
    //     to: XorName,
    //     /// The amount to transfer.
    //     amount: Money,
    //     /// Is this for a new account?
    //     new_account: bool,
    //     /// Seriliased proof of the client request. aka: TransferRequest Message, serialised. to be verified at recipient section
    //     transfer_proof: Vec<u8>,
    //     /// Transfer id
    //     transfer_id: TransferId,
    // },
    /// Get account balance.
    GetBalance(XorName),
}

impl MoneyRequest {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use MoneyRequest::*;
        match *self {
            GetBalance(_) => Type::PrivateGet,
            Transfer { .. } => Type::Transfer,
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use MoneyRequest::*;
        match *self {
            GetBalance(_) => Response::GetBalance(Err(error)),
            Transfer { .. } => Response::TransferRegistered(Err(error)),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use MoneyRequest::*;
        match *self {
            Transfer {
                amount,
                new_account,
                ..
            } => {
                if !new_account {
                    AuthorisationKind::TransferMoney
                } else if amount.as_nano() == 0 {
                    AuthorisationKind::Mutation // just create the account
                } else {
                    // create and transfer the amount
                    AuthorisationKind::MutAndTransferMoney
                }
            }
            GetBalance(_) => AuthorisationKind::GetBalance,
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dest_address(&self) -> Option<Cow<XorName>> {
        use MoneyRequest::*;
        match self {
            Transfer { ref to, .. } => Some(Cow::Owned(XorName::from(*to))),
            GetBalance(_) => None,
        }
    }
}

impl fmt::Debug for MoneyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use MoneyRequest::*;
        write!(
            formatter,
            "Request::{}",
            match *self {
                Transfer { .. } => "Transfer",
                GetBalance(_) => "GetBalance",
            }
        )
    }
}
