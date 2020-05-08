// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{AuthorisationKind, Type};
use crate::{Error, Money, PublicKey, Response, TransactionId, XorName};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// Money request that is sent to vaults.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum MoneyRequest {
    // ===== Money =====
    //
    /// Money transfer.
    TransferMoney {
        /// The destination to transfer to.
        from: XorName,
        /// The destination to transfer to.
        to: XorName,
        /// The amount to transfer.
        amount: Money,
        // /// A signature over the transfer.
        // signature: Signature,
        /// Transaction id
        transaction_id: TransactionId,
    },
    /// Last part of a money transfer.
    DepositMoney {
        /// The destination to transfer to.
        from: XorName,
        /// The destination to transfer to.
        to: XorName,
        /// The amount to transfer.
        amount: Money,
        /// Is this for a new account?
        new_account: bool,
        /// Seriliased proof of the client request. aka: TransferRequest Message, serialised. to be verified at recipient section
        transfer_proof: Vec<u8>,
        /// Transaction id
        transaction_id: TransactionId,
    },
    /// Get account balance.
    GetBalance(XorName),
    /// Create a new coin balance.
    CreateBalance {
        /// Source of any initial balance.
        from: PublicKey,
        /// Owner of the balance.
        to: PublicKey,
        /// The initial balance.
        amount: Money,
        // /// A signature over the transfer.
        // signature: Signature,
        /// Transaction id
        transaction_id: Option<TransactionId>,
    },
}

impl MoneyRequest {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use MoneyRequest::*;
        match *self {
            GetBalance(_) => Type::PrivateGet,
            DepositMoney { .. } | TransferMoney { .. } | CreateBalance { .. } => Type::Transaction,
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use MoneyRequest::*;
        match *self {
            GetBalance(_) => Response::GetBalance(Err(error)),
            DepositMoney { .. } | TransferMoney { .. } | CreateBalance { .. } => {
                Response::MoneyReceipt(Err(error))
            }
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use MoneyRequest::*;
        match *self {
            CreateBalance { amount, .. } => {
                if amount.as_nano() == 0 {
                    AuthorisationKind::Mutation
                } else {
                    AuthorisationKind::MutAndTransferMoney
                }
            }
            DepositMoney { .. } | TransferMoney { .. } => AuthorisationKind::TransferMoney,
            GetBalance(_) => AuthorisationKind::GetBalance,
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dest_address(&self) -> Option<Cow<XorName>> {
        use MoneyRequest::*;
        match self {
            CreateBalance { ref to, .. } => Some(Cow::Owned(XorName::from(*to))),
            TransferMoney { ref to, .. } => Some(Cow::Borrowed(to)),
            DepositMoney { ref to, .. } => Some(Cow::Borrowed(to)),
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
                TransferMoney { .. } => "TransferMoney",
                DepositMoney { .. } => "DepositMoney",
                GetBalance(_) => "GetBalance",
                CreateBalance { .. } => "CreateBalance",
            }
        )
    }
}
