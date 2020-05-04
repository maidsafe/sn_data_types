// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::Type;
use crate::{Coins, Error, PublicKey, Response, TransactionId, XorName};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Coins request that is sent to vaults.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum CoinsRequest {
    /// Balance transfer.
    Transfer {
        /// The destination to transfer to.
        destination: XorName,
        /// The amount in coins to transfer.
        amount: Coins,
        /// The ID of the transaction.
        transaction_id: TransactionId,
    },
    /// Get current wallet balance.
    GetBalance,
    /// Create a new coin balance.
    CreateBalance {
        /// The new owner of the balance.
        new_balance_owner: PublicKey,
        /// The new balance amount in coins.
        amount: Coins,
        /// The ID of the transaction.
        transaction_id: TransactionId,
    },
}

impl CoinsRequest {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use CoinsRequest::*;

        match *self {
            GetBalance => Type::PrivateGet,
            Transfer { .. } | CreateBalance { .. } => Type::Transaction,
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use CoinsRequest::*;

        match *self {
            GetBalance => Response::GetBalance(Err(error)),
            Transfer { .. } | CreateBalance { .. } => Response::Transaction(Err(error)),
        }
    }
}

impl fmt::Debug for CoinsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use CoinsRequest::*;

        write!(
            formatter,
            "Request::{}",
            match *self {
                Transfer { .. } => "TransferCoins",
                GetBalance => "GetBalance",
                CreateBalance { .. } => "CreateBalance",
            }
        )
    }
}
