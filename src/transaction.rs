// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::Coins;
use serde::{Deserialize, Serialize};

pub type TransactionId = u64; // TODO: Use the trait UUID

/// Coin transaction.
#[derive(Copy, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct Transaction {
    pub id: TransactionId,
    pub amount: Coins,
}
