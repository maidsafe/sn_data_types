// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::Money;
use serde::{Deserialize, Serialize};

/// The representation of the smallest unit of work.
/// This is strictly incrementing (i.e. accumulated)
/// during the network lifetime of the worker.
pub type Work = u64;

///
#[derive(Clone, Eq, Hash, PartialEq, PartialOrd, Debug, Ord, Serialize, Deserialize)]
pub struct RewardCounter {
    /// Accumulated rewards.
    /// This is reset every time the
    /// reward is paid out to the worker.
    pub reward: Money,
    /// Accumulated work.
    /// This is strictly incrementing during
    /// the network lifetime of the worker.
    pub work: Work,
}

impl RewardCounter {
    ///
    pub fn add(&self, reward: Money) -> Option<Self> {
        let sum = match self.reward.checked_add(reward) {
            Some(s) => s,
            None => return None,
        };
        Some(Self {
            work: self.work + 1,
            reward: sum,
        })
    }
}

impl Default for RewardCounter {
    fn default() -> Self {
        Self {
            work: 0,
            reward: Money::zero(),
        }
    }
}
