// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use serde::{Deserialize, Serialize};

///
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum Duty {
    ///
    Adult(AdultDuties),
    ///
    Elder(ElderDuties),
    ///
    Node(NodeDuties),
}

/// Duties of a Node.
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum NodeDuties {
    /// Config of a node, such as reward wallet.
    NodeConfig,
}

/// Duties of an Adult.
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum AdultDuties {
    /// Keeping and serving chunks.
    ChunkStorage,
    /// Replicating chunks.
    ChunkReplication,
}

/// Duties of an Elder.
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum ElderDuties {
    /// Interfacing with clients.
    Gateway,
    /// Metadata management.
    Metadata,
    /// Transfers of money.
    Transfer,
    /// Rewards for data storage etc.
    Rewards,
}
