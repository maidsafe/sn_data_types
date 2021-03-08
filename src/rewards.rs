// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::PublicKey;
use serde::{Deserialize, Serialize};

/// Node age, the number of times
/// it has been relocated between sections.
pub type NodeAge = u8;

/// The stage of a node, with
/// regards to eligibility for rewards.
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeRewardStage {
    /// When a new node joins the network.
    NewNode,
    /// When a node has been relocated to us.
    AwaitingActivation(NodeAge),
    /// After we have received the wallet id, 
    /// the stage is `Active`.
    Active { 
        /// The wallet of the node operator.
        wallet: PublicKey, 
        /// The node age.
        age: NodeAge 
    },
    /// After a node leaves the section
    /// it transitions into `AwaitingRelocation` stage.
    AwaitingRelocation(PublicKey),
}
