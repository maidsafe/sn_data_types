// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    AccountId, Address, DebitAgreementProof, Error, IData, IDataAddress, Result, Signature,
    SignatureShare, SignedTransfer, TransferId, TransferValidated, XorName,
};
use serde::{Deserialize, Serialize};

///
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NetworkCmd {
    ///
    PropagateTransfer(DebitAgreementProof),
    ///
    InitiateRewardPayout(SignedTransfer),
    ///
    FinaliseRewardPayout(DebitAgreementProof),
    ///
    DuplicateChunk {
        ///
        address: IDataAddress,
        ///
        new_holder: XorName,
        ///
        signature: Option<(usize, SignatureShare)>,
    },
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NetworkEvent {
    /// Wrapper for a duplicate completion response, from a node to elders.
    DuplicationComplete {
        ///
        chunk: IDataAddress,
        /// The Elder's accumulated signature
        /// over the chunk address. This is sent back
        /// to them so that any uninformed Elder knows
        /// that this is all good.
        proof: Signature,
    },
    ///
    RewardPayoutValidated(TransferValidated),
}

///
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NetworkQuery {
    /// Elder to Adult Get.
    GetChunk {
        /// The holder id.
        holder: XorName,
        /// The chunk address.
        address: IDataAddress,
    },
    /// Adult to Adult Get
    GetChunks {
        /// The holder id.
        holder: XorName,
        /// The chunk addresses.
        addresses: Vec<IDataAddress>,
    },
    /// Sent by new section to old section
    /// after having received a relocated node.
    GetRewardCounter {
        /// The old section will know
        /// which counter to return
        /// by the old node id.
        old_node_id: XorName,
    },
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NetworkQueryResponse {
    /// Elder to Adult Get.
    GetChunk(Result<IData>),
    /// Adult to Adult Get
    GetChunks(Result<Vec<IData>>),
    /// The old section returns
    /// the accumulated work & reward
    /// for the relocated node.
    GetRewardCounter {
        /// This informs new section
        /// which node this counter is for.
        old_node_id: XorName,
        /// The account id to payout rewards to.
        account_id: AccountId,
        /// The serialized RewardCounter.
        counter: Vec<u8>,
    },
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NetworkCmdError {
    ///
    WorkerReception {
        ///
        account_id: AccountId,
        ///
        error: Error,
    },
    ///
    DuplicateChunk {
        ///
        address: IDataAddress,
        ///
        error: Error,
    },
    ///
    RewardPayoutInitiation {
        ///
        id: TransferId,
        ///
        account: AccountId,
    },
    ///
    RewardPayoutFinalisation {
        ///
        id: TransferId,
        ///
        account: AccountId,
    },
}

impl NetworkCmd {
    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> Address {
        use Address::*;
        use NetworkCmd::*;
        match self {
            PropagateTransfer(debit_agreement) => Section(debit_agreement.to().into()),
            InitiateRewardPayout(signed_transfer) => Section(signed_transfer.from().into()),
            FinaliseRewardPayout(debit_agreement) => Section(debit_agreement.from().into()),
            DuplicateChunk { new_holder, .. } => Node(*new_holder),
        }
    }
}

impl NetworkEvent {
    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> Address {
        use Address::*;
        use NetworkEvent::*;
        match self {
            DuplicationComplete { chunk, .. } => Section(*chunk.name()),
            RewardPayoutValidated(event) => Section(event.from().into()),
        }
    }
}

impl NetworkQuery {
    /// Returns the address of the destination for the query.
    pub fn dst_address(&self) -> Address {
        use Address::*;
        use NetworkQuery::*;
        match self {
            GetChunk { holder, .. } | GetChunks { holder, .. } => Node(*holder),
            GetRewardCounter { old_node_id, .. } => Section(*old_node_id),
        }
    }
}
