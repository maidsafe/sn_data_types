// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    AccountId, Address, DebitAgreementProof, Error, IDataAddress, MessageId, Signature,
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
    ReceiveWorker {
        ///
        new_node_id: XorName,
        ///
        account_id: AccountId,
        ///
        counter: Vec<u8>,
    },
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
            ReceiveWorker { new_node_id, .. } => Section(*new_node_id),
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
