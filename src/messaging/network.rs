// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{
    Address, Blob, BlobAddress, DebitAgreementProof, Error, MessageId, MsgSender, PublicKey,
    ReplicaEvent, Result, Signature, SignedTransfer, TransferId, TransferValidated, XorName,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

// -------------- Node Cmds --------------

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeCmd {
    /// Cmds related to the running of a node.
    System(NodeSystemCmd),
    ///
    Data(NodeDataCmd),
    ///
    Transfers(NodeTransferCmd),
}

/// Cmds related to the running of a node.
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeSystemCmd {
    /// Register a wallet for reward payouts.
    RegisterWallet {
        /// The wallet to which rewards will be paid out by the network.
        wallet: PublicKey,
        /// The section where this wallet is to be registered (NB: this is the section of the node id).
        section: XorName,
    },
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeTransferCmd {
    ///
    PropagateTransfer(DebitAgreementProof),
    ///
    ValidateSectionPayout(SignedTransfer),
    ///
    RegisterSectionPayout(DebitAgreementProof),
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeDataCmd {
    /// Duplicate a given chunk at another Adult
    DuplicateChunk {
        /// New Holder's name
        new_holder: XorName,
        /// Address of the blob to be duplicated
        address: BlobAddress,
        /// Current Holders
        fetch_from_holders: BTreeSet<XorName>,
    },
    /// Get Chunk from current holders for duplication
    GetChunk {
        /// New Holder's name
        new_holder: XorName,
        /// Address of the blob to be duplicated
        address: BlobAddress,
        /// Details of the section that authorised the duplication
        section_authority: MsgSender,
        /// Current Holders
        fetch_from_holders: BTreeSet<XorName>,
    },
    /// Provide chunk to the new holder for duplication
    GiveChunk {
        /// Blob to be duplicated
        blob: Blob,
        /// Name of the new holder
        new_holder: XorName,
        /// MessageId of the Duplication Message
        correlation_id: MessageId,
    },
}

// -------------- Node Events --------------

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeEvent {
    /// Wrapper for a duplicate completion response, from a node to elders.
    DuplicationComplete {
        ///
        chunk: BlobAddress,
        /// The Elder's accumulated signature
        /// over the chunk address. This is sent back
        /// to them so that any uninformed Elder knows
        /// that this is all good.
        proof: Signature,
    },
    ///
    SectionPayoutValidated(TransferValidated),
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeQuery {
    ///
    Data(NodeDataQuery),
    ///
    Rewards(NodeRewardQuery),
    ///
    Transfers(NodeTransferQuery),
}

/// Reward query that is sent between sections.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeRewardQuery {
    /// Sent by the new section to the
    /// old section after node relocation.
    GetWalletId {
        /// The id of the node
        /// in the old section.
        old_node_id: XorName,
        /// The id of the node
        /// in the new section.
        new_node_id: XorName,
    },
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeTransferQuery {
    /// Replicas starting up
    /// need to query for events of
    /// the existing Replicas.
    GetReplicaEvents(PublicKey),
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeDataQuery {
    /// Elder to Adult Get.
    GetChunk {
        /// The holder id.
        holder: XorName,
        /// The chunk address.
        address: BlobAddress,
    },
    /// Adult to Adult Get
    GetChunks {
        /// The holder id.
        holder: XorName,
        /// The chunk addresses.
        addresses: BTreeSet<BlobAddress>,
    },
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeQueryResponse {
    ///
    Data(NodeDataQueryResponse),
    ///
    Rewards(NodeRewardQueryResponse),
    ///
    Transfers(NodeTransferQueryResponse),
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeRewardQueryResponse {
    /// Returns the wallet address
    /// together with the new node id,
    /// that followed with the original query.
    GetWalletId(Result<(PublicKey, XorName)>),
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeTransferQueryResponse {
    /// Replicas starting up
    /// need to query for events of
    /// the existing Replicas.
    GetReplicaEvents(Result<Vec<ReplicaEvent>>),
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeDataQueryResponse {
    /// Elder to Adult Get.
    GetChunk(Result<Blob>),
    /// Adult to Adult Get
    GetChunks(Result<Vec<Blob>>),
}

///
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeCmdError {
    ///
    Data(NodeDataError),
    ///
    Rewards(NodeRewardError),
    ///
    Transfers(NodeTransferError),
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeDataError {
    ///
    ChunkDuplication {
        ///
        address: BlobAddress,
        ///
        error: Error,
    },
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeTransferError {
    /// The error of propagation of TransferRegistered event.
    TransferPropagation(Error),
}

///
#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum NodeRewardError {
    ///
    RewardClaiming {
        ///
        wallet: PublicKey,
        ///
        error: Error,
    },
    ///
    RewardPayoutInitiation {
        ///
        id: TransferId,
        ///
        wallet: PublicKey,
        ///
        error: Error,
    },
    ///
    RewardPayoutFinalisation {
        ///
        id: TransferId,
        ///
        wallet: PublicKey,
        ///
        error: Error,
    },
}

impl NodeCmd {
    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> Address {
        use Address::*;
        use NodeCmd::*;
        use NodeDataCmd::*;
        use NodeTransferCmd::*;
        match self {
            System(NodeSystemCmd::RegisterWallet { section, .. }) => Section(*section),
            Data(cmd) => match cmd {
                DuplicateChunk { new_holder, .. } => Node(*new_holder),
                GetChunk {
                    fetch_from_holders, ..
                } => Node(
                    *fetch_from_holders
                        .iter()
                        .next()
                        .unwrap_or(&XorName::random()),
                ), // namesake
                GiveChunk { new_holder, .. } => Node(*new_holder),
            },
            Transfers(cmd) => match cmd {
                ValidateSectionPayout(signed_transfer) => Section(signed_transfer.from().into()),
                RegisterSectionPayout(debit_agreement) => Section(debit_agreement.from().into()),
                PropagateTransfer(debit_agreement) => Section(debit_agreement.to().into()),
            },
        }
    }
}

impl NodeEvent {
    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> Address {
        use Address::*;
        use NodeEvent::*;
        match self {
            DuplicationComplete { chunk, .. } => Section(*chunk.name()),
            SectionPayoutValidated(event) => Section(event.from().into()),
        }
    }
}

impl NodeQuery {
    /// Returns the address of the destination for the query.
    pub fn dst_address(&self) -> Address {
        use Address::*;
        use NodeDataQuery::*;
        use NodeQuery::*;
        use NodeRewardQuery::*;
        use NodeTransferQuery::*;
        match self {
            Data(data_query) => match data_query {
                GetChunk { holder, .. } | GetChunks { holder, .. } => Node(*holder),
            },
            Transfers(transfer_query) => match transfer_query {
                GetReplicaEvents(section_key) => Section((*section_key).into()),
            },
            Rewards(GetWalletId { old_node_id, .. }) => Section(*old_node_id),
        }
    }
}
