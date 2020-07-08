// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#![allow(unused_imports)] // NB: Only while we have #[cfg(feature = "simulated-payouts")]

use super::{
    AuthorisationKind, CmdError, MiscAuthKind, MoneyAuthKind, QueryResponse, TransferError,
};
use crate::{DebitAgreementProof, Error, PublicKey, SignedTransfer, Transfer, XorName};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// Money cmd that is sent to network.
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum TransferCmd {
    #[cfg(feature = "simulated-payouts")]
    /// Request to simulate a farming payout
    SimulatePayout {
        /// The cmd to validate a transfer.
        transfer: Transfer,
    },
    /// Request to validate transfer.
    ValidateTransfer {
        /// The cmd to validate a transfer.
        signed_transfer: SignedTransfer,
    },
    /// Request to register transfer.
    RegisterTransfer {
        /// The cmd to register the consensused transfer.
        proof: DebitAgreementProof,
    },
    /// Request to propagate transfer.
    PropagateTransfer {
        /// The cmd to register the consensused transfer.
        proof: DebitAgreementProof,
    },
}

/// Money query that is sent to network.
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum TransferQuery {
    /// Get the PublicKeySet for replicas of a given PK
    GetReplicaKeys(PublicKey),
    /// Get key balance.
    GetBalance(PublicKey),
    /// Get key transfers since specified version.
    GetHistory {
        /// The balance key.
        at: PublicKey,
        /// The last version of transfers we know of.
        since_version: usize,
    },
}

impl TransferCmd {
    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> CmdError {
        use CmdError::*;
        use TransferCmd::*;
        use TransferError::*;
        match *self {
            ValidateTransfer { .. } => Transfer(TransferValidation(error)),
            RegisterTransfer { .. } => Transfer(TransferRegistration(error)),
            PropagateTransfer { .. } => Transfer(TransferPropagation(error)),
            #[cfg(feature = "simulated-payouts")]
            SimulatePayout { .. } => Transfer(TransferPropagation(error)),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use TransferCmd::*;
        match self.clone() {
            PropagateTransfer { .. } => AuthorisationKind::None, // the proof has the authority within it
            RegisterTransfer { .. } => AuthorisationKind::None, // the proof has the authority within it
            ValidateTransfer { .. } => AuthorisationKind::Misc(MiscAuthKind::WriteAndTransfer),
            #[cfg(feature = "simulated-payouts")]
            SimulatePayout { .. } => AuthorisationKind::None,
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> XorName {
        use TransferCmd::*;
        match self {
            PropagateTransfer { ref proof, .. } => XorName::from(proof.to()), // sent to section where credit is made
            RegisterTransfer { ref proof, .. } => XorName::from(proof.from()), // this is handled where the debit is made
            ValidateTransfer {
                ref signed_transfer,
                ..
            } => XorName::from(signed_transfer.from()), // this is handled where the debit is made
            #[cfg(feature = "simulated-payouts")]
            SimulatePayout { ref transfer, .. } => XorName::from(transfer.from()), // this is handled where the debit is made
        }
    }
}

impl fmt::Debug for TransferCmd {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use TransferCmd::*;
        write!(
            formatter,
            "TransferCmd::{}",
            match *self {
                PropagateTransfer { .. } => "PropagateTransfer",
                RegisterTransfer { .. } => "RegisterTransfer",
                ValidateTransfer { .. } => "ValidateTransfer",
                #[cfg(feature = "simulated-payouts")]
                SimulatePayout { .. } => "SimulatePayout",
            }
        )
    }
}

impl TransferQuery {
    // /// Get the variant of this query.
    // pub fn get_type(&self) -> Type {
    //     use TransferQuery::*;
    //     match *self {
    //         // TODO: This should this be private
    //         GetReplicaKeys(_) => Type::PublicRead,
    //         GetBalance(_) => Type::PrivateRead,
    //         GetHistory { .. } => Type::PrivateRead,
    //     }
    // }

    /// Creates a QueryResponse containing an error, with the QueryResponse variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> QueryResponse {
        use TransferQuery::*;
        match *self {
            GetReplicaKeys(_) => QueryResponse::GetReplicaKeys(Err(error)),
            GetBalance(_) => QueryResponse::GetBalance(Err(error)),
            GetHistory { .. } => QueryResponse::GetHistory(Err(error)),
        }
    }

    /// Returns the type of authorisation needed for the query.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use TransferQuery::*;
        match self.clone() {
            GetBalance(_) => AuthorisationKind::Money(MoneyAuthKind::ReadBalance), // current state
            GetReplicaKeys(_) => AuthorisationKind::None, // current replica keys
            GetHistory { .. } => AuthorisationKind::Money(MoneyAuthKind::ReadHistory), // history of incoming transfers
        }
    }

    /// Returns the address of the destination for the query.
    pub fn dst_address(&self) -> XorName {
        use TransferQuery::*;
        match self {
            GetBalance(at) | GetReplicaKeys(at) | GetHistory { at, .. } => XorName::from(*at),
        }
    }
}

impl fmt::Debug for TransferQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use TransferQuery::*;
        write!(
            formatter,
            "TransferQuery::{}",
            match *self {
                GetBalance(_) => "GetBalance",
                GetReplicaKeys(_) => "GetReplicaKeys",
                GetHistory { .. } => "GetHistory",
            }
        )
    }
}
