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

/// Money query that is sent to network.
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum PaymentQuery {
    /// Get the current metrics
    GetStoreCost(PublicKey),
}

impl PaymentQuery {
    /// Creates a QueryResponse containing an error, with the QueryResponse variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> QueryResponse {
        use PaymentQuery::*;
        match *self {
            GetStoreCost(_) => QueryResponse::GetStoreCost(Err(error)),
        }
    }

    /// Returns the type of authorisation needed for the query.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use PaymentQuery::*;
        match self.clone() {
            GetStoreCost(_) => AuthorisationKind::None,
        }
    }

    /// Returns the address of the destination for the query.
    pub fn dst_address(&self) -> XorName {
        use PaymentQuery::*;
        match self {
            GetStoreCost(at) => XorName::from(*at),
        }
    }
}

impl fmt::Debug for PaymentQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use PaymentQuery::*;
        write!(
            formatter,
            "PaymentQuery::{}",
            match *self {
                GetStoreCost(_) => "GetStoreCost",
            }
        )
    }
}
