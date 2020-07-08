// // Copyright 2019 MaidSafe.net limited.
// //
// // This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// // https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// // https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// // modified, or distributed except according to those terms. Please review the Licences for the
// // specific language governing permissions and limitations relating to use of the SAFE Network
// // Software.

// pub use super::transfer::{TransferCmd, TransferQuery};
// use super::{cmd::Cmd, query::Query, system::SystemOp, AuthorisationKind, QueryResponse};
// use crate::{DebitAgreementProof, Error, XorName};
// use serde::{Deserialize, Serialize};
// use std::fmt;

// /// Gateway forwarded requests
// #[allow(clippy::large_enum_variant)]
// #[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
// pub enum GatewayRequest {
//     /// Free
//     Read(Query),
//     /// Costs
//     Write {
//         /// TODO: docs
//         write: Cmd,
//         // NB: this might be a DebitProof instead.
//         /// TODO: docs
//         debit_agreement: DebitAgreementProof,
//     },
//     /// Free system requests by Client (Owner)
//     System(SystemOp),
// }

// impl GatewayRequest {
//     /// Returns the type of authorisation needed for the request.
//     pub fn authorisation_kind(&self) -> AuthorisationKind {
//         use GatewayRequest::*;
//         match self {
//             Read(req) => req.authorisation_kind(),
//             Write { write, .. } => write.authorisation_kind(),
//             System(req) => req.authorisation_kind(),
//         }
//     }

//     /// Returns the address of the destination for `request`.
//     pub fn dst_address(&self) -> XorName {
//         use GatewayRequest::*;
//         match self {
//             Read(req) => req.dst_address(),
//             Write { write, .. } => write.dst_address(),
//             System(req) => req.dst_address(),
//         }
//     }
// }

// impl fmt::Debug for GatewayRequest {
//     fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//         use GatewayRequest::*;
//         match self {
//             Read(req) => write!(formatter, "{:?}", req),
//             Write { write, .. } => write!(formatter, "{:?}", write),
//             System(req) => write!(formatter, "{:?}", req),
//         }
//     }
// }
