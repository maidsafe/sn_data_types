// // Copyright 2019 MaidSafe.net limited.
// //
// // This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// // https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// // https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// // modified, or distributed except according to those terms. Please review the Licences for the
// // specific language governing permissions and limitations relating to use of the SAFE Network
// // Software.

// pub use super::transfer::{TransferCmd, TransferQuery};
// use super::{cmd::Cmd, query::Query, AuthorisationKind};
// use crate::{DebitAgreementProof, Error, XorName};
// use serde::{Deserialize, Serialize};
// use std::fmt;

// /// Client initiated requests
// #[allow(clippy::large_enum_variant)]
// #[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
// pub enum ClientMessage {
//     /// Free
//     Query(Query),
//     /// Costs
//     Cmd {
//         /// TODO: docs
//         cmd: Cmd,
//         // NB: this might be a DebitProof instead.
//         /// TODO: docs
//         debit_agreement: DebitAgreementProof,
//     },
// }

// impl ClientMessage {

//     // /// Creates a Response containing an error, with the Response variant corresponding to the
//     // /// Request variant.
//     // pub fn error_response(&self, error: Error) -> Response {
//     //     use ClientMessage::*;
//     //     match self {
//     //         Query(query) => query.error(error),
//     //         Cmd { cmd, .. } => cmd.error(error),
//     //         System(req) => req.error_response(error),
//     //     }
//     // }

//     /// Returns the type of authorisation needed for the request.
//     pub fn authorisation_kind(&self) -> AuthorisationKind {
//         use ClientMessage::*;
//         match self {
//             Query(query) => query.authorisation_kind(),
//             Cmd { cmd, .. } => cmd.authorisation_kind(),
//         }
//     }

//     /// Returns the address of the destination for `request`.
//     pub fn dst_address(&self) -> XorName {
//         use ClientMessage::*;
//         match self {
//             Query(query) => query.dst_address(),
//             Cmd { cmd, .. } => cmd.dst_address(),
//         }
//     }
// }

// impl fmt::Debug for ClientMessage {
//     fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//         use ClientMessage::*;
//         match self {
//             Query(query) => write!(formatter, "{:?}", query),
//             Cmd { cmd, .. } => write!(formatter, "{:?}", cmd),
//         }
//     }
// }
