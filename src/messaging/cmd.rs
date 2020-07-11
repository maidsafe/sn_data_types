// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{auth::AuthCmd, data::DataCmd, transfer::TransferCmd, AuthorisationKind};
use crate::{DebitAgreementProof, XorName};
use serde::{Deserialize, Serialize};

/// TODO: docs
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum Cmd {
    ///
    Auth(AuthCmd),
    ///
    Data {
        ///
        cmd: DataCmd,
        ///
        payment: DebitAgreementProof,
    },
    ///
    Transfer(TransferCmd),
}

impl Cmd {
    /// Returns the type of authorisation needed for the cuest.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use Cmd::*;
        match self {
            Auth(c) => c.authorisation_kind(),
            Data { cmd, .. } => cmd.authorisation_kind(),
            Transfer(c) => c.authorisation_kind(),
        }
    }

    /// Returns the address of the destination for `cuest`.
    pub fn dst_address(&self) -> XorName {
        use Cmd::*;
        match self {
            Auth(c) => c.dst_address(),
            Data { cmd, .. } => cmd.dst_address(),
            Transfer(c) => c.dst_address(),
        }
    }
}
