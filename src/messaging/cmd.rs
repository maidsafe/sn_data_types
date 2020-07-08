// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{
    account::AccountCmd, auth::AuthCmd, blob::BlobWrite, map::MapWrite, sequence::SequenceWrite,
    transfer::TransferCmd, AuthorisationKind, CmdError,
};
use crate::{DebitAgreementProof, Error, XorName};
use serde::{Deserialize, Serialize};
use std::fmt;

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

/// TODO: docs
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum DataCmd {
    /// TODO: docs
    Blob(BlobWrite),
    /// TODO: docs
    Map(MapWrite),
    /// TODO: docs
    Sequence(SequenceWrite),
    /// Use this only while we don't
    /// have Authenticator as its own app.
    Account(AccountCmd), // <- "LoginPacket"
}

impl DataCmd {
    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// cuest variant.
    pub fn error(&self, error: Error) -> CmdError {
        use DataCmd::*;
        match self {
            Blob(c) => c.error(error),
            Map(c) => c.error(error),
            Sequence(c) => c.error(error),
            Account(c) => c.error(error),
        }
    }
    /// Returns the type of authorisation needed for the cuest.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use DataCmd::*;
        match self {
            Blob(c) => c.authorisation_kind(),
            Map(c) => c.authorisation_kind(),
            Sequence(c) => c.authorisation_kind(),
            Account(c) => c.authorisation_kind(),
        }
    }

    /// Returns the address of the destination for `cuest`.
    pub fn dst_address(&self) -> XorName {
        use DataCmd::*;
        match self {
            Blob(c) => c.dst_address(),
            Map(c) => c.dst_address(),
            Sequence(c) => c.dst_address(),
            Account(c) => c.dst_address(),
        }
    }
}

impl fmt::Debug for DataCmd {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use DataCmd::*;
        match self {
            Blob(c) => write!(formatter, "{:?}", c),
            Map(c) => write!(formatter, "{:?}", c),
            Sequence(c) => write!(formatter, "{:?}", c),
            Account(c) => write!(formatter, "{:?}", c),
        }
    }
}
