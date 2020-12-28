// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{AuthorisationKind, CmdError, DataAuthKind, QueryResponse};
use crate::{Error, PublicKey, Result, Signature, XorName};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Login packet size is limited .
pub const MAX_LOGIN_PACKET_BYTES: usize = 1024 * 1024; // 1 MB

/// Use this only while we don't
/// have Authenticator as its own app.
#[allow(clippy::large_enum_variant)]
#[derive(Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum AccountWrite {
    /// Create a new account.
    New(Account),
    /// Update (overwrite) an Account.
    Update(Account),
}

/// Use this only while we don't
/// have Authenticator as its own app.
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Clone, Serialize, Deserialize)]
pub enum AccountRead {
    /// Get an encrypted account.
    Get(XorName),
}

impl AccountWrite {
    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> CmdError {
        use AccountWrite::*;
        match *self {
            New { .. } | Update { .. } => CmdError::Data(error),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use AccountWrite::*;
        match *self {
            New { .. } | Update { .. } => AuthorisationKind::Data(DataAuthKind::Write),
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dst_address(&self) -> XorName {
        use AccountWrite::*;
        match self {
            New(account) => *account.address(),
            Update(account) => *account.address(),
        }
    }

    /// Returns the owner of the account.
    pub fn owner(&self) -> PublicKey {
        match self {
            Self::New(acc) => acc.owner,
            Self::Update(acc) => acc.owner,
        }
    }
}

impl fmt::Debug for AccountWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use AccountWrite::*;
        write!(
            formatter,
            "Request::{}",
            match *self {
                New { .. } => "NewAccount",
                Update { .. } => "UpdateAccount",
            }
        )
    }
}

impl AccountRead {
    // /// Get the `Type` of this request.
    // pub fn get_type(&self) -> Type {
    //     Type::PrivateRead
    // }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error(&self, error: Error) -> QueryResponse {
        QueryResponse::GetAccount(Err(error))
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        AuthorisationKind::Data(DataAuthKind::PrivateRead)
    }

    /// Returns the address of the destination for request.
    pub fn dst_address(&self) -> XorName {
        use AccountRead::*;
        match self {
            Get(ref name) => *name,
        }
    }
}

impl fmt::Debug for AccountRead {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Request::GetAccount")
    }
}

/// Use this only while we don't
/// have Authenticator as its own app.
/// Containing arbitrary user's account information.
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct Account {
    address: XorName,
    owner: PublicKey, // deterministically created from passwords
    data: Vec<u8>,
    signature: Signature,
}

impl Account {
    /// Construct a new login packet.
    pub fn new(
        address: XorName,
        owner: PublicKey,
        data: Vec<u8>,
        signature: Signature,
    ) -> Result<Self> {
        let account = Self {
            address,
            owner,
            data,
            signature,
        };
        if account.size_is_valid() {
            Ok(account)
        } else {
            Err(Error::ExceededSize)
        }
    }

    /// Returns true if the size of the data is valid.
    pub fn size_is_valid(&self) -> bool {
        self.data.len() <= MAX_LOGIN_PACKET_BYTES
    }

    /// Gets the address.
    pub fn address(&self) -> &XorName {
        &self.address
    }

    /// Gets the owner.
    pub fn owner(&self) -> &PublicKey {
        &self.owner
    }

    /// Returns the data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Convert this login packet into its data and signature.
    pub fn into_data_and_signature(self) -> (Vec<u8>, Signature) {
        (self.data, self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::{Account, MAX_LOGIN_PACKET_BYTES};
    use crate::{Error, Keypair};

    #[test]
    fn exceed_size_limit() -> anyhow::Result<()> {
        let our_id = Keypair::new_ed25519(&mut rand::thread_rng());

        let acc_data = vec![0; MAX_LOGIN_PACKET_BYTES + 1];
        let signature = our_id.sign(&acc_data);

        let res = Account::new(rand::random(), our_id.public_key(), acc_data, signature);

        match res {
            Err(Error::ExceededSize) => Ok(()),
            Ok(_) => Err(anyhow::anyhow!("Unexpected success".to_string())),
            Err(e) => Err(anyhow::anyhow!("Unexpected error: {:?}", e)),
        }
    }

    #[test]
    fn valid() -> anyhow::Result<()> {
        let our_id = Keypair::new_ed25519(&mut rand::thread_rng());

        let acc_data = vec![1; 16];
        let signature = our_id.sign(&acc_data);

        let res = Account::new(
            rand::random(),
            our_id.public_key(),
            acc_data.clone(),
            signature,
        );

        match res {
            Ok(ad) => {
                assert_eq!(ad.data(), acc_data.as_slice());
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("Unexpected error: {:?}", e)),
        }
    }
}
