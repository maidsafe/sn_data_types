// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::{AuthorisationKind, Type};
use crate::{Coins, Error, PublicKey, Response, Result, Signature, TransactionId, XorName};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, fmt};

/// Login packet size is limited .
pub const MAX_LOGIN_PACKET_BYTES: usize = 1024 * 1024; // 1 MB

/// LoginPacket request that is sent to vaults.
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum LoginPacketRequest {
    /// Create a login packet.
    Create(LoginPacket),
    /// Create a login packet for a given user and transfer some initial coins.
    CreateFor {
        /// The new owner of the login packet.
        new_owner: PublicKey,
        /// The new balance amount in coins.
        amount: Coins,
        /// The ID of the transaction.
        transaction_id: TransactionId,
        /// The new login packet.
        new_login_packet: LoginPacket,
    },
    /// Update a login packet.
    Update(LoginPacket),
    /// Get an encrypted login packet.
    Get(XorName),
}

impl LoginPacketRequest {
    /// Get the `Type` of this `Request`.
    pub fn get_type(&self) -> Type {
        use LoginPacketRequest::*;
        match *self {
            Get(..) => Type::PrivateGet,
            CreateFor { .. } => Type::Transaction,
            Create { .. } | Update { .. } => Type::Mutation,
        }
    }

    /// Creates a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use LoginPacketRequest::*;
        match *self {
            Get(..) => Response::GetLoginPacket(Err(error)),
            CreateFor { .. } => Response::Transaction(Err(error)),
            Create { .. } | Update { .. } => Response::Mutation(Err(error)),
        }
    }

    /// Returns the type of authorisation needed for the request.
    pub fn authorisation_kind(&self) -> AuthorisationKind {
        use LoginPacketRequest::*;
        match *self {
            Create { .. } | Update { .. } => AuthorisationKind::Mutation,
            CreateFor { amount, .. } => {
                if amount.as_nano() == 0 {
                    AuthorisationKind::Mutation
                } else {
                    AuthorisationKind::MutAndTransferCoins
                }
            }
            Get(_) => AuthorisationKind::GetPriv,
        }
    }

    /// Returns the address of the destination for `request`.
    pub fn dest_address(&self) -> Option<Cow<XorName>> {
        use LoginPacketRequest::*;
        match self {
            Create(login_packet) => Some(Cow::Borrowed(login_packet.destination())),
            CreateFor {
                new_login_packet, ..
            } => Some(Cow::Borrowed(new_login_packet.destination())),
            Update(login_packet) => Some(Cow::Borrowed(login_packet.destination())),
            Get(ref name) => Some(Cow::Borrowed(name)),
        }
    }
}

impl fmt::Debug for LoginPacketRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use LoginPacketRequest::*;

        write!(
            formatter,
            "Request::{}",
            match *self {
                Create { .. } => "CreateLoginPacket",
                CreateFor { .. } => "CreateLoginPacketFor",
                Update { .. } => "UpdateLoginPacket",
                Get(..) => "GetLoginPacket",
            }
        )
    }
}

/// Login packet containing arbitrary user's login information.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct LoginPacket {
    destination: XorName,
    authorised_getter: PublicKey, // deterministically created from passwords
    data: Vec<u8>,
    signature: Signature,
}

impl LoginPacket {
    /// Construct a new login packet.
    pub fn new(
        destination: XorName,
        authorised_getter: PublicKey,
        data: Vec<u8>,
        signature: Signature,
    ) -> Result<Self> {
        let login_packet_data = Self {
            destination,
            authorised_getter,
            data,
            signature,
        };
        if login_packet_data.size_is_valid() {
            Ok(login_packet_data)
        } else {
            Err(Error::ExceededSize)
        }
    }

    /// Returns true if the size of the data is valid.
    pub fn size_is_valid(&self) -> bool {
        self.data.len() <= MAX_LOGIN_PACKET_BYTES
    }

    /// Gets the destination.
    pub fn destination(&self) -> &XorName {
        &self.destination
    }

    /// Gets the authorised getter.
    pub fn authorised_getter(&self) -> &PublicKey {
        &self.authorised_getter
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
    use super::{LoginPacket, MAX_LOGIN_PACKET_BYTES};
    use crate::{ClientFullId, Error};

    #[test]
    fn exceed_size_limit() {
        let our_id = ClientFullId::new_ed25519(&mut rand::thread_rng());

        let acc_data = vec![0; MAX_LOGIN_PACKET_BYTES + 1];
        let signature = our_id.sign(&acc_data);

        let res = LoginPacket::new(
            rand::random(),
            *our_id.public_id().public_key(),
            acc_data,
            signature,
        );

        match res {
            Err(Error::ExceededSize) => (),
            Ok(_) => panic!("Unexpected success"),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn valid() {
        let our_id = ClientFullId::new_ed25519(&mut rand::thread_rng());

        let acc_data = vec![1; 16];
        let signature = our_id.sign(&acc_data);

        let res = LoginPacket::new(
            rand::random(),
            *our_id.public_id().public_key(),
            acc_data.clone(),
            signature,
        );

        match res {
            Ok(ad) => {
                assert_eq!(ad.data(), acc_data.as_slice());
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
}
