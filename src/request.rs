// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT> or the Modified
// BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option. This file may not be copied, modified, or distributed
// except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use
// of the SAFE Network Software.

use crate::immutable_data::UnpubImmutableData;
use crate::mutable_data::{MutableDataRef, UnsequencedMutableData};
use crate::MessageId;
use crate::XorName;
use threshold_crypto::PublicKey;

/// RPC Request that is sent to vaults
#[allow(clippy::large_enum_variant)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Request {
    GetUnpubIData(XorName),
    PutUnpubIData(UnpubImmutableData),
    DeleteUnpubIData(XorName),

    GetUnseqMData {
        // Address of the mutable data to be fetched
        address: MutableDataRef,
        requester: PublicKey,
        // Unique message Identifier
        message_id: MessageId,
    },
    PutUnseqMData {
        // Mutable Data to be stored
        data: UnsequencedMutableData,
        // Requester public key
        requester: PublicKey,
        // Unique message Identifier
        message_id: MessageId,
    },
}
