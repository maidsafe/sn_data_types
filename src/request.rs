// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::immutable_data::UnpubImmutableData;
use crate::mutable_data::{MutableData, MutableDataRef};
use crate::MessageId;
use crate::XorName;
use threshold_crypto::PublicKey;

/// RPC Request that is sent to vaults
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
        data: MutableData,
        // Requester public key
        requester: PublicKey,
        // Unique message Identifier
        message_id: MessageId,
    },
}
