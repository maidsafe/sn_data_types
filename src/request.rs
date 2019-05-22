use crate::mutable_data::{MutableDataRef, UnpublishedMutableData};
use serde::{Deserialize, Serialize};
// use threshold_crypto::PublicKey;
use routing::MessageId;
use rust_sodium::crypto::sign::PublicKey;

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Request {
    GetUnseqMData {
        // Address of the mutable data to be fetched
        address: MutableDataRef,
        requester: PublicKey,
        // Unique message Identifier
        message_id: MessageId,
    },
    PutUnseqMData {
        // Mutable Data to be stored
        data: UnpublishedMutableData,
        // Requester public key
        requester: PublicKey,
        // Unique message Identifier
        message_id: MessageId,
    },
}
