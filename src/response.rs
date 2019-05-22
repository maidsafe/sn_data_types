use routing::ClientError;
use crate::mutable_data::UnpublishedMutableData;
use routing::MessageId;
use serde::{Deserialize, Serialize};

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Response {
    GetUnseqMData {
        res: Result<UnpublishedMutableData, ClientError>,
        msg_id: MessageId,
    },
    PutUnseqMData {
        res: Result<(), ClientError>,
        msg_id: MessageId,
    }
}