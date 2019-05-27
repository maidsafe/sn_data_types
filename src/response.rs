// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::errors::ClientError;
use crate::mutable_data::UnpublishedMutableData;
use crate::MessageId;

/// Rpc responses from vaults.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Response {
    GetUnseqMData {
        res: Result<UnpublishedMutableData, ClientError>,
        msg_id: MessageId,
    },
    PutUnseqMData {
        res: Result<(), ClientError>,
        msg_id: MessageId,
    },
}
