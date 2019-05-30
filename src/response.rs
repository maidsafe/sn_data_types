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
use crate::mutable_data::UnsequencedMutableData;
use crate::MessageId;

/// RPC responses from vaults.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Response<ErrorType> {
    GetUnpubIData(Result<UnpubImmutableData, ErrorType>),
    PutUnpubIData(Result<(), ErrorType>),
    DeleteUnpubIData(Result<(), ErrorType>),

    GetUnseqMData {
        res: Result<UnsequencedMutableData, ErrorType>,
        msg_id: MessageId,
    },
    PutUnseqMData {
        res: Result<(), ErrorType>,
        msg_id: MessageId,
    },
}
