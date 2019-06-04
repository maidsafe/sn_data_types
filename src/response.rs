// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::immutable_data::UnpubImmutableData;
use crate::mutable_data::{SeqMutableData, UnseqMutableData};
use crate::MessageId;
use serde::{Deserialize, Serialize};

/// RPC responses from vaults.
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Response<ErrorType> {
    GetUnpubIData(Result<UnpubImmutableData, ErrorType>),
    PutUnpubIData(Result<(), ErrorType>),
    DeleteUnpubIData(Result<(), ErrorType>),

    GetUnseqMData {
        res: Result<UnseqMutableData, ErrorType>,
        msg_id: MessageId,
    },
    PutUnseqMData {
        res: Result<(), ErrorType>,
        msg_id: MessageId,
    },
    GetSeqMData {
        res: Result<SeqMutableData, ErrorType>,
        msg_id: MessageId,
    },
    PutSeqMData {
        res: Result<(), ErrorType>,
        msg_id: MessageId,
    },
}

use std::fmt;

impl<T> fmt::Debug for Response<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            Response::GetUnpubIData { .. } => "Response::GetUnpubIData",
            Response::PutUnpubIData { .. } => "Response::PutUnpubIData",
            Response::DeleteUnpubIData { .. } => "Response::DeleteUnpubIData",
            Response::GetUnseqMData { .. } => "Response::GetUnseqMData",
            Response::PutUnseqMData { .. } => "Response::PutUnseqMData",
            Response::GetSeqMData { .. } => "Response::GetSeqMData",
            Response::PutSeqMData { .. } => "Response::PutSeqMData",
        };
        write!(f, "{}", printable)
    }
}
