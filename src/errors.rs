use serde::{Deserialize, Serialize};

#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct ClientError {
    error_code: u32,
}
