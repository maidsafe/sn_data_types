// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod login_packet;

pub use self::login_packet::{LoginPacket, MAX_LOGIN_PACKET_BYTES};
use crate::{
    Address,
    AppPermissions,
    BlobAddress,
    BlobData,
    Coins,
    Error,
    Index,
    MapData,
    //MapAddress, MapEntryActions, MapPermissionSet,
    Owner,
    PrivatePermissions,
    PublicKey,
    PublicPermissions,
    Response,
    SequenceCmd,
    SequenceData,
    TransactionId,
    User,
    // Version,
    XorName,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// RPC Request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum Request {
    Data(DataRequest),
    Owners(OwnerRequest),
    Auth(AuthRequest),
    Balance(BalanceRequest),
    Misc(MiscRequest),
}

/// RPC misc request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum MiscRequest {
    Read(MiscRead),
    Write(MiscWrite),
}

/// RPC data request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum DataRequest {
    Read(DataRead),
    Write(DataWrite),
}

/// RPC Balance request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum BalanceRequest {
    Read(BalanceRead),
    Write(BalanceWrite),
}

/// RPC owner request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum OwnerRequest {
    Read(OwnerRead),
    Write(OwnerWrite),
}

/// RPC atuh request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum AuthRequest {
    Read(AuthRead),
    Write(AuthWrite),
}

/// RPC data read request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum DataRead {
    //
    // ===== Blob =====
    //
    GetBlob(BlobAddress),
    //
    // ===== Map =====
    //
    //GetMap(MapAddress),
    // GetMapValue {
    //     address: MapAddress,
    //     key: Vec<u8>,
    // },
    // GetMapShell(MapAddress),
    // GetMapVersion(MapAddress),
    // ListMapEntries(MapAddress),
    // ListMapKeys(MapAddress),
    // ListMapValues(MapAddress),
    // ===== Sequence =====
    //
    /// Get Sequence from the network.
    GetSequence(Address),
    /// Get `Sequence` shell at a certain point in history (`data_index` refers to the list
    /// of data).
    GetSequenceShell {
        address: Address,
        data_index: Index,
    },
    /// Get a range of entries from an Sequence object on the network.
    GetSequenceRange {
        address: Address,
        // Range of entries to fetch.
        //
        // For example, get 10 last entries:
        // range: (Index::FromEnd(10), Index::FromEnd(0))
        //
        // Get all entries:
        // range: (Index::FromStart(0), Index::FromEnd(0))
        //
        // Get first 5 entries:
        // range: (Index::FromStart(0), Index::FromStart(5))
        range: (Index, Index),
    },
    GetSequenceValue {
        address: Address,
        index: Index,
    },
    /// Get current indices: data, owners, permissions.
    GetSequenceIndices(Address),
    /// Get an entry with the current index.
    GetSequenceCurrentEntry(Address),
}

/// RPC data write request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum DataWrite {
    //
    // ===== Blob =====
    //
    PutBlob(BlobData),
    DeletePrivateBlob(BlobAddress),
    //
    // ===== Map =====
    //
    PutMap(MapData),
    DeletePrivateMap(Address),
    // CommitMapTx {
    //     address: MapAddress,
    //     actions: MapEntryActions,
    // },
    //
    // ===== Sequence =====
    //
    /// Put a new Sequence onto the network.
    PutSequence(SequenceData),
    /// Delete private `Sequence`.
    ///
    /// This operation MUST return an error if applied to published Sequence. Only the current
    /// owner(s) can perform this action.
    DeletePrivateSequence(Address),
    // Append data with concurrency control.
    AppendSentried {
        append: SequenceCmd,
        expected_index: u64,
    },
    // Append data.
    Append(SequenceCmd),
}

/// RPC Balance read request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum BalanceRead {
    /// Get a default balance // when no other differntiation is yet designed
    GetBalance,
    // GetBalanceOf(PublicKey), // when various balances can be managed
}

/// RPC Balance write request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum BalanceWrite {
    /// Balance transfer
    TransferCoins {
        destination: XorName,
        amount: Coins,
        transaction_id: TransactionId,
    },
    /// Create a new coin balance
    CreateBalance {
        new_balance_owner: PublicKey,
        amount: Coins,
        transaction_id: TransactionId,
    },
}

/// RPC owner read request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum OwnerRead {
    /// Get Map owner at the provided index.
    GetMapOwner { address: Address, index: Index },
    /// Get Sequence owner at the provided index.
    GetSequenceOwner { address: Address, index: Index },
    // /// Get Index owner at the provided version.
    // GetIndexOwner {
    //     address: Address,
    //     version: Version,
    // },
    // /// Get Balance owner at the provided version.
    // GetBalanceOwner {
    //     address: Address,
    //     version: Version,
    // },
}

/// RPC owner write request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum OwnerWrite {
    /// Set owner. Only the current owner(s) can perform this action.
    SetMapOwner {
        address: Address,
        owner: Owner,
        expected_index: u64,
    },
    /// Set owner. Only the current owner(s) can perform this action.
    SetSequenceOwner {
        address: Address,
        owner: Owner,
        expected_index: u64,
    },
    // /// Set owner. Only the current owner(s) can perform this action.
    // SetIndexOwner {
    //     address: Address,
    //     owner: Owner,
    //     expected_version: u64,
    // },
    // /// Set owner. Only the current owner(s) can perform this action.
    // SetBalanceOwner {
    //     address: Address,
    //     owner: Owner,
    //     expected_version: u64,
    // },
}

/// RPC auth read request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum AuthRead {
    // ========== Map ==========
    //
    // ListMapPermissions(MapAddress),
    // ListMapUserPermissions {
    //     address: MapAddress,
    //     user: PublicKey,
    // },
    //
    /// Get Map authorization at the provided index.
    GetMapAuthorization { address: Address, index: Index },
    /// Get Map permissions for a specified user(s).
    GetPublicMapUserPermissions {
        address: Address,
        index: Index,
        user: User,
    },
    /// Get Map permissions for a specified public key.
    GetPrivateMapUserPermissions {
        address: Address,
        index: Index,
        public_key: PublicKey,
    },
    //
    // ========== Sequence ==========
    //
    /// Get Sequence authorization at the provided index.
    GetSequenceAuthorization { address: Address, index: Index },
    /// Get Sequence permissions for a specified user(s).
    GetPublicSequenceUserPermissions {
        address: Address,
        index: Index,
        user: User,
    },
    /// Get Sequence permissions for a specified public key.
    GetPrivateSequenceUserPermissions {
        address: Address,
        index: Index,
        public_key: PublicKey,
    },
    //
    // ========== Index ==========
    //
    // /// Get Index authorization at the provided version.
    // GetIndexAuthorization {
    //     address: Address,
    //     version: Version,
    // },
    // /// Get Index permissions for a specified user(s).
    // GetPublicIndexUserPermissions {
    //     address: Address,
    //     version: Version,
    //     user: User,
    // },
    // /// Get Index permissions for a specified public key.
    // GetPrivateIndexUserPermissions {
    //     address: Address,
    //     version: Version,
    //     public_key: PublicKey,
    // },
    //
    // ========== Balance ==========
    //
    // /// Get Balance authorization at the provided index.
    // GetBalanceAuthorization {
    //     address: Address,
    //     version: Version,
    // },
    // /// Get Balance permissions for a specified user(s).
    // GetPublicBalanceUserPermissions {
    //     address: Address,
    //     version: Version,
    //     user: User,
    // },
    // /// Get Balance permissions for a specified public key.
    // GetPrivateBalanceUserPermissions {
    //     address: Address,
    //     version: Version,
    //     public_key: PublicKey,
    // },
}

/// RPC auth write request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum AuthWrite {
    // ========== Map ==========
    //
    SetPublicMapPermissions {
        address: Address,
        user: PublicKey,
        permissions: PublicPermissions,
        version: u64,
    },
    SetPrivateMapPermissions {
        address: Address,
        user: PublicKey,
        permissions: PrivatePermissions,
        version: u64,
    },
    // DeletePrivateMapUserPermissions {
    //     address: MapAddress,
    //     user: PublicKey,
    //     version: u64,
    // },
    //
    // ========== Sequence ==========
    //
    /// Set permissions.
    SetPublicSequencePermissions {
        address: Address,
        permissions: PublicPermissions,
        expected_index: u64,
    },
    /// Set permissions.
    SetPrivateSequencePermissions {
        address: Address,
        permissions: PrivatePermissions,
        expected_index: u64,
    },
    //
    // ========== Index ==========
    //
    // /// Set permissions.
    // SetPublicIndexPermissions {
    //     address: Address,
    //     permissions: PublicPermissions,
    //     expected_version: u64,
    // },
    // /// Set permissions.
    // SetPrivateIndexPermissions {
    //     address: Address,
    //     permissions: PrivatePermissions,
    //     expected_version: u64,
    // },
    //
    // ========== Balance ==========
    //
    // /// Set permissions.
    // SetPublicBalancePermissions {
    //     address: Address,
    //     permissions: PublicPermissions,
    //     expected_version: u64,
    // },
    // /// Set permissions.
    // SetPrivateBalancePermissions {
    //     address: Address,
    //     permissions: PrivatePermissions,
    //     expected_version: u64,
    // },
}

/// RPC misc read request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum MiscRead {
    // ===== Login Packet =====
    //
    GetLoginPacket(XorName),
    //
    // ===== Client (Owner) to SrcElders =====
    //
    /// List authorised keys and version stored by Elders.
    ListAuthKeysAndVersion,
}

/// RPC misc write request that is sent to vaults
#[allow(clippy::large_enum_variant, missing_docs)]
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub enum MiscWrite {
    //
    // ===== Login Packet =====
    //
    CreateLoginPacket(LoginPacket),
    CreateLoginPacketFor {
        new_owner: PublicKey,
        amount: Coins,
        transaction_id: TransactionId,
        new_login_packet: LoginPacket,
    },
    UpdateLoginPacket(LoginPacket),
    //
    // ===== Client (Owner) to SrcElders =====
    //
    /// Inserts an authorised key (for an app, user, etc.).
    InsertAuthKey {
        /// Authorised key to be inserted
        key: PublicKey,
        /// Incremented version
        version: u64,
        /// Permissions
        permissions: AppPermissions,
    },
    /// Deletes an authorised key.
    DeleteAuthKey {
        /// Authorised key to be deleted
        key: PublicKey,
        /// Incremented version
        version: u64,
    },
}

impl Request {
    /// Create a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use Request::*;
        match &*self {
            Data(data) => match data {
                DataRequest::Read(read) => read.error_response(error),
                DataRequest::Write(write) => write.error_response(error),
            },
            Balance(balance) => match balance {
                BalanceRequest::Read(read) => read.error_response(error),
                BalanceRequest::Write(write) => write.error_response(error),
            },
            Owners(owners) => match owners {
                OwnerRequest::Read(read) => read.error_response(error),
                OwnerRequest::Write(write) => write.error_response(error),
            },
            Auth(auth) => match auth {
                AuthRequest::Read(read) => read.error_response(error),
                AuthRequest::Write(write) => write.error_response(error),
            },
            Misc(misc) => match misc {
                MiscRequest::Read(read) => read.error_response(error),
                MiscRequest::Write(write) => write.error_response(error),
            },
        }
    }
}

impl DataRead {
    /// Create a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use DataRead::*;
        match *self {
            // ======== Blob ========
            GetBlob(_) => Response::GetBlob(Err(error)),
            // ======== Map ========
            //GetMap(_) => Response::GetMap(Err(error)),
            //GetMapValue { .. } => Response::GetMapValue(Err(error)),
            //GetMapShell(_) => Response::GetMapShell(Err(error)),
            //GetMapVersion(_) => Response::GetMapVersion(Err(error)),
            //ListMapEntries(_) => Response::ListMapEntries(Err(error)),
            //ListMapKeys(_) => Response::ListMapKeys(Err(error)),
            //ListMapValues(_) => Response::ListMapValues(Err(error)),
            //ListMapPermissions(_) => Response::ListMapPermissions(Err(error)),
            //ListMapUserPermissions { .. } => Response::ListMapUserPermissions(Err(error)),
            // ======== Sequence ========
            GetSequence(_) => Response::GetSequence(Err(error)),
            GetSequenceShell { .. } => Response::GetSequenceShell(Err(error)),
            GetSequenceValue { .. } => Response::GetSequenceValue(Err(error)),
            GetSequenceRange { .. } => Response::GetSequenceRange(Err(error)),
            GetSequenceIndices(_) => Response::GetExpectedIndices(Err(error)),
            GetSequenceCurrentEntry(_) => Response::GetSequenceCurrentEntry(Err(error)),
        }
    }
}

impl DataWrite {
    /// Create a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use DataWrite::*;
        match *self {
            // ======== Blob ========
            PutBlob(_) |
            DeletePrivateBlob(_) |
            // ======== Map ========
            PutMap(_) |
            DeletePrivateMap(_) |
            //CommitMapTx { .. } |
            // ======== Sequence ========
            PutSequence(_) |
            DeletePrivateSequence(_) |
            AppendSentried { .. } |
            Append(_)  => Response::Mutation(Err(error)),
        }
    }
}

impl OwnerRead {
    /// Create a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use OwnerRead::*;
        match *self {
            GetMapOwner { .. } => Response::GetMapOwner(Err(error)),
            GetSequenceOwner { .. } => Response::GetSequenceOwner(Err(error)),
            // GetIndexOwner { .. } => Response::GetIndexOwner(Err(error)),
            // GetBalanceOwner { .. } => Response::GetBalanceOwner(Err(error)),
        }
    }
}

impl OwnerWrite {
    /// Create a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use OwnerWrite::*;
        match *self {
            // SetIndexOwner { .. } |
            SetMapOwner { .. } | SetSequenceOwner { .. } => Response::Mutation(Err(error)),
            // SetBalanceOwner { .. } => Response::Mutation(Err(error)),
        }
    }
}

impl AuthRead {
    /// Create a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use AuthRead::*;
        match *self {
            // ==== Map ====
            GetMapAuthorization { .. } => Response::GetMapAuthorization(Err(error)),
            GetPublicMapUserPermissions { .. } => Response::GetPublicMapUserPermissions(Err(error)),
            GetPrivateMapUserPermissions { .. } => {
                Response::GetPrivateMapUserPermissions(Err(error))
            }
            //
            // ==== Sequence ====
            GetSequenceAuthorization { .. } => Response::GetSequenceAuthorization(Err(error)),
            GetPublicSequenceUserPermissions { .. } => {
                Response::GetPublicSequenceUserPermissions(Err(error))
            }
            GetPrivateSequenceUserPermissions { .. } => {
                Response::GetPrivateSequenceUserPermissions(Err(error))
            } //
              // ==== Index ====
              // GetIndexAuthorization { .. } => Response::GetIndexAuthorization(Err(error)),
              // GetPublicIndexUserPermissions { .. } => Response::GetPublicIndexUserPermissions(Err(error)),
              // GetPrivateIndexUserPermissions { .. } => Response::GetPrivateIndexUserPermissions(Err(error)),
              //
              // ==== Balance ====
              // GetBalanceAuthorization { .. } => Response::GetBalanceAuthorization(Err(error)),
              // GetPublicBalanceUserPermissions { .. } => Response::GetPublicBalanceUserPermissions(Err(error)),
              // GetPrivateBalanceUserPermissions { .. } => Response::GetPrivateBalanceUserPermissions(Err(error)),
        }
    }
}

impl AuthWrite {
    /// Create a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use AuthWrite::*;
        match *self {
            // ==== Index ====
            // SetPublicIndexPermissions { .. } |
            // SetPrivateIndexPermissions { .. } |
            //
            // ==== Balance ====
            // SetPublicBalancePermissions { .. } |
            // SetPrivateBalancePermissions { .. } |
            //
            // ==== Map ====
            SetPublicMapPermissions { .. } |
            SetPrivateMapPermissions { .. } |
            //
            // ==== Sequence ====
            SetPublicSequencePermissions { .. } |
            SetPrivateSequencePermissions { .. } => Response::Mutation(Err(error)),
        }
    }
}

impl BalanceRead {
    /// Create a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use BalanceRead::*;
        match *self {
            GetBalance => Response::GetBalance(Err(error)),
        }
    }
}

impl BalanceWrite {
    /// Create a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use BalanceWrite::*;
        match *self {
            TransferCoins { .. } => Response::Transaction(Err(error)),
            CreateBalance { .. } => Response::Transaction(Err(error)),
        }
    }
}

impl MiscRead {
    /// Create a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use MiscRead::*;
        match *self {
            // ===== Login Packet =====
            GetLoginPacket(..) => Response::GetLoginPacket(Err(error)),
            // ===== Client (Owner) to SrcElders =====
            ListAuthKeysAndVersion => Response::ListAuthKeysAndVersion(Err(error)),
        }
    }
}

impl MiscWrite {
    /// Create a Response containing an error, with the Response variant corresponding to the
    /// Request variant.
    pub fn error_response(&self, error: Error) -> Response {
        use MiscWrite::*;
        match *self {
            // ===== Login Packet =====
            CreateLoginPacket { .. } |
            CreateLoginPacketFor { .. } |
            UpdateLoginPacket { .. } |
            // ===== Client (Owner) to SrcElders =====
            InsertAuthKey { .. } |
            DeleteAuthKey { .. } => Response::Mutation(Err(error)),
        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        use Request::*;

        write!(
            formatter,
            "{}",
            match &*self {
                Data(data) => {
                    match data {
                        DataRequest::Read(read) => {
                            match read {
                                // ==== Blob ====
                                DataRead::GetBlob { .. } => "DataRead::GetBlob",
                                // ==== Index ====
                                //
                                // ==== Map ====
                                //
                                // ==== Sequence ====
                                DataRead::GetSequence { .. } => "DataRead::GetSequence",
                                DataRead::GetSequenceCurrentEntry { .. } => {
                                    "DataRead::GetSequenceCurrentEntry"
                                }
                                DataRead::GetSequenceIndices { .. } => {
                                    "DataRead::GetSequenceIndices"
                                }
                                DataRead::GetSequenceRange { .. } => "DataRead::GetSequenceRange",
                                DataRead::GetSequenceShell { .. } => "DataRead::GetSequenceShell",
                                DataRead::GetSequenceValue { .. } => "DataRead::GetSequenceValue",
                            }
                        }
                        DataRequest::Write(write) => {
                            match write {
                                // ==== Blob ====
                                DataWrite::PutBlob { .. } => "DataWrite::PutBlob",
                                DataWrite::DeletePrivateBlob { .. } => {
                                    "DataWrite::DeletePrivateBlob"
                                }
                                // ==== Index ====
                                //
                                // ==== Map ====
                                DataWrite::PutMap { .. } => "DataWrite::PutMap",
                                DataWrite::DeletePrivateMap { .. } => "DataWrite::DeletePrivateMap",
                                // ==== Sequence ====
                                DataWrite::PutSequence { .. } => "DataWrite::PutSequence",
                                DataWrite::DeletePrivateSequence { .. } => {
                                    "DataWrite::DeletePrivateSequence"
                                }
                                DataWrite::Append { .. } => "DataWrite::Append",
                                DataWrite::AppendSentried { .. } => "DataWrite::AppendSentried",
                            }
                        }
                    }
                }
                Balance(balance) => match balance {
                    BalanceRequest::Read(read) => match read {
                        BalanceRead::GetBalance { .. } => "BalanceRead::GetBalance",
                    },
                    BalanceRequest::Write(write) => match write {
                        BalanceWrite::CreateBalance { .. } => "BalanceWrite::CreateBalance",
                        BalanceWrite::TransferCoins { .. } => "BalanceWrite::TransferCoins",
                    },
                },
                Owners(owners) => {
                    match owners {
                        OwnerRequest::Read(read) => {
                            match read {
                                OwnerRead::GetMapOwner { .. } => "OwnerRead::GetMapOwner",
                                OwnerRead::GetSequenceOwner { .. } => "OwnerRead::GetSequenceOwner",
                                // OwnerRead::GetIndexOwner { .. } => "OwnerRead::GetIndexOwner",
                                // OwnerRead::GetBalanceOwner { .. } => "OwnerRead::GetBalanceOwner",
                            }
                        }
                        OwnerRequest::Write(write) => {
                            match write {
                                OwnerWrite::SetMapOwner { .. } => "OwnerWrite::SetMapOwner",
                                OwnerWrite::SetSequenceOwner { .. } => {
                                    "OwnerWrite::SetSequenceOwner"
                                } // OwnerWrite::SetIndexOwner { .. } => "OwnerWrite::SetIndexOwner",
                                  // OwnerWrite::SetBalanceOwner { .. } => "OwnerWrite::SetBalanceOwner",
                            }
                        }
                    }
                }
                Auth(auth) => {
                    match auth {
                        AuthRequest::Read(read) => {
                            match read {
                                // ==== Map ====
                                AuthRead::GetPrivateMapUserPermissions { .. } => {
                                    "AuthRead::GetPrivateMapUserPermissions"
                                }
                                AuthRead::GetPublicMapUserPermissions { .. } => {
                                    "AuthRead::GetPublicMapUserPermissions"
                                }
                                AuthRead::GetMapAuthorization { .. } => {
                                    "AuthRead::GetMapAuthorization"
                                }
                                // ==== Sequence ====
                                AuthRead::GetPrivateSequenceUserPermissions { .. } => {
                                    "AuthRead::GetPrivateSequenceUserPermissions"
                                }
                                AuthRead::GetPublicSequenceUserPermissions { .. } => {
                                    "AuthRead::GetPublicSequenceUserPermissions"
                                }
                                AuthRead::GetSequenceAuthorization { .. } => {
                                    "AuthRead::GetSequenceAuthorization"
                                } // ==== Index ====
                                  // AuthRead::GetPrivateIndexUserPermissions { .. } => "AuthRead::GetPrivateIndexUserPermissions",
                                  // AuthRead::GetIndexAuthorization { .. } => "AuthRead::GetIndexAuthorization",
                                  // AuthRead::GetPublicIndexUserPermissions { .. } => "AuthRead::GetPublicIndexUserPermissions",
                                  // ==== Balance ====
                                  // AuthRead::GetPrivateBalanceUserPermissions { .. } => "AuthRead::GetPrivateBalanceUserPermissions",
                                  // AuthRead::GetPublicBalanceUserPermissions { .. } => "AuthRead::GetPublicBalanceUserPermissions",
                                  // AuthRead::GetBalanceAuthorization { .. } => "AuthRead::GetBalanceAuthorization",
                            }
                        }
                        AuthRequest::Write(write) => {
                            match write {
                                // ==== Map ====
                                AuthWrite::SetPrivateMapPermissions { .. } => {
                                    "AuthWrite::SetPrivateMapPermissions"
                                }
                                AuthWrite::SetPublicMapPermissions { .. } => {
                                    "AuthWrite::SetPublicMapPermissions"
                                }
                                // ==== Sequence ====
                                AuthWrite::SetPrivateSequencePermissions { .. } => {
                                    "AuthWrite::SetPrivateSequencePermissions"
                                }
                                AuthWrite::SetPublicSequencePermissions { .. } => {
                                    "AuthWrite::SetPublicSequencePermissions"
                                } // ==== Index ====
                                  // AuthWrite::SetPrivateIndexPermissions { .. } => "AuthWrite::SetPrivateIndexPermissions",
                                  // AuthWrite::SetPublicIndexPermissions { .. } => "AuthWrite::SetPublicIndexPermissions",
                                  // ==== Balance ====
                                  // AuthWrite::SetPrivateBalancePermissions { .. } => "AuthWrite::SetPrivateBalancePermissions",
                                  // AuthWrite::SetPublicBalancePermissions { .. } => "AuthWrite::SetPublicBalancePermissions",
                            }
                        }
                    }
                }
                Misc(misc) => match misc {
                    MiscRequest::Read(read) => match read {
                        MiscRead::GetLoginPacket { .. } => "MiscRead::GetLoginPacket",
                        MiscRead::ListAuthKeysAndVersion { .. } => {
                            "MiscRead::ListAuthKeysAndVersion"
                        }
                    },
                    MiscRequest::Write(write) => match write {
                        MiscWrite::CreateLoginPacket { .. } => "MiscWrite::CreateLoginPacket",
                        MiscWrite::CreateLoginPacketFor { .. } => "MiscWrite::CreateLoginPacketFor",
                        MiscWrite::UpdateLoginPacket { .. } => "MiscWrite::UpdateLoginPacket",
                        MiscWrite::DeleteAuthKey { .. } => "MiscWrite::DeleteAuthKey",
                        MiscWrite::InsertAuthKey { .. } => "MiscWrite::InsertAuthKey",
                    },
                },
            }
        )
    }
}
