// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]
// FIXME - write docs
#![allow(missing_docs)]

pub mod appendable_data;
pub mod errors;
pub mod immutable_data;
pub mod mutable_data;
pub mod request;
pub mod response;

pub use immutable_data::{ImmutableData, UnpubImmutableData, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES};
use serde::{Deserialize, Serialize};

/// Constant byte length of `XorName`.
pub const XOR_NAME_LEN: usize = 32;

/// A [`XOR_NAME_BITS`](constant.XOR_NAME_BITS.html)-bit number, viewed as a point in XOR space.
///
/// This wraps an array of [`XOR_NAME_LEN`](constant.XOR_NAME_LEN.html) bytes, i.e. a number
/// between 0 and 2<sup>`XOR_NAME_BITS`</sup> - 1.
///
/// XOR space is the space of these numbers, with the [XOR metric][1] as a notion of distance,
/// i. e. the points with IDs `x` and `y` are considered to have distance `x xor y`.
///
/// [1]: https://en.wikipedia.org/wiki/Kademlia#System_details
pub type XorName = [u8; XOR_NAME_LEN];

// impl XorName {
//     /// Private function exposed in fmt Debug {:?} and Display {} traits.
//     fn get_debug_id(&self) -> String {
//         format!("{:02x}{:02x}{:02x}..", self.0[0], self.0[1], self.0[2])
//     }
// }

// impl fmt::Debug for XorName {
//     fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//         write!(formatter, "{}", self.get_debug_id())
//     }
// }

/// Unique ID for messages
///
/// This is used for deduplication: Since the network sends messages redundantly along different
/// routes, the same message will usually arrive more than once at any given node. A message with
/// an ID that is already in the cache will be ignored.
#[derive(Ord, PartialOrd, Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct MessageId(pub XorName);

// Impl this in SAFE Client Libs if we still need old routing Message IDs:
//
// impl From<OldMessageId> for MessageId {
//     fn from(old_msg_id: OldMessageId) -> Self {
//         MessageId {
//             0: (old_msg_id.0).0,
//         }
//     }
// }
// impl Into<OldMessageId> for MessageId {
//     fn into(self) -> OldMessageId {
//         OldMessageId::from_name_array(self.0)
//     }
// }
